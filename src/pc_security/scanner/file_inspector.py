
"""Read-only inspection of executable files: digital signature and SHA-256.

Nothing here modifies, moves, or uploads a file. Results are cached per
path (and invalidated when the file's size or modification time changes)
so repeated scans stay fast.
"""

import hashlib
import json
import ntpath
import os
import subprocess
import sys
import threading


SIGNATURE_VALID = "valid"
SIGNATURE_UNSIGNED = "unsigned"
SIGNATURE_INVALID = "invalid"
SIGNATURE_UNKNOWN = "unknown"

# Get-AuthenticodeSignature status -> ProcessSentinel status.
_STATUS_MAP = {
    "Valid": SIGNATURE_VALID,
    "NotSigned": SIGNATURE_UNSIGNED,
    "HashMismatch": SIGNATURE_INVALID,
    "NotTrusted": SIGNATURE_INVALID,
}

# Paths are read from stdin as JSON so a file name can never be
# interpreted as PowerShell code.
_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# -InputObject (not a pipeline) so a JSON array is not wrapped in a second
# array by Windows PowerShell 5.1.
$paths = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$results = foreach ($p in $paths) {
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $subject = $null
        if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
        [pscustomobject]@{ path = $p; status = [string]$sig.Status; subject = $subject; error = $null }
    } catch {
        [pscustomobject]@{ path = $p; status = 'Error'; subject = $null; error = $_.Exception.Message }
    }
}
ConvertTo-Json -InputObject @($results) -Compress
"""

_HASH_CHUNK_SIZE = 1024 * 1024

_cache_lock = threading.Lock()
_signature_cache = {}
_hash_cache = {}


def _cache_key(path):
    """Identify a file version by path, size and modification time."""
    stat = os.stat(path)
    return (ntpath.normcase(path), stat.st_size, stat.st_mtime_ns)


def _signer_name(subject):
    """Extract the CN= part of a certificate subject."""
    if not subject:
        return None

    for part in subject.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "CN" and value:
            return value.strip().strip('"')

    return subject.strip() or None


def _unknown(reason):
    return {"status": SIGNATURE_UNKNOWN, "signer": None, "reason": reason}


def clear_cache():
    """Forget cached signature and hash results."""
    with _cache_lock:
        _signature_cache.clear()
        _hash_cache.clear()


def _run_powershell(paths, timeout):
    """Run Get-AuthenticodeSignature for many paths in one hidden process."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command", _POWERSHELL_SCRIPT,
        ],
        input=json.dumps(paths, ensure_ascii=True).encode("ascii"),
        capture_output=True,
        timeout=timeout,
        creationflags=creationflags,
        check=False,
    )

    output = completed.stdout.decode("utf-8-sig", errors="replace").strip()
    if not output:
        raise RuntimeError(
            completed.stderr.decode("utf-8", errors="replace").strip()
            or f"PowerShell exited with code {completed.returncode}"
        )

    parsed = json.loads(output)
    return parsed if isinstance(parsed, list) else [parsed]


def get_signatures(paths, timeout=None):
    """Return {path: signature_info} for many executables in one call.

    signature_info = {"status": valid|unsigned|invalid|unknown,
                      "signer": str|None, "reason": str|None}
    Failures produce "unknown" with a reason instead of raising.
    """
    results = {}
    pending = {}

    for path in dict.fromkeys(p for p in paths if isinstance(p, str) and p):
        if sys.platform != "win32":
            results[path] = _unknown(
                "Signature checks are only available on Windows."
            )
            continue

        try:
            key = _cache_key(path)
        except OSError as exc:
            results[path] = _unknown(
                f"File could not be read: {exc.strerror or exc}"
            )
            continue

        with _cache_lock:
            cached = _signature_cache.get(key)

        if cached is not None:
            results[path] = dict(cached)
        else:
            pending[path] = key

    if not pending:
        return results

    if timeout is None:
        timeout = min(30 + 0.5 * len(pending), 180)

    try:
        rows = _run_powershell(list(pending), timeout)
    except subprocess.TimeoutExpired:
        for path in pending:
            results[path] = _unknown("Signature check timed out.")
        return results
    except (OSError, ValueError, RuntimeError) as exc:
        reason = f"Signature check could not run: {exc}"[:300]
        for path in pending:
            results[path] = _unknown(reason)
        return results

    rows_by_path = {
        ntpath.normcase(row.get("path") or ""): row
        for row in rows
        if isinstance(row, dict)
    }

    for path, key in pending.items():
        row = rows_by_path.get(ntpath.normcase(path))
        if row is None:
            results[path] = _unknown("No signature result was returned.")
            continue

        raw_status = row.get("status") or ""
        status = _STATUS_MAP.get(raw_status, SIGNATURE_UNKNOWN)
        info = {
            "status": status,
            "signer": _signer_name(row.get("subject")),
            "reason": None if status != SIGNATURE_UNKNOWN else (
                row.get("error") or f"Windows reported '{raw_status}'."
            ),
        }
        results[path] = info

        # Errors may be temporary (file locked); only cache real answers.
        if raw_status != "Error":
            with _cache_lock:
                _signature_cache[key] = dict(info)

    return results


def get_signature(path, timeout=30):
    """Return signature info for one executable (see get_signatures)."""
    if not isinstance(path, str) or not path:
        return _unknown("No executable path available.")

    return get_signatures([path], timeout=timeout)[path]


def get_sha256(path):
    """Return (sha256_hex, error_reason). Exactly one value is None."""
    if not isinstance(path, str) or not path:
        return None, "No executable path available."

    try:
        key = _cache_key(path)
    except OSError as exc:
        return None, f"File could not be read: {exc.strerror or exc}"

    with _cache_lock:
        cached = _hash_cache.get(key)
    if cached is not None:
        return cached, None

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(_HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except PermissionError:
        return None, "Permission denied while reading the file."
    except OSError as exc:
        return None, f"File could not be read: {exc.strerror or exc}"

    value = digest.hexdigest()
    with _cache_lock:
        _hash_cache[key] = value
    return value, None


def inspect_processes(processes):
    """Add signature and hash fields to process records in place.

    Adds: signature_status, signer, sha256. Problems become
    metadata_notes, never exceptions.
    """
    paths = [
        item.get("exe_path")
        for item in processes
        if isinstance(item.get("exe_path"), str) and item.get("exe_path")
    ]
    signatures = get_signatures(paths)

    for item in processes:
        notes = item.setdefault("metadata_notes", [])
        path = item.get("exe_path")

        if not path:
            item["signature_status"] = SIGNATURE_UNKNOWN
            item["signer"] = None
            item["sha256"] = None
            continue

        signature = signatures.get(path) or _unknown("Not checked.")
        item["signature_status"] = signature["status"]
        item["signer"] = signature["signer"]
        if signature.get("reason"):
            notes.append(f"Signature unknown: {signature['reason']}")

        sha256, error = get_sha256(path)
        item["sha256"] = sha256
        if error:
            notes.append(f"SHA-256 unavailable: {error}")

    return processes
