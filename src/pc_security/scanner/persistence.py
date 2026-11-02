
"""Read-only listing of programs that start automatically.

Sources: registry Run/RunOnce keys (KEY_READ only), Startup folders, and
scheduled tasks (schtasks /query). Nothing is created, changed, or removed.
"""

import csv
import io
import ntpath
import os
import re
import struct
import subprocess
import sys

try:
    import winreg
except ImportError:  # Not Windows.
    winreg = None

from pc_security.scanner import file_inspector


SOURCE_REGISTRY_RUN = "Registry Run"
SOURCE_REGISTRY_RUNONCE = "Registry RunOnce"
SOURCE_STARTUP_FOLDER = "Startup folder"
SOURCE_SCHEDULED_TASK = "Scheduled task"

_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN_WOW = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

# (hive attribute name, label, key path, source)
REGISTRY_LOCATIONS = [
    ("HKEY_CURRENT_USER", "HKCU", _RUN, SOURCE_REGISTRY_RUN),
    ("HKEY_CURRENT_USER", "HKCU", _RUN + "Once", SOURCE_REGISTRY_RUNONCE),
    ("HKEY_LOCAL_MACHINE", "HKLM", _RUN, SOURCE_REGISTRY_RUN),
    ("HKEY_LOCAL_MACHINE", "HKLM", _RUN + "Once", SOURCE_REGISTRY_RUNONCE),
    ("HKEY_LOCAL_MACHINE", "HKLM", _RUN_WOW, SOURCE_REGISTRY_RUN),
    ("HKEY_LOCAL_MACHINE", "HKLM", _RUN_WOW + "Once", SOURCE_REGISTRY_RUNONCE),
]

_STARTUP_PARTS = ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")

BUILTIN_TASK_PREFIX = "\\microsoft\\windows\\"

SCHTASKS_TIMEOUT = 60

# Fixed column order of `schtasks /query /fo CSV /v`, used when the header
# is in another language.
_TASK_NAME_INDEX = 1
_TASK_COMMAND_INDEX = 8

_EXECUTABLE_PATTERN = re.compile(
    r"^(.+?\.(?:exe|com|scr|bat|cmd|vbs|vbe|js|jse|wsf|ps1|msc|cpl|dll))"
    r"(?=[\s,]|$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------

def _system_root():
    return os.environ.get("SystemRoot") or r"C:\Windows"


def resolve_executable(command):
    """Return (executable_path, note) for a startup command line.

    Handles quoted paths, unquoted paths containing spaces, environment
    variables such as %ProgramFiles%, and bare names like rundll32.exe.
    """
    if not isinstance(command, str) or not command.strip():
        return None, "No command recorded."

    text = ntpath.expandvars(command.strip())

    if text.startswith('"'):
        end = text.find('"', 1)
        candidate = text[1:end] if end > 0 else text[1:]
    else:
        match = _EXECUTABLE_PATTERN.match(text)
        candidate = match.group(1) if match else text.split()[0]

    candidate = candidate.strip()
    if not candidate:
        return None, "The command does not name a program file."

    if not ntpath.dirname(candidate):
        system_copy = os.path.join(_system_root(), "System32", candidate)
        if os.path.isfile(system_copy):
            return system_copy, None
        return candidate, "Program name without a folder; location not confirmed."

    return candidate, None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _read_registry_entries(notes):
    if winreg is None:
        notes.append("Registry checks are only available on Windows.")
        return []

    entries = []
    for hive_name, hive_label, key_path, source in REGISTRY_LOCATIONS:
        location = f"{hive_label}\\{key_path}"
        try:
            hive = getattr(winreg, hive_name)
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break  # No more values.
                    index += 1

                    if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                        continue

                    entries.append({
                        "source": source,
                        "location": location,
                        "name": name or "(Default)",
                        "command": value,
                        "notes": [],
                    })
        except FileNotFoundError:
            continue  # Missing Run keys are normal.
        except OSError as exc:
            notes.append(
                f"Could not read {location}: {exc.strerror or exc}"
            )

    return entries


# ---------------------------------------------------------------------------
# Startup folders and .lnk shortcuts
# ---------------------------------------------------------------------------

def _read_c_string(data, offset, unicode):
    """Read a NUL-terminated ANSI or UTF-16 string."""
    if unicode:
        end = offset
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", errors="replace")

    end = data.index(b"\x00", offset)
    raw = data[offset:end]
    try:
        # The ANSI code page; the "mbcs" codec only exists on Windows.
        return raw.decode("mbcs", errors="replace")
    except LookupError:
        return raw.decode("latin-1", errors="replace")


def read_shortcut(path):
    """Return (target_path, arguments) from a .lnk file, or (None, None).

    Minimal read-only parser of the documented Shell Link format
    ([MS-SHLLINK]); no COM objects or extra dependencies.
    """
    try:
        with open(path, "rb") as file:
            data = file.read(1024 * 1024)

        if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
            return None, None

        flags = struct.unpack_from("<I", data, 0x14)[0]
        is_unicode = bool(flags & 0x80)
        offset = 0x4C

        if flags & 0x01:  # HasLinkTargetIDList
            offset += 2 + struct.unpack_from("<H", data, offset)[0]

        target = None
        if flags & 0x02:  # HasLinkInfo
            info = offset
            info_size, header_size, info_flags = struct.unpack_from(
                "<III", data, info
            )
            if info_flags & 0x01:  # VolumeIDAndLocalBasePath
                base_offset = struct.unpack_from("<I", data, info + 16)[0]
                suffix_offset = struct.unpack_from("<I", data, info + 24)[0]
                if header_size >= 0x24:
                    unicode_base = struct.unpack_from("<I", data, info + 28)[0]
                    target = _read_c_string(data, info + unicode_base, True)
                else:
                    target = _read_c_string(data, info + base_offset, False)
                    suffix = _read_c_string(data, info + suffix_offset, False)
                    target += suffix
            offset += info_size

        arguments = None
        char_size = 2 if is_unicode else 1
        # StringData order: name, relative path, working dir, arguments.
        for flag in (0x04, 0x08, 0x10, 0x20):
            if not flags & flag:
                continue
            count = struct.unpack_from("<H", data, offset)[0]
            raw = data[offset + 2:offset + 2 + count * char_size]
            offset += 2 + count * char_size
            if flag == 0x20:
                arguments = raw.decode(
                    "utf-16-le" if is_unicode else "latin-1", errors="replace"
                )

        return target or None, arguments or None
    except (OSError, struct.error, ValueError, IndexError):
        return None, None


def _startup_folders():
    folders = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    # os.path for real folders (it is ntpath on Windows); ntpath is only
    # used to parse Windows command strings.
    if appdata:
        folders.append(
            ("Current user", os.path.join(appdata, *_STARTUP_PARTS))
        )
    if programdata:
        folders.append(
            ("All users", os.path.join(programdata, *_STARTUP_PARTS))
        )
    return folders


def _read_startup_folder_entries(notes):
    folders = _startup_folders()
    if not folders:
        notes.append("Startup folder locations are unavailable on this system.")
        return []

    entries = []
    for label, folder in folders:
        try:
            names = sorted(os.listdir(folder))
        except FileNotFoundError:
            continue
        except OSError as exc:
            notes.append(f"Could not list {folder}: {exc.strerror or exc}")
            continue

        for file_name in names:
            if file_name.lower() == "desktop.ini":
                continue

            path = os.path.join(folder, file_name)
            if not os.path.isfile(path):
                continue

            entry = {
                "source": SOURCE_STARTUP_FOLDER,
                "location": f"{label}: {folder}",
                "name": file_name,
                "command": path,
                "notes": [],
            }

            if file_name.lower().endswith(".lnk"):
                target, arguments = read_shortcut(path)
                if target:
                    entry["command"] = (
                        f'"{target}" {arguments}' if arguments else f'"{target}"'
                    )
                    entry["executable_path"] = target
                else:
                    entry["executable_path"] = path
                    entry["notes"].append(
                        "Shortcut target could not be read; showing the "
                        ".lnk file itself."
                    )
            else:
                entry["executable_path"] = path

            entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

def _decode_console_output(raw):
    for encoding in ("oem", "mbcs", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def parse_schtasks_csv(text, include_builtin=False):
    """Parse `schtasks /query /fo CSV /v` output into entries and notes.

    Repeated header rows are skipped. Column positions come from the
    English header when present, otherwise from the fixed schtasks order.
    """
    notes = []
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        return [], [f"Scheduled task list could not be read: {exc}"]

    rows = [row for row in rows if any(cell.strip() for cell in row)]
    if not rows:
        return [], notes

    header = rows[0]
    lowered = [cell.strip().lower() for cell in header]
    name_index = (
        lowered.index("taskname") if "taskname" in lowered
        else _TASK_NAME_INDEX
    )
    command_index = (
        lowered.index("task to run") if "task to run" in lowered
        else _TASK_COMMAND_INDEX
    )
    if "taskname" not in lowered:
        notes.append(
            "Scheduled task columns were matched by position because the "
            "output is not in English."
        )

    entries = []
    seen = set()
    skipped = 0
    needed = max(name_index, command_index)

    for row in rows[1:]:
        if row == header or (row and row[0] == header[0]):
            continue  # schtasks repeats the header for each task folder.
        if len(row) <= needed:
            skipped += 1
            continue

        name = row[name_index].strip()
        command = row[command_index].strip()
        if not name:
            skipped += 1
            continue
        if not include_builtin and name.lower().startswith(BUILTIN_TASK_PREFIX):
            continue
        if (name, command) in seen:
            continue  # One row per trigger; keep one per action.
        seen.add((name, command))

        folder, _, short_name = name.rpartition("\\")
        entries.append({
            "source": SOURCE_SCHEDULED_TASK,
            "location": name,
            "name": short_name or name,
            "command": command,
            "notes": [],
        })

    if skipped:
        notes.append(f"{skipped} scheduled task rows could not be read.")

    return entries, notes


def _read_scheduled_task_entries(notes, include_builtin):
    if sys.platform != "win32":
        notes.append("Scheduled task checks are only available on Windows.")
        return []

    try:
        completed = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=SCHTASKS_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        notes.append("Listing scheduled tasks timed out.")
        return []
    except OSError as exc:
        notes.append(f"Scheduled tasks could not be listed: {exc}")
        return []

    if completed.returncode != 0 and not completed.stdout:
        notes.append(
            "Scheduled tasks could not be listed: "
            + _decode_console_output(completed.stderr or b"").strip()[:200]
        )
        return []

    entries, parse_notes = parse_schtasks_csv(
        _decode_console_output(completed.stdout), include_builtin
    )
    notes.extend(parse_notes)
    return entries


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def _normalize(path):
    if not isinstance(path, str) or not path.strip():
        return None
    return ntpath.normcase(ntpath.normpath(path.strip()))


def _is_inside(path, directory):
    try:
        return ntpath.commonpath([path, directory]) == directory
    except ValueError:
        return False


def _user_writable_label(path):
    """Return a label like %APPDATA% if path is in a user-writable folder."""
    normalized = _normalize(path)
    if normalized is None:
        return None

    user_profile = os.environ.get("USERPROFILE")
    # Most specific first: Temp lives inside %LOCALAPPDATA%.
    candidates = [
        ("Temp", os.environ.get("TEMP")),
        ("Temp", os.environ.get("TMP")),
        ("Temp", ntpath.join(_system_root(), "Temp")),
        ("Downloads", ntpath.join(user_profile, "Downloads")
         if user_profile else None),
        ("%APPDATA%", os.environ.get("APPDATA")),
        ("%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA")),
        ("%PROGRAMDATA%", os.environ.get("PROGRAMDATA")),
        (r"C:\Users\Public", os.environ.get("PUBLIC") or r"C:\Users\Public"),
    ]

    for label, directory in candidates:
        directory = _normalize(directory)
        if directory and _is_inside(normalized, directory):
            return label
    return None


def _finding(code, severity, title, explanation, points):
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "points": points,
    }


def _flag_entry(entry, signature, exists, location_label):
    flags = []

    if not exists:
        flags.append(_finding(
            "STARTUP_EXECUTABLE_MISSING", "info",
            "Program file not found",
            "This startup entry points to a file that does not exist. It is "
            "often left over from uninstalled software, but it can also hide "
            "a program that only appears later.",
            10,
        ))

    status = signature.get("status") if signature else None
    if exists and status == "invalid":
        flags.append(_finding(
            "STARTUP_INVALID_SIGNATURE", "warning",
            "Startup program has an invalid signature",
            "Windows says this program's digital signature is not valid. The "
            "file may have been changed after it was signed.",
            45,
        ))
    elif exists and status == "unsigned":
        flags.append(_finding(
            "STARTUP_UNSIGNED", "info",
            "Startup program is not signed",
            "This program starts automatically but has no digital signature, "
            "so its publisher cannot be confirmed.",
            10,
        ))

    if location_label:
        flags.append(_finding(
            "STARTUP_IN_USER_WRITABLE_DIR", "info",
            "Startup program in a user-writable folder",
            f"This program lives in {location_label}, which normal user "
            "accounts can write to. Many apps start from here, but so does "
            "malware because no administrator rights are needed.",
            10,
        ))

    entry["flags"] = flags
    entry["score"] = min(sum(flag["points"] for flag in flags), 100)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_startup_entries(
    include_builtin_tasks=False,
    progress_callback=None,
    signature_checker=None,
):
    """Return {"entries": [...], "notes": [...]} describing autostart items.

    Each entry: source, location, name, command, executable_path,
    signature_status, signer, exists, flags (findings), score, notes.
    """
    def report(message):
        if progress_callback is not None:
            progress_callback(message)

    notes = []
    entries = []

    report("Reading registry Run keys...")
    entries.extend(_read_registry_entries(notes))

    report("Reading Startup folders...")
    entries.extend(_read_startup_folder_entries(notes))

    report("Reading scheduled tasks...")
    entries.extend(_read_scheduled_task_entries(notes, include_builtin_tasks))

    for entry in entries:
        if "executable_path" not in entry:
            path, note = resolve_executable(entry["command"])
            entry["executable_path"] = path
            if note:
                entry["notes"].append(note)

    report("Checking digital signatures...")
    checker = signature_checker or file_inspector.get_signatures
    existing = []
    for entry in entries:
        path = entry["executable_path"]
        entry["exists"] = (
            bool(path) and os.path.isabs(path) and os.path.isfile(path)
        )
        if entry["exists"]:
            existing.append(path)

    try:
        signatures = checker(existing) if existing else {}
    except Exception as exc:
        notes.append(f"Signature checks failed: {exc}")
        signatures = {}

    for entry in entries:
        path = entry["executable_path"]
        signature = signatures.get(path) if entry["exists"] else None
        entry["signature_status"] = (
            signature.get("status") if signature else "unknown"
        )
        entry["signer"] = signature.get("signer") if signature else None
        if signature and signature.get("reason"):
            entry["notes"].append(f"Signature unknown: {signature['reason']}")

        # "Missing" only when we know the full path and it is absent.
        known_path = bool(path) and os.path.isabs(path)
        _flag_entry(
            entry,
            signature,
            exists=entry["exists"] or not known_path,
            location_label=_user_writable_label(path),
        )

    report(f"Found {len(entries)} startup entries.")
    return {"entries": entries, "notes": notes}
