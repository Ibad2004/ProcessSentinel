
import hashlib
import io
import json
from types import SimpleNamespace

import pytest

import pc_security.scanner.file_inspector as fi


MS_SUBJECT = (
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, "
    "S=Washington, C=US"
)


class FakeTimeout(Exception):
    pass


class FakeSubprocess:
    """Stands in for the subprocess module; never starts a real process."""

    CREATE_NO_WINDOW = 0x08000000
    TimeoutExpired = FakeTimeout

    def __init__(self, rows=None, error=None, stdout=None, stderr=b""):
        self.rows = rows or {}
        self.error = error
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error

        if self.stdout is not None:
            stdout = self.stdout
        else:
            paths = json.loads(kwargs["input"].decode("ascii"))
            result = [
                {"path": p, **self.rows.get(p, {"status": "NotSigned"})}
                for p in paths
            ]
            stdout = json.dumps(result).encode("utf-8")

        return SimpleNamespace(
            stdout=stdout, stderr=self.stderr, returncode=0,
        )


class FakeOs:
    """Stands in for os.stat with controllable size and mtime."""

    def __init__(self):
        self.files = {}
        self.missing = set()

    def stat(self, path):
        if path in self.missing:
            raise FileNotFoundError(2, "The system cannot find the file")
        size, mtime = self.files.get(path, (100, 1))
        return SimpleNamespace(st_size=size, st_mtime_ns=mtime)


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    fi.clear_cache()
    fake_os = FakeOs()
    monkeypatch.setattr(fi, "os", fake_os)
    monkeypatch.setattr(fi, "sys", SimpleNamespace(platform="win32"))
    yield fake_os
    fi.clear_cache()


def use_subprocess(monkeypatch, **kwargs):
    fake = FakeSubprocess(**kwargs)
    monkeypatch.setattr(fi, "subprocess", fake)
    return fake


# --- Signatures ------------------------------------------------------------

def test_valid_signature_reports_signer(monkeypatch):
    path = r"C:\Windows\System32\svchost.exe"
    fake = use_subprocess(monkeypatch, rows={
        path: {"status": "Valid", "subject": MS_SUBJECT},
    })

    result = fi.get_signature(path)

    assert result == {
        "status": "valid", "signer": "Microsoft Windows", "reason": None,
    }
    args, kwargs = fake.calls[0]
    assert args[0] == "powershell.exe"
    assert "-NoProfile" in args
    assert "-NonInteractive" in args
    assert kwargs["creationflags"] == FakeSubprocess.CREATE_NO_WINDOW
    assert kwargs["timeout"] > 0


def test_paths_are_sent_on_stdin_not_in_the_script(monkeypatch):
    path = r"C:\Apps\evil'; Remove-Item x; '.exe"
    fake = use_subprocess(monkeypatch)

    fi.get_signature(path)

    args, kwargs = fake.calls[0]
    assert all(path not in arg for arg in args)
    assert json.loads(kwargs["input"].decode("ascii")) == [path]


def test_unsigned_file(monkeypatch):
    use_subprocess(monkeypatch)

    result = fi.get_signature(r"C:\Tools\tool.exe")

    assert result["status"] == "unsigned"
    assert result["signer"] is None


@pytest.mark.parametrize("raw_status", ["HashMismatch", "NotTrusted"])
def test_invalid_signature(monkeypatch, raw_status):
    path = r"C:\Tools\tampered.exe"
    use_subprocess(monkeypatch, rows={
        path: {"status": raw_status, "subject": "CN=Some Vendor"},
    })

    result = fi.get_signature(path)

    assert result["status"] == "invalid"
    assert result["signer"] == "Some Vendor"


def test_unrecognised_status_is_unknown_with_reason(monkeypatch):
    path = r"C:\Tools\odd.exe"
    use_subprocess(monkeypatch, rows={path: {"status": "UnknownError"}})

    result = fi.get_signature(path)

    assert result["status"] == "unknown"
    assert "UnknownError" in result["reason"]


def test_timeout_marks_every_path_unknown(monkeypatch):
    use_subprocess(monkeypatch, error=FakeTimeout("too slow"))

    results = fi.get_signatures([r"C:\a.exe", r"C:\b.exe"])

    assert {r["status"] for r in results.values()} == {"unknown"}
    assert all("timed out" in r["reason"] for r in results.values())


def test_powershell_missing_is_handled(monkeypatch):
    use_subprocess(
        monkeypatch,
        error=FileNotFoundError(2, "No such file", "powershell.exe"),
    )

    result = fi.get_signature(r"C:\a.exe")

    assert result["status"] == "unknown"
    assert "could not run" in result["reason"]


def test_empty_or_garbled_output_is_handled(monkeypatch):
    use_subprocess(monkeypatch, stdout=b"", stderr=b"blocked by policy")
    assert fi.get_signature(r"C:\a.exe")["status"] == "unknown"

    fi.clear_cache()
    use_subprocess(monkeypatch, stdout=b"not json")
    assert fi.get_signature(r"C:\a.exe")["status"] == "unknown"


def test_non_windows_never_runs_powershell(monkeypatch):
    monkeypatch.setattr(fi, "sys", SimpleNamespace(platform="linux"))
    fake = use_subprocess(monkeypatch)

    result = fi.get_signature("/usr/bin/python3")

    assert result["status"] == "unknown"
    assert "only available on Windows" in result["reason"]
    assert fake.calls == []


def test_missing_file_is_unknown_without_running_powershell(
    monkeypatch, isolated,
):
    isolated.missing.add(r"C:\gone.exe")
    fake = use_subprocess(monkeypatch)

    result = fi.get_signature(r"C:\gone.exe")

    assert result["status"] == "unknown"
    assert fake.calls == []


def test_many_paths_use_one_powershell_call_and_are_cached(monkeypatch):
    fake = use_subprocess(monkeypatch)
    paths = [r"C:\a.exe", r"C:\b.exe", r"C:\a.exe"]

    fi.get_signatures(paths)
    fi.get_signatures(paths)

    assert len(fake.calls) == 1
    sent = json.loads(fake.calls[0][1]["input"].decode("ascii"))
    assert sent == [r"C:\a.exe", r"C:\b.exe"]


def test_cache_is_invalidated_when_file_changes(monkeypatch, isolated):
    fake = use_subprocess(monkeypatch)

    fi.get_signature(r"C:\a.exe")
    isolated.files[r"C:\a.exe"] = (100, 2)  # modification time changed
    fi.get_signature(r"C:\a.exe")

    assert len(fake.calls) == 2


def test_temporary_errors_are_not_cached(monkeypatch):
    path = r"C:\locked.exe"
    fake = use_subprocess(monkeypatch, rows={
        path: {"status": "Error", "error": "file in use"},
    })

    assert fi.get_signature(path)["reason"] == "file in use"
    fi.get_signature(path)

    assert len(fake.calls) == 2


# --- SHA-256 ---------------------------------------------------------------

def test_sha256_streams_and_caches(monkeypatch):
    content = b"x" * (fi._HASH_CHUNK_SIZE * 2 + 5)
    opened = []

    def fake_open(path, mode):
        opened.append((path, mode))
        return io.BytesIO(content)

    monkeypatch.setattr(fi, "open", fake_open, raising=False)

    first = fi.get_sha256(r"C:\a.exe")
    second = fi.get_sha256(r"C:\a.exe")

    expected = hashlib.sha256(content).hexdigest()
    assert first == (expected, None)
    assert second == (expected, None)
    assert opened == [(r"C:\a.exe", "rb")]


def test_sha256_permission_denied(monkeypatch):
    def fake_open(path, mode):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(fi, "open", fake_open, raising=False)

    assert fi.get_sha256(r"C:\Windows\System32\lsass.exe") == (
        None, "Permission denied while reading the file.",
    )


def test_sha256_missing_file(isolated):
    isolated.missing.add(r"C:\gone.exe")

    value, error = fi.get_sha256(r"C:\gone.exe")

    assert value is None
    assert "could not be read" in error


def test_sha256_without_path():
    assert fi.get_sha256(None) == (None, "No executable path available.")


# --- inspect_processes -----------------------------------------------------

def test_inspect_processes_adds_fields_and_notes(monkeypatch, isolated):
    use_subprocess(monkeypatch, rows={
        r"C:\ok.exe": {"status": "Valid", "subject": "CN=Vendor Ltd"},
    })
    isolated.missing.add(r"C:\gone.exe")
    monkeypatch.setattr(
        fi, "open", lambda path, mode: io.BytesIO(b"abc"), raising=False,
    )

    processes = [
        {"pid": 1, "exe_path": r"C:\ok.exe", "metadata_notes": []},
        {"pid": 2, "exe_path": r"C:\gone.exe", "metadata_notes": []},
        {"pid": 3, "exe_path": None, "metadata_notes": []},
    ]

    fi.inspect_processes(processes)
    ok, gone, no_path = processes

    assert ok["signature_status"] == "valid"
    assert ok["signer"] == "Vendor Ltd"
    assert ok["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert ok["metadata_notes"] == []

    assert gone["signature_status"] == "unknown"
    assert gone["sha256"] is None
    assert any("Signature unknown" in n for n in gone["metadata_notes"])
    assert any("SHA-256 unavailable" in n for n in gone["metadata_notes"])

    assert no_path["signature_status"] == "unknown"
    assert no_path["sha256"] is None
