
# ---------------------------------------------------------------------------
# Mocked psutil tests: deterministic and independent of the host machine.
# ---------------------------------------------------------------------------

import os
from types import SimpleNamespace

import psutil
import pytest

import pc_security.scanner.process_scanner as scanner_module
from pc_security.scanner.process_scanner import scan_processes


class FakeProcess:
    def __init__(self, info, cpu=1.0, cpu_error=None, as_dict_error=None):
        self.pid = info.get("pid")
        self.info = info
        self.cpu = cpu
        self.cpu_error = cpu_error
        self.as_dict_error = as_dict_error

    def as_dict(self, attrs, ad_value=None):
        if self.as_dict_error is not None:
            raise self.as_dict_error
        return {attr: self.info.get(attr, ad_value) for attr in attrs}

    def cpu_percent(self, interval=None):
        if self.cpu_error is not None:
            raise self.cpu_error
        return self.cpu


def fake_info(pid, name, ppid, create_time, **extra):
    info = {
        "pid": pid,
        "name": name,
        "exe": rf"C:\Program Files\{name}",
        "memory_info": SimpleNamespace(rss=10 * 1024 * 1024),
        "ppid": ppid,
        "cmdline": [rf"C:\Program Files\{name}", "--flag", "two words"],
        "username": r"PC\alice",
        "create_time": create_time,
    }
    info.update(extra)
    return info


@pytest.fixture
def fake_processes(monkeypatch):
    processes = []
    monkeypatch.setattr(
        scanner_module.psutil, "process_iter", lambda: list(processes)
    )
    monkeypatch.setattr(scanner_module.time, "sleep", lambda seconds: None)
    return processes


def by_pid(results):
    return {item["pid"]: item for item in results}


def test_collects_cmdline_username_create_time_and_parent_name(
    fake_processes,
):
    fake_processes.extend([
        FakeProcess(fake_info(10, "explorer.exe", 1, 100.0)),
        FakeProcess(fake_info(20, "notepad.exe", 10, 200.0)),
    ])

    results = by_pid(scanner_module.scan_processes())
    child = results[20]

    assert child["cmdline"] == (
        r'"C:\Program Files\notepad.exe" --flag "two words"'
    )
    assert child["username"] == r"PC\alice"
    assert child["create_time"] == 200.0
    assert child["parent_name"] == "explorer.exe"


def test_access_denied_fields_become_metadata_notes(fake_processes):
    fake_processes.append(
        FakeProcess(
            fake_info(
                4, "System", 0, None,
                exe=None, cmdline=None, username=None,
            ),
            cpu_error=psutil.AccessDenied(4),
        )
    )

    results = scanner_module.scan_processes()

    assert len(results) == 1
    notes = results[0]["metadata_notes"]
    assert "Executable path unavailable" in notes
    assert "Command line unavailable" in notes
    assert "User account unavailable" in notes
    assert "Start time unavailable" in notes
    assert "CPU information unavailable" in notes


def test_access_denied_for_whole_process_does_not_drop_it(fake_processes):
    fake_processes.append(
        FakeProcess(
            {"pid": 900},
            as_dict_error=psutil.AccessDenied(900),
            cpu_error=psutil.AccessDenied(900),
        )
    )

    results = scanner_module.scan_processes()

    assert [item["pid"] for item in results] == [900]
    assert "Process name unavailable" in results[0]["metadata_notes"]


def test_vanished_process_is_skipped(fake_processes):
    fake_processes.extend([
        FakeProcess({"pid": 1}, as_dict_error=psutil.NoSuchProcess(1)),
        FakeProcess(fake_info(2, "ok.exe", 0, 1.0)),
    ])

    results = scanner_module.scan_processes()

    assert [item["pid"] for item in results] == [2]


def test_reused_parent_pid_is_not_reported_as_parent(fake_processes):
    # PID 10 started after its supposed child, so it cannot be the
    # original parent: Windows reused the PID.
    fake_processes.extend([
        FakeProcess(fake_info(10, "chrome.exe", 1, 500.0)),
        FakeProcess(fake_info(20, "csrss.exe", 10, 100.0)),
    ])

    child = by_pid(scanner_module.scan_processes())[20]

    assert child["parent_name"] is None
    assert any("reused" in note for note in child["metadata_notes"])


def test_missing_parent_is_noted(fake_processes):
    fake_processes.append(FakeProcess(fake_info(20, "app.exe", 999, 1.0)))

    child = scanner_module.scan_processes()[0]

    assert child["parent_name"] is None
    assert any(
        "no longer running" in note for note in child["metadata_notes"]
    )


# Converted from the original tests that scanned real processes.

def test_scan_processes_returns_a_list(fake_processes):
    fake_processes.append(FakeProcess(fake_info(1, "a.exe", 0, 1.0)))

    processes = scan_processes()

    assert isinstance(processes, list)


def test_scan_processes_includes_current_python_process(fake_processes):
    current_pid = os.getpid()
    fake_processes.extend([
        FakeProcess(fake_info(current_pid, "python.exe", 1, 2.0)),
        FakeProcess(fake_info(current_pid + 1, "other.exe", 1, 3.0)),
    ])

    processes = scan_processes()
    matching_processes = [
        process for process in processes
        if process["pid"] == current_pid
    ]

    assert len(matching_processes) == 1


def test_process_records_have_expected_fields(fake_processes):
    fake_processes.append(FakeProcess(fake_info(1, "a.exe", 0, 1.0)))

    processes = scan_processes()

    expected_fields = {
        "pid",
        "name",
        "exe_path",
        "cpu_percent",
        "memory_mb",
        "parent_pid",
    }

    assert expected_fields.issubset(processes[0].keys())
