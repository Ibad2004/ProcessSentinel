
from pc_security.scanner.process_scanner import scan_processes


def test_scan_processes_returns_a_list():
    processes = scan_processes()

    assert isinstance(processes, list)


def test_scan_processes_includes_current_python_process():
    processes = scan_processes()
    current_pid = __import__("os").getpid()

    matching_processes = [
        process for process in processes
        if process["pid"] == current_pid
    ]

    assert len(matching_processes) == 1


def test_process_records_have_expected_fields():
    processes = scan_processes()

    if not processes:
        return

    expected_fields = {
        "pid",
        "name",
        "exe_path",
        "cpu_percent",
        "memory_mb",
        "parent_pid",
    }

    assert expected_fields.issubset(processes[0].keys())
