
from pc_security.security.analyzer import (
    analyze_process,
    analyze_processes,
)


def test_missing_path_does_not_automatically_increase_risk():
    process = {
        "pid": 188,
        "name": None,
        "exe_path": None,
        "cpu_percent": 0.0,
        "memory_mb": 100.0,
        "parent_pid": 4,
    }

    result = analyze_process(process)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert any(
        finding["code"] == "MISSING_PATH"
        for finding in result["findings"]
    )


def test_system_process_from_expected_directory_is_not_flagged():
    process = {
        "pid": 1104,
        "name": "svchost.exe",
        "exe_path": r"C:\Windows\System32\svchost.exe",
        "cpu_percent": 0.0,
        "memory_mb": 18.0,
        "parent_pid": 1308,
    }

    result = analyze_process(process)

    assert result["risk_score"] == 0
    assert not any(
        finding["code"] == "SYSTEM_NAME_UNUSUAL_PATH"
        for finding in result["findings"]
    )


def test_system_name_from_unusual_directory_is_flagged():
    process = {
        "pid": 1234,
        "name": "svchost.exe",
        "exe_path": r"C:\Users\Public\svchost.exe",
        "cpu_percent": 0.0,
        "memory_mb": 10.0,
        "parent_pid": 1000,
    }

    result = analyze_process(process)

    assert result["risk_score"] == 35
    assert result["risk_level"] == "medium"
    assert any(
        finding["code"] == "SYSTEM_NAME_UNUSUAL_PATH"
        for finding in result["findings"]
    )


def test_analyze_processes_returns_one_result_per_process():
    processes = [
        {
            "pid": 1,
            "name": "example.exe",
            "exe_path": r"C:\Program Files\Example\example.exe",
            "cpu_percent": 0.0,
            "memory_mb": 10.0,
            "parent_pid": 0,
        },
        {
            "pid": 2,
            "name": None,
            "exe_path": None,
            "cpu_percent": 0.0,
            "memory_mb": None,
            "parent_pid": None,
        },
    ]

    results = analyze_processes(processes)

    assert len(results) == 2
    assert results[0]["pid"] == 1
    assert results[1]["pid"] == 2
