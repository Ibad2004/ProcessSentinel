
import ntpath
import struct
from types import SimpleNamespace

import pytest

import pc_security.scanner.persistence as persistence


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeWinreg:
    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_DWORD = 4

    def __init__(self, keys=None):
        self.keys = keys or {}
        self.opened = []

    def OpenKey(self, hive, path, reserved, access):
        self.opened.append((hive, path, access))
        if (hive, path) not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file")
        values = self.keys[(hive, path)]
        if isinstance(values, Exception):
            raise values
        return FakeKey(values)

    def EnumValue(self, key, index):
        if index >= len(key.values):
            raise OSError(259, "No more data is available")
        return key.values[index]


class FakeTimeout(Exception):
    pass


class FakeSubprocess:
    CREATE_NO_WINDOW = 0x08000000
    DEVNULL = -3
    TimeoutExpired = FakeTimeout

    def __init__(self, stdout=b"", error=None, returncode=0, stderr=b""):
        self.stdout = stdout
        self.error = error
        self.returncode = returncode
        self.stderr = stderr
        self.calls = []

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            stdout=self.stdout, stderr=self.stderr,
            returncode=self.returncode,
        )


class FakeSignatures:
    def __init__(self, statuses=None):
        self.statuses = statuses or {}
        self.calls = []

    def __call__(self, paths):
        self.calls.append(list(paths))
        return {
            path: {
                "status": self.statuses.get(path, "valid"),
                "signer": "Vendor Ltd",
                "reason": None,
            }
            for path in paths
        }


RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUNONCE = RUN + "Once"
WOW_RUN = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Point every Windows folder at tmp_path; no real files are used."""
    roots = {
        "SystemRoot": tmp_path / "Windows",
        "APPDATA": tmp_path / "Users" / "alice" / "AppData" / "Roaming",
        "LOCALAPPDATA": tmp_path / "Users" / "alice" / "AppData" / "Local",
        "PROGRAMDATA": tmp_path / "ProgramData",
        "USERPROFILE": tmp_path / "Users" / "alice",
        "PUBLIC": tmp_path / "Users" / "Public",
        "TEMP": tmp_path / "Users" / "alice" / "AppData" / "Local" / "Temp",
        "TMP": tmp_path / "Users" / "alice" / "AppData" / "Local" / "Temp",
        "ProgramFiles": tmp_path / "Program Files",
    }
    for name, folder in roots.items():
        folder.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(name, str(folder))
    (roots["SystemRoot"] / "System32").mkdir()

    monkeypatch.setattr(persistence, "winreg", FakeWinreg())
    monkeypatch.setattr(persistence, "subprocess", FakeSubprocess())
    monkeypatch.setattr(persistence, "sys", SimpleNamespace(platform="win32"))
    return roots


def make_file(path, content=b"MZ"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


def same_path(first, second):
    """Compare paths the way Windows does, on any OS.

    On Linux tmp_path uses "/" while expanded Windows commands use "\\", so
    both sides are normalised (separators and case) before comparing.
    """
    return ntpath.normcase(ntpath.normpath(first)) == ntpath.normcase(
        ntpath.normpath(second)
    )


def by_name(result):
    return {entry["name"]: entry for entry in result["entries"]}


def flag_codes(entry):
    return {flag["code"] for flag in entry["flags"]}


# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------

def test_quoted_path_with_arguments(env):
    path, note = persistence.resolve_executable(
        r'"C:\Program Files\App\app.exe" --minimized'
    )
    assert path == r"C:\Program Files\App\app.exe"
    assert note is None


def test_unquoted_path_with_spaces_and_arguments(env):
    path, _ = persistence.resolve_executable(
        r"C:\Program Files\App\app.exe /background"
    )
    assert path == r"C:\Program Files\App\app.exe"


def test_environment_variables_are_expanded(env):
    path, _ = persistence.resolve_executable(
        r'"%ProgramFiles%\Vendor\agent.exe" -s'
    )
    assert path == ntpath.join(
        str(env["ProgramFiles"]), "Vendor", "agent.exe"
    )


def test_bare_name_resolves_to_system32_when_present(env):
    system_copy = make_file(env["SystemRoot"] / "System32" / "rundll32.exe")

    path, note = persistence.resolve_executable(
        "rundll32.exe shell32.dll,Control_RunDLL"
    )

    assert path == system_copy
    assert note is None


def test_bare_name_not_found_gets_note(env):
    path, note = persistence.resolve_executable("helper.exe /x")

    assert path == "helper.exe"
    assert "without a folder" in note


@pytest.mark.parametrize("command", [None, "", "   "])
def test_empty_command(env, command):
    assert persistence.resolve_executable(command)[0] is None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_entries_read_only_with_key_read(env):
    good = make_file(env["ProgramFiles"] / "Vendor" / "agent.exe")
    fake = FakeWinreg({
        ("HKCU", RUN): [
            ("Agent", f'"{good}" --tray', FakeWinreg.REG_SZ),
            ("Number", 5, FakeWinreg.REG_DWORD),
        ],
        ("HKLM", WOW_RUN): [
            ("Legacy", r"%ProgramFiles%\Vendor\agent.exe",
             FakeWinreg.REG_EXPAND_SZ),
        ],
    })
    env_winreg = fake
    persistence.winreg = env_winreg

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )
    entries = by_name(result)

    assert set(entries) == {"Agent", "Legacy"}
    assert entries["Agent"]["source"] == "Registry Run"
    assert entries["Agent"]["location"] == "HKCU\\" + RUN
    assert entries["Agent"]["executable_path"] == good
    assert same_path(entries["Legacy"]["executable_path"], good)
    assert entries["Agent"]["signature_status"] == "valid"
    # Every key is opened with KEY_READ and nothing else.
    assert len(fake.opened) == 6
    assert {access for _, _, access in fake.opened} == {FakeWinreg.KEY_READ}


def test_missing_registry_keys_are_silently_skipped(env):
    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    assert result["entries"] == []
    assert not any("Could not read" in note for note in result["notes"])


def test_unreadable_registry_key_is_noted(env):
    persistence.winreg = FakeWinreg({
        ("HKLM", RUNONCE): PermissionError(5, "Access is denied"),
    })

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    assert any(
        "Could not read HKLM" in note and "denied" in note
        for note in result["notes"]
    )


# ---------------------------------------------------------------------------
# Startup folders and shortcuts
# ---------------------------------------------------------------------------

def build_lnk(target, arguments=None):
    """Build a minimal Shell Link with an ANSI LinkInfo local base path."""
    flags = 0x02 | 0x80 | (0x20 if arguments else 0)
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    struct.pack_into("<I", header, 0x14, flags)

    base = target.encode("latin-1") + b"\x00"
    info_header_size = 0x1C
    base_offset = info_header_size
    suffix_offset = base_offset + len(base)
    info_size = suffix_offset + 1
    link_info = struct.pack(
        "<IIIIIII",
        info_size, info_header_size, 0x01, 0, base_offset, 0, suffix_offset,
    ) + base + b"\x00"

    string_data = b""
    if arguments:
        string_data = (
            struct.pack("<H", len(arguments))
            + arguments.encode("utf-16-le")
        )
    return bytes(header) + link_info + string_data


def startup_folder(root):
    return root / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def test_startup_folder_files_and_shortcuts(env):
    target = make_file(env["ProgramFiles"] / "Chat" / "chat.exe")
    user_folder = startup_folder(env["APPDATA"])
    make_file(user_folder / "Chat.lnk", build_lnk(target, "--hidden"))
    make_file(user_folder / "desktop.ini", b"[.ShellClassInfo]")
    script = make_file(startup_folder(env["PROGRAMDATA"]) / "run.bat")

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )
    entries = by_name(result)

    assert set(entries) == {"Chat.lnk", "run.bat"}
    chat = entries["Chat.lnk"]
    assert chat["source"] == "Startup folder"
    assert chat["location"].startswith("Current user: ")
    assert chat["executable_path"] == target
    assert chat["command"] == f'"{target}" --hidden'
    assert entries["run.bat"]["executable_path"] == script
    assert entries["run.bat"]["location"].startswith("All users: ")


def test_unreadable_shortcut_keeps_lnk_path_with_note(env):
    broken = make_file(
        startup_folder(env["APPDATA"]) / "Broken.lnk", b"not a shortcut"
    )

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )
    entry = by_name(result)["Broken.lnk"]

    assert entry["executable_path"] == broken
    assert any("Shortcut target" in note for note in entry["notes"])


def test_read_shortcut_handles_missing_file(tmp_path):
    assert persistence.read_shortcut(str(tmp_path / "none.lnk")) == (None, None)


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

HEADER = (
    '"HostName","TaskName","Next Run Time","Status","Logon Mode",'
    '"Last Run Time","Last Result","Author","Task To Run","Start In"'
)


def task_row(name, command):
    command = command.replace('"', '""')
    return (
        f'"PC","{name}","N/A","Ready","Interactive","N/A","0","Vendor",'
        f'"{command}","N/A"'
    )


def test_parse_schtasks_handles_repeated_headers_dupes_and_builtins():
    text = "\r\n".join([
        HEADER,
        task_row(r"\Vendor Update", r'"C:\Vendor\upd.exe" /check'),
        task_row(r"\Vendor Update", r'"C:\Vendor\upd.exe" /check'),
        "",
        HEADER,
        task_row(r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                 r"%windir%\system32\defrag.exe -c"),
        '"PC","\\Broken"',
    ])

    entries, notes = persistence.parse_schtasks_csv(text)

    assert [e["location"] for e in entries] == [r"\Vendor Update"]
    assert entries[0]["name"] == "Vendor Update"
    assert entries[0]["command"] == r'"C:\Vendor\upd.exe" /check'
    assert any("1 scheduled task rows" in note for note in notes)

    with_builtin, _ = persistence.parse_schtasks_csv(text, include_builtin=True)
    assert len(with_builtin) == 2


def test_parse_schtasks_localized_header_uses_column_positions():
    german_header = (
        '"Hostname","Aufgabenname","Nächste Laufzeit","Status",'
        '"Anmeldemodus","Letzte Laufzeit","Letztes Ergebnis","Autor",'
        '"Auszuführende Aufgabe","Starten in"'
    )
    text = "\n".join([german_header, task_row(r"\Tool", r"C:\Tool\t.exe")])

    entries, notes = persistence.parse_schtasks_csv(text)

    assert entries[0]["command"] == r"C:\Tool\t.exe"
    assert any("by position" in note for note in notes)


@pytest.mark.parametrize("text", ["", "\n\n", 'garbage "unclosed'])
def test_parse_schtasks_bad_or_empty_csv(text):
    entries, notes = persistence.parse_schtasks_csv(text)

    assert entries == []
    assert isinstance(notes, list)


def test_schtasks_runs_hidden_and_read_only(env):
    fake = FakeSubprocess(stdout="\r\n".join([
        HEADER, task_row(r"\Tool", r"C:\Tool\t.exe"),
    ]).encode("ascii"))
    persistence.subprocess = fake

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    args, kwargs = fake.calls[0]
    assert args == ["schtasks", "/query", "/fo", "CSV", "/v"]
    assert kwargs["creationflags"] == FakeSubprocess.CREATE_NO_WINDOW
    assert kwargs["timeout"] == persistence.SCHTASKS_TIMEOUT
    assert by_name(result)["Tool"]["source"] == "Scheduled task"


def test_schtasks_timeout_is_noted_and_scan_continues(env):
    persistence.subprocess = FakeSubprocess(error=FakeTimeout())
    make_file(startup_folder(env["APPDATA"]) / "a.exe")

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    assert "a.exe" in by_name(result)
    assert any("timed out" in note for note in result["notes"])


def test_schtasks_missing_is_noted(env):
    persistence.subprocess = FakeSubprocess(
        error=FileNotFoundError(2, "No such file", "schtasks")
    )

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    assert any("could not be listed" in note for note in result["notes"])


# ---------------------------------------------------------------------------
# Flags, signatures and platform behaviour
# ---------------------------------------------------------------------------

def test_flags_for_missing_unsigned_invalid_and_user_writable(env):
    signed = make_file(env["ProgramFiles"] / "Good" / "good.exe")
    unsigned = make_file(env["APPDATA"] / "Tool" / "tool.exe")
    invalid = make_file(env["ProgramFiles"] / "Bad" / "bad.exe")
    in_temp = make_file(env["TEMP"] / "setup.exe")
    missing = str(env["ProgramFiles"] / "Gone" / "gone.exe")

    persistence.winreg = FakeWinreg({("HKCU", RUN): [
        ("Good", f'"{signed}"', FakeWinreg.REG_SZ),
        ("Tool", f'"{unsigned}"', FakeWinreg.REG_SZ),
        ("Bad", f'"{invalid}"', FakeWinreg.REG_SZ),
        ("Temp", f'"{in_temp}"', FakeWinreg.REG_SZ),
        ("Gone", f'"{missing}"', FakeWinreg.REG_SZ),
    ]})
    checker = FakeSignatures({unsigned: "unsigned", invalid: "invalid"})

    entries = by_name(persistence.scan_startup_entries(
        signature_checker=checker
    ))

    # One batch call, only for files that exist.
    assert len(checker.calls) == 1
    assert missing not in checker.calls[0]
    assert len(checker.calls[0]) == 4

    assert entries["Good"]["flags"] == []
    assert flag_codes(entries["Tool"]) == {
        "STARTUP_UNSIGNED", "STARTUP_IN_USER_WRITABLE_DIR",
    }
    assert "%APPDATA%" in entries["Tool"]["flags"][1]["explanation"]
    assert flag_codes(entries["Bad"]) == {"STARTUP_INVALID_SIGNATURE"}
    temp_flag = entries["Temp"]["flags"][0]
    assert temp_flag["code"] == "STARTUP_IN_USER_WRITABLE_DIR"
    assert "Temp" in temp_flag["explanation"]
    assert flag_codes(entries["Gone"]) == {"STARTUP_EXECUTABLE_MISSING"}
    assert entries["Gone"]["signature_status"] == "unknown"

    for entry in entries.values():
        for flag in entry["flags"]:
            assert set(flag) == {
                "code", "severity", "title", "explanation", "points",
            }


def test_unknown_signature_adds_no_flag(env):
    path = make_file(env["ProgramFiles"] / "App" / "app.exe")
    persistence.winreg = FakeWinreg({("HKCU", RUN): [
        ("App", path, FakeWinreg.REG_SZ),
    ]})

    entries = by_name(persistence.scan_startup_entries(
        signature_checker=FakeSignatures({path: "unknown"})
    ))

    assert entries["App"]["flags"] == []


def test_signature_checker_failure_is_noted(env):
    path = make_file(env["ProgramFiles"] / "App" / "app.exe")
    persistence.winreg = FakeWinreg({("HKCU", RUN): [
        ("App", path, FakeWinreg.REG_SZ),
    ]})

    def failing(paths):
        raise RuntimeError("PowerShell unavailable")

    result = persistence.scan_startup_entries(signature_checker=failing)

    assert by_name(result)["App"]["signature_status"] == "unknown"
    assert any("PowerShell unavailable" in n for n in result["notes"])


def test_default_signature_checker_is_file_inspector(env, monkeypatch):
    calls = []
    monkeypatch.setattr(
        persistence.file_inspector, "get_signatures",
        lambda paths: calls.append(paths) or {},
    )
    make_file(startup_folder(env["APPDATA"]) / "a.exe")

    persistence.scan_startup_entries()

    assert len(calls) == 1


def test_non_windows_reports_notes_without_crashing(env, monkeypatch):
    monkeypatch.setattr(persistence, "winreg", None)
    monkeypatch.setattr(persistence, "sys", SimpleNamespace(platform="linux"))
    fake = FakeSubprocess()
    monkeypatch.setattr(persistence, "subprocess", fake)

    result = persistence.scan_startup_entries(
        signature_checker=FakeSignatures()
    )

    assert fake.calls == []
    assert any("Registry checks" in note for note in result["notes"])
    assert any("Scheduled task checks" in note for note in result["notes"])


def test_progress_messages_are_reported(env):
    messages = []

    persistence.scan_startup_entries(
        progress_callback=messages.append,
        signature_checker=FakeSignatures(),
    )

    assert "Reading scheduled tasks..." in messages
    assert messages[-1].startswith("Found ")
