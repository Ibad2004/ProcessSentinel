
import sqlite3

import pytest

from pc_security.core.history import HistoryError, ScanHistory


def analysis(pid, name, path=None, sha=None, score=0, level="low", codes=()):
    return {
        "pid": pid,
        "name": name,
        "exe_path": path,
        "sha256": sha,
        "signature_status": "valid",
        "risk_score": score,
        "risk_level": level,
        "findings": [
            {"code": code, "severity": "info", "title": code,
             "explanation": "", "points": 0}
            for code in codes
        ],
    }


@pytest.fixture
def history(tmp_path):
    return ScanHistory(tmp_path / "data" / "history.db", max_scans=50)


def is_new(analyses):
    return {item["pid"]: item["is_new_since_last_scan"] for item in analyses}


def test_creates_folder_and_saves_scan(history):
    scan = [
        analysis(1, "a.exe", r"C:\A\a.exe", "aa", 35, "medium",
                 codes=["EXECUTABLE_IN_TEMP"]),
        analysis(2, "b.exe", r"C:\B\b.exe", "bb", 60, "high"),
        analysis(3, "c.exe", r"C:\C\c.exe", "cc"),
    ]

    scan_id = history.record_scan(scan, scanned_count=3,
                                  scanned_at="2026-11-03T10:00:00")

    assert history.path.is_file()
    scans = history.list_scans()
    assert scans == [{
        "id": scan_id, "scanned_at": "2026-11-03T10:00:00",
        "scanned_count": 3, "low_count": 1, "medium_count": 1,
        "high_count": 1,
    }]
    saved = {row["pid"]: row for row in history.get_scan_processes(scan_id)}
    assert saved[1]["finding_codes"] == ["EXECUTABLE_IN_TEMP"]
    assert saved[1]["exe_path"] == r"C:\A\a.exe"
    assert saved[1]["sha256"] == "aa"
    assert saved[2]["risk_level"] == "high"


def test_first_scan_marks_nothing_new(history):
    scan = [analysis(1, "a.exe", r"C:\A\a.exe", "aa")]

    history.record_scan(scan)

    assert is_new(scan) == {1: False}


def test_new_since_last_scan_uses_path_and_hash(history):
    history.record_scan([
        analysis(1, "a.exe", r"C:\A\a.exe", "aa"),
        analysis(2, "b.exe", r"C:\B\b.exe", "bb"),
    ])

    second = [
        analysis(10, "a.exe", r"c:\a\A.EXE", "AA"),  # same file, new PID
        analysis(11, "b.exe", r"C:\B\b.exe", "changed"),  # file changed
        analysis(12, "new.exe", r"C:\N\new.exe", "nn"),
    ]
    history.record_scan(second)

    assert is_new(second) == {10: False, 11: True, 12: True}


def test_missing_values_fall_back_to_path_then_name(history):
    history.record_scan([
        analysis(1, "a.exe", r"C:\A\a.exe", "aa"),
        analysis(2, "System", None, None),
    ])

    second = [
        analysis(3, "a.exe", r"C:\A\a.exe", None),   # hash failed: path
        analysis(4, "System", None, None),           # name only
        analysis(5, "Registry", None, None),         # new name
        analysis(6, None, None, None),               # nothing to compare
    ]
    history.record_scan(second)

    assert is_new(second) == {3: False, 4: False, 5: True, 6: False}


def test_prunes_to_max_scans(tmp_path):
    history = ScanHistory(tmp_path / "h.db", max_scans=3)

    for index in range(5):
        history.record_scan([analysis(index, f"p{index}.exe")])

    scans = history.list_scans()
    assert len(scans) == 3
    assert [s["id"] for s in scans] == [5, 4, 3]

    with sqlite3.connect(history.path) as connection:
        orphans = connection.execute(
            "SELECT COUNT(*) FROM scan_processes WHERE scan_id NOT IN "
            "(SELECT id FROM scans)"
        ).fetchone()[0]
    assert orphans == 0


def test_compare_with_previous(history):
    first = history.record_scan([
        analysis(1, "stays.exe", r"C:\S\stays.exe", "s"),
        analysis(2, "gone.exe", r"C:\G\gone.exe", "g"),
    ])
    second = history.record_scan([
        analysis(3, "stays.exe", r"C:\S\stays.exe", "s"),
        analysis(4, "came.exe", r"C:\C\came.exe", "c"),
    ])

    assert history.compare_with_previous(first) == {
        "previous_scan_id": None, "appeared": [], "disappeared": [],
    }
    comparison = history.compare_with_previous(second)
    assert comparison["previous_scan_id"] == first
    assert [r["name"] for r in comparison["appeared"]] == ["came.exe"]
    assert [r["name"] for r in comparison["disappeared"]] == ["gone.exe"]


def test_clear_removes_only_history_rows(history):
    history.record_scan([analysis(1, "a.exe")])

    history.clear()

    assert history.list_scans() == []
    assert history.path.is_file()  # The database itself stays.


def test_names_with_quotes_are_stored_safely(history):
    tricky = "x'); DROP TABLE scans; --.exe"

    scan_id = history.record_scan([analysis(1, tricky, rf"C:\{tricky}")])

    assert history.get_scan_processes(scan_id)[0]["name"] == tricky
    assert len(history.list_scans()) == 1


def test_corrupt_database_raises_history_error(tmp_path):
    path = tmp_path / "history.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    history = ScanHistory(path)
    scan = [analysis(1, "a.exe")]

    with pytest.raises(HistoryError):
        history.record_scan(scan)
    with pytest.raises(HistoryError):
        history.list_scans()

    assert is_new(scan) == {1: False}


def test_locked_database_raises_history_error(tmp_path):
    history = ScanHistory(tmp_path / "history.db")
    history.record_scan([analysis(1, "a.exe")])
    history_fast = ScanHistory(history.path)

    blocker = sqlite3.connect(history.path)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(HistoryError):
            history_fast.record_scan([analysis(2, "b.exe")])
    finally:
        blocker.rollback()
        blocker.close()


def test_unwritable_location_raises_history_error(tmp_path):
    blocker = tmp_path / "not_a_folder"
    blocker.write_text("file in the way")

    history = ScanHistory(blocker / "history.db")

    with pytest.raises(HistoryError):
        history.record_scan([analysis(1, "a.exe")])


@pytest.mark.parametrize("value", [0, -1, True, "50"])
def test_invalid_max_scans_is_rejected(tmp_path, value):
    with pytest.raises(ValueError):
        ScanHistory(tmp_path / "h.db", max_scans=value)
