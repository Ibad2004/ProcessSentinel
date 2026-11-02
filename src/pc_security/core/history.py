
"""Scan history stored in ProcessSentinel's own SQLite database.

Only this database file is written. All queries are parameterised.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path


DEFAULT_MAX_SCANS = 50

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    scanned_count INTEGER NOT NULL,
    low_count INTEGER NOT NULL,
    medium_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_processes (
    scan_id INTEGER NOT NULL,
    pid INTEGER,
    name TEXT,
    exe_path TEXT,
    sha256 TEXT,
    signature_status TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    finding_codes TEXT,
    is_new INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scan_processes_scan
    ON scan_processes (scan_id);
"""

_PROCESS_COLUMNS = (
    "pid", "name", "exe_path", "sha256", "signature_status",
    "risk_score", "risk_level", "finding_codes", "is_new",
)


class HistoryError(RuntimeError):
    """Raised when the history database cannot be read or written."""


def _lower(value):
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


class _Identities:
    """Process identities of one scan, used for "new" and comparisons.

    A process is matched by (exe_path, sha256) when both are known, else by
    exe_path, else by name. Comparisons use the most precise level that the
    current process has, so a missing hash never makes a process look new.
    """

    def __init__(self, rows):
        self.pairs = set()
        self.paths = set()
        self.names = set()
        for row in rows:
            path = _lower(row.get("exe_path"))
            sha = _lower(row.get("sha256"))
            name = _lower(row.get("name"))
            if path and sha:
                self.pairs.add((path, sha))
            if path:
                self.paths.add(path)
            if name:
                self.names.add(name)

    def contains(self, row):
        """True/False, or None when the row has nothing to compare."""
        path = _lower(row.get("exe_path"))
        sha = _lower(row.get("sha256"))
        name = _lower(row.get("name"))
        if path and sha:
            return (path, sha) in self.pairs
        if path:
            return path in self.paths
        if name:
            return name in self.names
        return None


def _finding_codes(analysis):
    return [
        finding.get("code")
        for finding in analysis.get("findings") or []
        if isinstance(finding, dict) and finding.get("code")
    ]


class ScanHistory:
    """Save scans and answer "what is new since the last scan"."""

    def __init__(self, path, max_scans=DEFAULT_MAX_SCANS):
        if (
            isinstance(max_scans, bool)
            or not isinstance(max_scans, int)
            or max_scans < 1
        ):
            raise ValueError("max_scans must be a positive integer")

        self.path = Path(path)
        self.max_scans = max_scans

    # -- connection --------------------------------------------------------

    def _connect(self):
        connection = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=2)
            connection.row_factory = sqlite3.Row
            connection.executescript(_SCHEMA)
            return connection
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.close()
            raise HistoryError(f"Scan history is unavailable: {exc}") from exc

    def _run(self, action):
        """Run action(connection) in a transaction, wrapping errors."""
        connection = self._connect()
        try:
            with connection:
                return action(connection)
        except sqlite3.Error as exc:
            raise HistoryError(f"Scan history is unavailable: {exc}") from exc
        finally:
            connection.close()

    # -- writing -----------------------------------------------------------

    def record_scan(self, analyses, scanned_count=None, scanned_at=None):
        """Mark is_new_since_last_scan on each analysis, then save the scan.

        The first scan ever marks nothing as new. Returns the new scan id.
        Raises HistoryError; analyses are then all marked not new.
        """
        for analysis in analyses:
            analysis["is_new_since_last_scan"] = False

        scanned_at = scanned_at or datetime.now().isoformat(timespec="seconds")
        scanned_count = len(analyses) if scanned_count is None else scanned_count

        def action(connection):
            previous = connection.execute(
                "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()

            if previous is not None:
                identities = _Identities(
                    self._process_rows(connection, previous["id"])
                )
                for analysis in analyses:
                    analysis["is_new_since_last_scan"] = (
                        identities.contains(analysis) is False
                    )

            levels = [str(item.get("risk_level") or "low") for item in analyses]
            cursor = connection.execute(
                "INSERT INTO scans (scanned_at, scanned_count, low_count, "
                "medium_count, high_count) VALUES (?, ?, ?, ?, ?)",
                (
                    scanned_at,
                    scanned_count,
                    levels.count("low"),
                    levels.count("medium"),
                    levels.count("high"),
                ),
            )
            scan_id = cursor.lastrowid

            connection.executemany(
                "INSERT INTO scan_processes (scan_id, pid, name, exe_path, "
                "sha256, signature_status, risk_score, risk_level, "
                "finding_codes, is_new) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        item.get("pid"),
                        item.get("name"),
                        item.get("exe_path"),
                        item.get("sha256"),
                        item.get("signature_status"),
                        item.get("risk_score"),
                        item.get("risk_level"),
                        json.dumps(_finding_codes(item)),
                        int(bool(item.get("is_new_since_last_scan"))),
                    )
                    for item in analyses
                ],
            )
            self._prune(connection)
            return scan_id

        try:
            return self._run(action)
        except HistoryError:
            for analysis in analyses:
                analysis["is_new_since_last_scan"] = False
            raise

    def _prune(self, connection):
        connection.execute(
            "DELETE FROM scan_processes WHERE scan_id NOT IN "
            "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
            (self.max_scans,),
        )
        connection.execute(
            "DELETE FROM scans WHERE id NOT IN "
            "(SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
            (self.max_scans,),
        )

    def clear(self):
        """Delete every saved scan (ProcessSentinel's own rows only)."""
        def action(connection):
            connection.execute("DELETE FROM scan_processes")
            connection.execute("DELETE FROM scans")

        self._run(action)

    # -- reading -----------------------------------------------------------

    @staticmethod
    def _process_rows(connection, scan_id):
        rows = connection.execute(
            f"SELECT {', '.join(_PROCESS_COLUMNS)} FROM scan_processes "
            "WHERE scan_id = ? ORDER BY risk_score DESC, pid",
            (scan_id,),
        ).fetchall()

        result = []
        for row in rows:
            item = dict(row)
            try:
                item["finding_codes"] = json.loads(item["finding_codes"] or "[]")
            except (TypeError, ValueError):
                item["finding_codes"] = []
            item["is_new"] = bool(item["is_new"])
            result.append(item)
        return result

    def list_scans(self):
        """Return saved scans, newest first."""
        def action(connection):
            return [
                dict(row) for row in connection.execute(
                    "SELECT id, scanned_at, scanned_count, low_count, "
                    "medium_count, high_count FROM scans ORDER BY id DESC"
                )
            ]

        return self._run(action)

    def get_scan_processes(self, scan_id):
        return self._run(lambda c: self._process_rows(c, scan_id))

    def compare_with_previous(self, scan_id):
        """Return {"previous_scan_id", "appeared", "disappeared"}.

        previous_scan_id is None (and both lists empty) for the oldest scan.
        """
        def action(connection):
            previous = connection.execute(
                "SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            if previous is None:
                return {
                    "previous_scan_id": None,
                    "appeared": [],
                    "disappeared": [],
                }

            current_rows = self._process_rows(connection, scan_id)
            previous_rows = self._process_rows(connection, previous["id"])
            current = _Identities(current_rows)
            earlier = _Identities(previous_rows)

            return {
                "previous_scan_id": previous["id"],
                "appeared": [
                    row for row in current_rows
                    if earlier.contains(row) is False
                ],
                "disappeared": [
                    row for row in previous_rows
                    if current.contains(row) is False
                ],
            }

        return self._run(action)
