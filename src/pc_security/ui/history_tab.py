"""History tab: past scans, their processes, and scan-to-scan changes."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pc_security.ui.common import (
    NEW_ROW_BRUSH,
    NEW_TOOLTIP,
    NumericTableWidgetItem,
    signature_label,
)


SCAN_HEADERS = ["DATE / TIME", "PROCESSES", "MEDIUM", "HIGH"]
PROCESS_HEADERS = [
    "PID", "PROCESS", "SCORE", "LEVEL", "SIGNATURE", "EXECUTABLE", "FINDINGS",
]
COMPARE_HEADERS = ["CHANGE", "PROCESS", "PID", "SCORE", "EXECUTABLE"]


def _table(object_name, headers, stretch_column):
    table = QTableWidget(0, len(headers))
    table.setObjectName(object_name)
    table.setHorizontalHeaderLabels(headers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setShowGrid(False)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    header = table.horizontalHeader()
    for column in range(len(headers)):
        header.setSectionResizeMode(
            column,
            QHeaderView.ResizeMode.Stretch
            if column == stretch_column
            else QHeaderView.ResizeMode.ResizeToContents,
        )
    return table


class HistoryTab(QWidget):
    """Read-only view of ProcessSentinel's own scan history database."""

    def __init__(self, history=None, parent=None):
        super().__init__(parent)
        self.setObjectName("historyPage")
        self.history = history
        self.scans: list[dict[str, Any]] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        title = QLabel("Scan history")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        header = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setObjectName("muted")
        self.status_label.setWordWrap(True)
        header.addWidget(self.status_label, 1)

        self.refresh_button = QPushButton("↻  Refresh")
        self.refresh_button.setObjectName("secondaryButton")
        self.refresh_button.clicked.connect(self.refresh)
        header.addWidget(self.refresh_button)

        self.clear_button = QPushButton("Clear history")
        self.clear_button.setObjectName("secondaryButton")
        self.clear_button.setToolTip(
            "Deletes ProcessSentinel's saved scans only. Nothing else on "
            "this computer is changed."
        )
        self.clear_button.clicked.connect(self._clear_history)
        header.addWidget(self.clear_button)
        layout.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.scan_table = _table("historyTable", SCAN_HEADERS, stretch_column=0)
        self.scan_table.itemSelectionChanged.connect(self._show_selected_scan)
        splitter.addWidget(self.scan_table)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.detail_tabs = QTabWidget()

        processes_page = QWidget()
        processes_layout = QVBoxLayout(processes_page)
        self.process_search_input = QLineEdit()
        self.process_search_input.setObjectName("searchInput")
        self.process_search_input.setPlaceholderText(
            "Search saved processes..."
        )
        self.process_search_input.setClearButtonEnabled(True)
        self.process_search_input.textChanged.connect(self._filter_processes)
        processes_layout.addWidget(self.process_search_input)
        self.process_table = _table(
            "historyTable", PROCESS_HEADERS, stretch_column=5
        )
        processes_layout.addWidget(self.process_table, 1)
        self.detail_tabs.addTab(processes_page, "Saved processes")

        compare_page = QWidget()
        compare_layout = QVBoxLayout(compare_page)
        self.compare_label = QLabel()
        self.compare_label.setObjectName("muted")
        self.compare_label.setWordWrap(True)
        compare_layout.addWidget(self.compare_label)
        self.compare_table = _table(
            "historyTable", COMPARE_HEADERS, stretch_column=4
        )
        compare_layout.addWidget(self.compare_table, 1)
        self.detail_tabs.addTab(compare_page, "Compare with previous scan")

        right_layout.addWidget(self.detail_tabs)
        splitter.addWidget(right)
        splitter.setSizes([360, 1000])
        layout.addWidget(splitter, 1)

        self.refresh()

    # ------------------------------------------------------------------

    def _report_error(self, exc) -> None:
        self.status_label.setText(f"Scan history is unavailable: {exc}")

    @Slot()
    def refresh(self) -> None:
        """Reload the list of saved scans (small, local reads only)."""
        self.scan_table.setRowCount(0)
        self.process_table.setRowCount(0)
        self.compare_table.setRowCount(0)
        self.scans = []

        if self.history is None:
            self.status_label.setText("Scan history is turned off.")
            self.clear_button.setEnabled(False)
            return

        try:
            self.scans = self.history.list_scans()
        except Exception as exc:
            self._report_error(exc)
            self.clear_button.setEnabled(False)
            return

        self.clear_button.setEnabled(bool(self.scans))
        self.status_label.setText(
            f"{len(self.scans)} saved scans. Select one to see its "
            "processes and what changed since the scan before it."
            if self.scans
            else "No saved scans yet. Each process scan is saved here."
        )

        for scan in self.scans:
            row = self.scan_table.rowCount()
            self.scan_table.insertRow(row)
            stamp = str(scan.get("scanned_at") or "").replace("T", "  ")
            values = [
                QTableWidgetItem(stamp),
                NumericTableWidgetItem(str(scan.get("scanned_count", 0))),
                NumericTableWidgetItem(str(scan.get("medium_count", 0))),
                NumericTableWidgetItem(str(scan.get("high_count", 0))),
            ]
            values[0].setData(Qt.ItemDataRole.UserRole, scan.get("id"))
            for column, item in enumerate(values):
                self.scan_table.setItem(row, column, item)

        if self.scans:
            self.scan_table.selectRow(0)

    def selected_scan_id(self) -> int | None:
        row = self.scan_table.currentRow()
        item = self.scan_table.item(row, 0) if row >= 0 else None
        value = item.data(Qt.ItemDataRole.UserRole) if item else None
        return value if isinstance(value, int) else None

    @Slot()
    def _show_selected_scan(self) -> None:
        scan_id = self.selected_scan_id()
        if scan_id is None or self.history is None:
            return

        try:
            processes = self.history.get_scan_processes(scan_id)
            comparison = self.history.compare_with_previous(scan_id)
        except Exception as exc:
            self._report_error(exc)
            return

        self._fill_processes(processes)
        self._fill_comparison(comparison)

    def _fill_processes(self, processes) -> None:
        table = self.process_table
        table.setRowCount(0)
        for process in processes:
            row = table.rowCount()
            table.insertRow(row)
            values = [
                NumericTableWidgetItem(str(process.get("pid", ""))),
                QTableWidgetItem(str(process.get("name") or "Unknown")),
                NumericTableWidgetItem(str(process.get("risk_score") or 0)),
                QTableWidgetItem(str(process.get("risk_level") or "low").upper()),
                QTableWidgetItem(signature_label(process.get("signature_status"))),
                QTableWidgetItem(str(process.get("exe_path") or "Unavailable")),
                QTableWidgetItem(", ".join(process.get("finding_codes") or [])),
            ]
            for column, item in enumerate(values):
                if process.get("is_new"):
                    item.setBackground(NEW_ROW_BRUSH)
                    item.setToolTip(NEW_TOOLTIP)
                table.setItem(row, column, item)
        self._filter_processes(self.process_search_input.text())

    def _fill_comparison(self, comparison) -> None:
        table = self.compare_table
        table.setRowCount(0)

        if comparison.get("previous_scan_id") is None:
            self.compare_label.setText(
                "This is the oldest saved scan, so there is nothing to "
                "compare it with."
            )
            return

        appeared = comparison.get("appeared") or []
        disappeared = comparison.get("disappeared") or []
        self.compare_label.setText(
            f"{len(appeared)} appeared and {len(disappeared)} disappeared "
            "since the previous scan. Programs start and stop all the time; "
            "a change is not suspicious by itself."
        )

        for change, rows in (("Appeared", appeared), ("Disappeared", disappeared)):
            for process in rows:
                row = table.rowCount()
                table.insertRow(row)
                values = [
                    QTableWidgetItem(change),
                    QTableWidgetItem(str(process.get("name") or "Unknown")),
                    NumericTableWidgetItem(str(process.get("pid", ""))),
                    NumericTableWidgetItem(str(process.get("risk_score") or 0)),
                    QTableWidgetItem(str(process.get("exe_path") or "Unavailable")),
                ]
                for column, item in enumerate(values):
                    table.setItem(row, column, item)

    @Slot(str)
    def _filter_processes(self, query: str) -> None:
        query = query.strip().casefold()
        table = self.process_table
        for row in range(table.rowCount()):
            text = " ".join(
                table.item(row, column).text()
                if table.item(row, column) is not None
                else ""
                for column in range(table.columnCount())
            ).casefold()
            table.setRowHidden(row, bool(query) and query not in text)

    @Slot()
    def _clear_history(self) -> None:
        if self.history is None:
            return

        answer = QMessageBox.question(
            self,
            "Clear scan history",
            "Delete all saved ProcessSentinel scans? This only removes "
            "ProcessSentinel's own history and cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            self.history.clear()
        except Exception as exc:
            self._report_error(exc)
            return
        self.refresh()
