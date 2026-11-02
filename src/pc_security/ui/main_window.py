"""Professional dashboard UI for ProcessSentinel."""

from __future__ import annotations

import re
from typing import Any, Callable

from PySide6.QtCore import QThread, QUrl, Signal, Slot, Qt
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


SIGNATURE_LABELS = {
    "valid": "Valid",
    "unsigned": "Unsigned",
    "invalid": "Invalid",
    "unknown": "Unknown",
}

_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

MAX_DETAIL_ENDPOINTS = 10

# Translucent amber reads well on both the dark and light themes.
FLAGGED_ROW_BRUSH = QBrush(QColor(251, 191, 36, 60))


def signature_label(status) -> str:
    """Return a readable label for a signature status."""
    return SIGNATURE_LABELS.get(status, "Not checked")


def virustotal_url(sha256) -> str | None:
    """Return the VirusTotal report URL for a hash, or None if invalid.

    Only the hash goes into the URL; no file is ever uploaded.
    """
    if not isinstance(sha256, str) or not _SHA256_PATTERN.match(sha256):
        return None
    return f"https://www.virustotal.com/gui/file/{sha256.lower()}"


class NumericTableWidgetItem(QTableWidgetItem):
    """Sort numeric values numerically rather than alphabetically."""

    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)


class TaskWorker(QThread):
    """Run scanning and AI requests without freezing the UI."""

    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, operation: Callable, parent=None):
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            result = self.operation(self.progress.emit)
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    """Main ProcessSentinel security dashboard."""

    def __init__(
        self,
        scan_service=None,
        ai_enabled: bool = False,
        ai_model: str = "openai/gpt-oss-20b",
        ai_timeout: int = 30,
        ai_max_tokens: int = 2000,
        explanation_service_factory=None,
        startup_scanner=None,
        parent=None,
    ):
        super().__init__(parent)

        self.scan_service = scan_service
        self.ai_enabled = ai_enabled
        self.ai_model = ai_model
        self.ai_timeout = ai_timeout
        self.ai_max_tokens = ai_max_tokens
        self.explanation_service_factory = explanation_service_factory
        self.startup_scanner = startup_scanner

        self.worker = None
        self.current_theme = "dark"
        self.analyses: list[dict[str, Any]] = []
        self.analyses_by_pid: dict[int, dict[str, Any]] = {}
        self.ai_explanations: dict[int, str] = {}
        self.ai_errors: dict[int, str] = {}
        self.ai_candidate_pids: list[int] = []
        self.ai_selection_mode = "not_requested"
        self.network_connections: list[dict[str, Any]] = []
        self.startup_entries: list[dict[str, Any]] = []

        self.setWindowTitle("ProcessSentinel")
        self.resize(1500, 900)
        self.setMinimumSize(1000, 680)

        self._build_ui()
        self._apply_theme()
        self._set_busy(False)

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        outer_layout = QVBoxLayout(root)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setObjectName("workspaceTabs")
        outer_layout.addWidget(self.workspace_tabs)

        # ============================================================
        # WORKSPACE 1: SECURITY OVERVIEW
        # ============================================================
        self.dashboard_page = QWidget()
        self.dashboard_page.setObjectName("dashboardPage")
        self.workspace_tabs.addTab(
            self.dashboard_page, "Security overview"
        )

        layout = QVBoxLayout(self.dashboard_page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()

        brand_icon = QLabel("◈")
        brand_icon.setObjectName("brandIcon")
        brand_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand_icon.setFixedSize(48, 48)
        header.addWidget(brand_icon)

        brand_text = QVBoxLayout()

        title = QLabel("ProcessSentinel")
        title.setObjectName("appTitle")

        subtitle = QLabel("WINDOWS PROCESS SECURITY")
        subtitle.setObjectName("eyebrow")

        brand_text.addWidget(title)
        brand_text.addWidget(subtitle)
        header.addLayout(brand_text)
        header.addStretch()

        self.theme_button = QPushButton("☀  Light mode")
        self.theme_button.setObjectName("themeButton")
        self.theme_button.clicked.connect(self._toggle_theme)
        self.theme_button.setToolTip(
            "Switch between dark and light appearance."
        )
        header.addWidget(self.theme_button)

        # Keep compatibility with existing scan-state logic, but hide it.
        self.connection_label = QLabel("LOCAL SCANNER")
        self.connection_label.hide()

        layout.addLayout(header)

        intro = QHBoxLayout()
        intro_text = QVBoxLayout()

        heading = QLabel("Security overview")
        heading.setObjectName("sectionTitle")

        description = QLabel(
            "Inspect running processes, review rule-based evidence, "
            "and request AI-assisted explanations."
        )
        description.setObjectName("muted")
        description.setWordWrap(True)

        intro_text.addWidget(heading)
        intro_text.addWidget(description)
        intro.addLayout(intro_text, 1)

        self.scan_button = QPushButton("↻  Scan processes")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.clicked.connect(self._start_scan)
        intro.addWidget(self.scan_button)

        self.ai_scan_button = QPushButton("✦  Scan + AI analysis")
        self.ai_scan_button.setObjectName("secondaryButton")
        self.ai_scan_button.setToolTip(
            "Scan processes and request AI explanations for up to "
            "10 candidates selected by the scan service."
        )
        self.ai_scan_button.clicked.connect(self._start_ai_scan)
        intro.addWidget(self.ai_scan_button)

        layout.addLayout(intro)

        stats = QHBoxLayout()
        stats.setSpacing(12)

        self.scanned_value = self._add_stat_card(
            stats, "PROCESSES ANALYZED", "0", "▤", "statBlue"
        )
        self.flagged_value = self._add_stat_card(
            stats, "POSITIVE RISK SCORES", "0", "!", "statAmber"
        )
        self.explained_value = self._add_stat_card(
            stats, "AI EXPLANATIONS", "0", "✦", "statPurple"
        )
        self.failures_value = self._add_stat_card(
            stats, "AI REQUEST FAILURES", "0", "×", "statRed"
        )

        layout.addLayout(stats)

        status_frame = QFrame()
        status_frame.setObjectName("statusFrame")

        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 9, 12, 9)
        status_layout.setSpacing(6)

        self.status_label = QLabel("Ready to scan this computer.")
        self.status_label.setObjectName("statusText")
        status_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(5)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)

        layout.addWidget(status_frame)

        explorer_header = QHBoxLayout()

        explorer_title = QLabel("Process explorer")
        explorer_title.setObjectName("sectionTitle")
        explorer_header.addWidget(explorer_title)

        self.result_count = QLabel("0 processes")
        self.result_count.setObjectName("muted")
        explorer_header.addWidget(self.result_count)
        explorer_header.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText(
            "Search process name, PID, or path..."
        )
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setFixedWidth(310)
        self.search_input.textChanged.connect(self._filter_processes)
        explorer_header.addWidget(self.search_input)

        layout.addLayout(explorer_header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        table_frame = QFrame()
        table_frame.setObjectName("panel")
        table_layout = QVBoxLayout(table_frame)
        table_layout.setContentsMargins(8, 8, 8, 8)

        self.process_table = QTableWidget(0, 6)
        self.process_table.setObjectName("processTable")
        self.process_table.setHorizontalHeaderLabels(
            [
                "PID", "PROCESS", "RISK SCORE", "RISK LEVEL",
                "SIGNATURE", "EXECUTABLE",
            ]
        )
        self.process_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.process_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.process_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.process_table.setShowGrid(False)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSortingEnabled(True)
        self.process_table.verticalHeader().setVisible(False)
        self.process_table.verticalHeader().setDefaultSectionSize(36)

        table_header = self.process_table.horizontalHeader()
        for column in range(5):
            table_header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        table_header.setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )

        self.process_table.itemSelectionChanged.connect(
            self._show_selected_process
        )
        table_layout.addWidget(self.process_table)
        splitter.addWidget(table_frame)

        detail_frame = QFrame()
        detail_frame.setObjectName("panel")
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        detail_layout.setSpacing(10)

        detail_heading = QLabel("Process details")
        detail_heading.setObjectName("sectionTitle")
        detail_layout.addWidget(detail_heading)

        self.selected_process_label = QLabel("No process selected")
        self.selected_process_label.setObjectName("detailTitle")
        self.selected_process_label.setWordWrap(True)
        detail_layout.addWidget(self.selected_process_label)

        self.selected_pid_label = QLabel(
            "Select a process to inspect its evidence."
        )
        self.selected_pid_label.setObjectName("muted")
        self.selected_pid_label.setWordWrap(True)
        detail_layout.addWidget(self.selected_pid_label)

        detail_layout.addWidget(self._separator())

        self.detail_tabs = QTabWidget()
        self.detail_tabs.setObjectName("detailTabs")

        self.details_text = QTextEdit()
        self.details_text.setObjectName("detailsText")
        self.details_text.setReadOnly(True)
        self.details_text.setAcceptRichText(False)
        self.details_text.setPlaceholderText(
            "Process path, risk score, findings, and verification "
            "guidance will appear here."
        )
        self.detail_tabs.addTab(
            self.details_text, "Process evidence"
        )

        self.ai_analysis_text = QTextEdit()
        self.ai_analysis_text.setObjectName("aiAnalysisText")
        self.ai_analysis_text.setReadOnly(True)
        self.ai_analysis_text.setAcceptRichText(False)
        self.ai_analysis_text.setPlaceholderText(
            "Use the Explainable AI Lab tab to read full reports."
        )
        self.detail_tabs.addTab(
            self.ai_analysis_text, "AI summary"
        )

        detail_layout.addWidget(self.detail_tabs, 1)

        self.retry_button = QPushButton(
            "✦  Explain selected process"
        )
        self.retry_button.setObjectName("secondaryButton")
        self.retry_button.clicked.connect(self._explain_selected)
        detail_layout.addWidget(self.retry_button)

        self.virustotal_button = QPushButton(
            "↗  Look up hash on VirusTotal"
        )
        self.virustotal_button.setObjectName("secondaryButton")
        self.virustotal_button.setToolTip(
            "Opens the VirusTotal report for this file's SHA-256 in your "
            "browser. Only the hash is in the link; no file is uploaded."
        )
        self.virustotal_button.setEnabled(False)
        self.virustotal_button.clicked.connect(self._open_virustotal)
        detail_layout.addWidget(self.virustotal_button)

        splitter.addWidget(detail_frame)
        splitter.setSizes([780, 460])
        layout.addWidget(splitter, 1)

        footer = QHBoxLayout()
        footer_text = QLabel(
            "READ-ONLY MODE  •  No process termination or file deletion"
        )
        footer_text.setObjectName("footerText")
        footer.addWidget(footer_text)
        footer.addStretch()

        self.footer_ai_label = QLabel(f"AI model: {self.ai_model}")
        self.footer_ai_label.setObjectName("footerText")
        footer.addWidget(self.footer_ai_label)

        layout.addLayout(footer)

        # ============================================================
        # WORKSPACE 2: EXPLAINABLE AI LAB
        # ============================================================
        self.ai_lab_page = QWidget()
        self.ai_lab_page.setObjectName("aiLabPage")
        self.workspace_tabs.addTab(
            self.ai_lab_page, "Explainable AI Lab"
        )

        lab_layout = QVBoxLayout(self.ai_lab_page)
        lab_layout.setContentsMargins(22, 20, 22, 20)
        lab_layout.setSpacing(14)

        lab_header = QHBoxLayout()
        lab_heading_layout = QVBoxLayout()

        lab_title = QLabel("Explainable AI Lab")
        lab_title.setObjectName("sectionTitle")

        lab_subtitle = QLabel(
            "Explore candidate processes and read detailed, "
            "evidence-based AI reports."
        )
        lab_subtitle.setObjectName("muted")
        lab_subtitle.setWordWrap(True)

        lab_heading_layout.addWidget(lab_title)
        lab_heading_layout.addWidget(lab_subtitle)
        lab_header.addLayout(lab_heading_layout, 1)

        self.ai_lab_mode_label = QLabel(
            "Run Scan + AI analysis to populate this workspace."
        )
        self.ai_lab_mode_label.setObjectName("muted")
        self.ai_lab_mode_label.setWordWrap(True)
        self.ai_lab_mode_label.setMaximumWidth(480)
        lab_header.addWidget(self.ai_lab_mode_label)

        lab_layout.addLayout(lab_header)

        lab_splitter = QSplitter(Qt.Orientation.Horizontal)
        lab_splitter.setChildrenCollapsible(False)

        candidate_frame = QFrame()
        candidate_frame.setObjectName("panel")
        candidate_layout = QVBoxLayout(candidate_frame)
        candidate_layout.setContentsMargins(12, 12, 12, 12)
        candidate_layout.setSpacing(8)

        candidate_title = QLabel("AI review candidates")
        candidate_title.setObjectName("detailTitle")
        candidate_layout.addWidget(candidate_title)

        self.ai_candidate_table = QTableWidget(0, 4)
        self.ai_candidate_table.setObjectName("aiCandidateTable")
        self.ai_candidate_table.setHorizontalHeaderLabels(
            ["PID", "PROCESS", "SCORE", "LEVEL"]
        )
        self.ai_candidate_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.ai_candidate_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.ai_candidate_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.ai_candidate_table.setShowGrid(False)
        self.ai_candidate_table.setAlternatingRowColors(True)
        self.ai_candidate_table.verticalHeader().setVisible(False)

        candidate_header = self.ai_candidate_table.horizontalHeader()
        candidate_header.setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        candidate_header.setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        candidate_header.setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        candidate_header.setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )

        self.ai_candidate_table.itemSelectionChanged.connect(
            self._show_ai_candidate_report
        )
        candidate_layout.addWidget(self.ai_candidate_table, 1)
        lab_splitter.addWidget(candidate_frame)

        report_frame = QFrame()
        report_frame.setObjectName("panel")
        report_layout = QVBoxLayout(report_frame)
        report_layout.setContentsMargins(14, 14, 14, 14)
        report_layout.setSpacing(8)

        report_title = QLabel("Detailed process report")
        report_title.setObjectName("detailTitle")
        report_layout.addWidget(report_title)

        self.ai_lab_text = QTextEdit()
        self.ai_lab_text.setObjectName("aiLabText")
        self.ai_lab_text.setReadOnly(True)
        self.ai_lab_text.setAcceptRichText(False)
        self.ai_lab_text.setLineWrapMode(
            QTextEdit.LineWrapMode.WidgetWidth
        )
        self.ai_lab_text.setPlaceholderText(
            "Run Scan + AI analysis, then select a candidate on the left. "
            "The full explanation will appear here."
        )
        report_layout.addWidget(self.ai_lab_text, 1)

        lab_splitter.addWidget(report_frame)
        lab_splitter.setSizes([360, 1000])
        lab_layout.addWidget(lab_splitter, 1)

        self._build_network_tab()
        self._build_startup_tab()

    @staticmethod
    def _make_table(object_name, headers, stretch_column):
        table = QTableWidget(0, len(headers))
        table.setObjectName(object_name)
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
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

    @staticmethod
    def _page_header(layout, title_text, subtitle_text):
        title = QLabel(title_text)
        title.setObjectName("sectionTitle")
        subtitle = QLabel(subtitle_text)
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

    def _build_network_tab(self) -> None:
        # ============================================================
        # WORKSPACE 3: NETWORK CONNECTIONS
        # ============================================================
        self.network_page = QWidget()
        self.network_page.setObjectName("networkPage")
        self.workspace_tabs.addTab(self.network_page, "Network")

        layout = QVBoxLayout(self.network_page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        self._page_header(
            layout,
            "Network connections",
            "Connections open at the time of the last process scan. "
            "Click a row to open that process in Security overview. "
            "ProcessSentinel only lists connections; it never blocks them.",
        )

        controls = QHBoxLayout()
        self.network_search_input = QLineEdit()
        self.network_search_input.setObjectName("searchInput")
        self.network_search_input.setPlaceholderText(
            "Search process, PID, address, port or state..."
        )
        self.network_search_input.setClearButtonEnabled(True)
        self.network_search_input.setFixedWidth(340)
        self.network_search_input.textChanged.connect(self._filter_network)
        controls.addWidget(self.network_search_input)

        self.established_only_checkbox = QCheckBox("Show only established")
        self.established_only_checkbox.toggled.connect(self._filter_network)
        controls.addWidget(self.established_only_checkbox)
        controls.addStretch()

        self.network_count_label = QLabel("0 connections")
        self.network_count_label.setObjectName("muted")
        controls.addWidget(self.network_count_label)
        layout.addLayout(controls)

        self.network_notes_label = QLabel("Run a process scan to list connections.")
        self.network_notes_label.setObjectName("muted")
        self.network_notes_label.setWordWrap(True)
        layout.addWidget(self.network_notes_label)

        self.network_table = self._make_table(
            "networkTable",
            [
                "PROCESS", "PID", "PROTOCOL", "LOCAL ADDRESS",
                "REMOTE ADDRESS", "REMOTE PORT", "STATE",
            ],
            stretch_column=4,
        )
        self.network_table.cellClicked.connect(
            self._select_process_from_network
        )
        layout.addWidget(self.network_table, 1)

    def _build_startup_tab(self) -> None:
        # ============================================================
        # WORKSPACE 4: STARTUP / PERSISTENCE
        # ============================================================
        self.startup_page = QWidget()
        self.startup_page.setObjectName("startupPage")
        self.workspace_tabs.addTab(self.startup_page, "Startup")

        layout = QVBoxLayout(self.startup_page)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        self._page_header(
            layout,
            "Startup items",
            "Programs Windows starts automatically: registry Run keys, "
            "Startup folders and scheduled tasks. This list is read-only; "
            "nothing is disabled or removed.",
        )

        controls = QHBoxLayout()
        self.startup_scan_button = QPushButton("↻  Scan startup items")
        self.startup_scan_button.setObjectName("primaryButton")
        self.startup_scan_button.clicked.connect(self._start_startup_scan)
        controls.addWidget(self.startup_scan_button)

        self.include_builtin_tasks_checkbox = QCheckBox(
            "Include built-in Windows tasks"
        )
        self.include_builtin_tasks_checkbox.setToolTip(
            "Also list tasks under \\Microsoft\\Windows\\. There are "
            "usually hundreds of these."
        )
        controls.addWidget(self.include_builtin_tasks_checkbox)
        controls.addStretch()

        self.startup_search_input = QLineEdit()
        self.startup_search_input.setObjectName("searchInput")
        self.startup_search_input.setPlaceholderText(
            "Search name, command, path or flag..."
        )
        self.startup_search_input.setClearButtonEnabled(True)
        self.startup_search_input.setFixedWidth(310)
        self.startup_search_input.textChanged.connect(self._filter_startup)
        controls.addWidget(self.startup_search_input)
        layout.addLayout(controls)

        self.startup_notes_label = QLabel(
            "Click Scan startup items to list autostart entries."
        )
        self.startup_notes_label.setObjectName("muted")
        self.startup_notes_label.setWordWrap(True)
        layout.addWidget(self.startup_notes_label)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        self.startup_table = self._make_table(
            "startupTable",
            [
                "SOURCE", "NAME", "COMMAND", "EXECUTABLE PATH",
                "SIGNATURE", "FLAGS",
            ],
            stretch_column=2,
        )
        self.startup_table.itemSelectionChanged.connect(
            self._show_selected_startup_entry
        )
        splitter.addWidget(self.startup_table)

        self.startup_details_text = QTextEdit()
        self.startup_details_text.setObjectName("startupDetailsText")
        self.startup_details_text.setReadOnly(True)
        self.startup_details_text.setAcceptRichText(False)
        self.startup_details_text.setPlaceholderText(
            "Select a startup entry to see its full details."
        )
        splitter.addWidget(self.startup_details_text)
        splitter.setSizes([520, 220])
        layout.addWidget(splitter, 1)

    def _add_stat_card(
        self, parent_layout, label, value, symbol, accent
    ):
        card = QFrame()
        card.setObjectName("statCard")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(7)

        top = QHBoxLayout()
        label_widget = QLabel(label)
        label_widget.setObjectName("statLabel")
        label_widget.setWordWrap(True)
        top.addWidget(label_widget, 1)

        icon_widget = QLabel(symbol)
        icon_widget.setObjectName(accent)
        icon_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top.addWidget(icon_widget)

        card_layout.addLayout(top)

        value_widget = QLabel(value)
        value_widget.setObjectName("statValue")
        card_layout.addWidget(value_widget)

        parent_layout.addWidget(card, 1)
        return value_widget

    @staticmethod
    def _separator():
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setObjectName("separator")
        return line

    def _apply_theme(self) -> None:
        dark = """
        QMainWindow, QWidget#root {
            background: #0B1120; color: #E5EAF4;
            font-family: "Segoe UI"; font-size: 10pt;
        }
        QLabel#appTitle { color: #F8FAFC; font-size: 23pt; font-weight: 700; }
        QLabel#brandIcon {
            background: #172B4D; color: #7DB4FF;
            border: 1px solid #2C4771; border-radius: 14px;
            font-size: 27pt; font-weight: 700;
        }
        QLabel#eyebrow { color: #7F93B5; font-size: 8pt; font-weight: 700; }
        QLabel#sectionTitle { color: #F1F5F9; font-size: 15pt; font-weight: 650; }
        QLabel#muted, QLabel#footerText { color: #91A0B8; font-size: 9pt; }
        QFrame#statCard, QFrame#panel, QFrame#statusFrame {
            background: #111B2E; border: 1px solid #243149; border-radius: 12px;
        }
        QLabel#statLabel { color: #93A4BD; font-size: 8pt; font-weight: 700; }
        QLabel#statValue { color: #F8FAFC; font-size: 25pt; font-weight: 700; }
        QLabel#statBlue { color: #60A5FA; font-size: 18pt; }
        QLabel#statAmber { color: #FBBF24; font-size: 18pt; }
        QLabel#statPurple { color: #C4B5FD; font-size: 18pt; }
        QLabel#statRed { color: #FCA5A5; font-size: 18pt; }
        QLabel#statusText { color: #CBD5E1; font-size: 9pt; }
        QLabel#detailTitle { color: #F8FAFC; font-size: 14pt; font-weight: 700; }
        QPushButton {
            border-radius: 8px; padding: 10px 14px;
            font-weight: 650; min-height: 18px;
        }
        QPushButton#primaryButton { color: white; background: #2563EB; border: 1px solid #3B82F6; }
        QPushButton#primaryButton:hover { background: #3478F6; }
        QPushButton#secondaryButton, QPushButton#themeButton {
            color: #E0E7FF; background: #202D48; border: 1px solid #344767;
        }
        QPushButton#secondaryButton:hover, QPushButton#themeButton:hover { background: #2B3B5B; }
        QPushButton:disabled { color: #68758B; background: #172033; border-color: #263247; }
        QLineEdit#searchInput {
            color: #E5EAF4; background: #111B2E; border: 1px solid #2B3A53;
            border-radius: 8px; padding: 10px 12px; selection-background-color: #2563EB;
        }
        QTableWidget#processTable, QTableWidget#aiCandidateTable,
        QTableWidget#networkTable, QTableWidget#startupTable {
            background: #111B2E; alternate-background-color: #131F33;
            color: #DCE5F2; border: none; selection-background-color: #1D3A65;
            selection-color: white; outline: none;
        }
        QTableWidget#processTable::item, QTableWidget#aiCandidateTable::item,
        QTableWidget#networkTable::item, QTableWidget#startupTable::item {
            padding: 7px; border-bottom: 1px solid #202D43;
        }
        QHeaderView::section {
            background: #172238; color: #91A4C1; border: none;
            border-bottom: 1px solid #2B3A53; padding: 10px 7px;
            font-size: 8pt; font-weight: 700;
        }
        QTextEdit#detailsText, QTextEdit#aiAnalysisText, QTextEdit#aiLabText,
        QTextEdit#startupDetailsText {
            background: #0D1728; color: #D6E0EF; border: 1px solid #253650;
            border-radius: 8px; padding: 14px; selection-background-color: #2563EB;
            font-family: "Segoe UI"; font-size: 11pt;
        }
        QTextEdit#aiLabText { font-size: 12pt; padding: 18px; }
        QFrame#separator { max-height: 1px; border: none; background: #26364F; }
        QProgressBar#scanProgress { background: #202D43; border: none; border-radius: 2px; }
        QProgressBar#scanProgress::chunk { background: #3B82F6; border-radius: 2px; }
        QSplitter::handle { background: #0B1120; width: 7px; }
        QTabWidget::pane { border: 1px solid #253650; border-radius: 8px; top: -1px; }
        QTabBar::tab {
            background: #172238; color: #91A4C1; padding: 10px 13px;
            margin-right: 4px; border-top-left-radius: 6px; border-top-right-radius: 6px;
        }
        QTabBar::tab:selected { background: #2563EB; color: white; }
        QScrollBar:vertical { background: #111B2E; width: 10px; margin: 0; }
        QScrollBar::handle:vertical { background: #34445F; min-height: 25px; border-radius: 4px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """

        light = """
        QMainWindow, QWidget#root {
            background: #F3F6FB; color: #1F2937;
            font-family: "Segoe UI"; font-size: 10pt;
        }
        QLabel#appTitle, QLabel#statValue, QLabel#detailTitle { color: #111827; }
        QLabel#brandIcon {
            background: #E0EAFA; color: #2457A7; border: 1px solid #C5D5EE;
            border-radius: 14px; font-size: 27pt; font-weight: 700;
        }
        QLabel#eyebrow, QLabel#muted, QLabel#footerText { color: #64748B; }
        QLabel#sectionTitle { color: #172033; font-size: 15pt; font-weight: 650; }
        QFrame#statCard, QFrame#panel, QFrame#statusFrame {
            background: white; border: 1px solid #D7E0EC; border-radius: 12px;
        }
        QLabel#statLabel { color: #64748B; font-size: 8pt; font-weight: 700; }
        QLabel#statBlue { color: #2563EB; font-size: 18pt; }
        QLabel#statAmber { color: #B45309; font-size: 18pt; }
        QLabel#statPurple { color: #7C3AED; font-size: 18pt; }
        QLabel#statRed { color: #DC2626; font-size: 18pt; }
        QLabel#statusText { color: #334155; font-size: 9pt; }
        QPushButton {
            border-radius: 8px; padding: 10px 14px; font-weight: 650; min-height: 18px;
        }
        QPushButton#primaryButton { color: white; background: #2563EB; border: 1px solid #2563EB; }
        QPushButton#primaryButton:hover { background: #1D4ED8; }
        QPushButton#secondaryButton, QPushButton#themeButton {
            color: #243247; background: #E7EEF8; border: 1px solid #C5D5E8;
        }
        QPushButton#secondaryButton:hover, QPushButton#themeButton:hover { background: #DCE7F5; }
        QPushButton:disabled { color: #94A3B8; background: #EDF2F8; border-color: #D7E0EC; }
        QLineEdit#searchInput {
            color: #243247; background: white; border: 1px solid #CBD5E1;
            border-radius: 8px; padding: 10px 12px; selection-background-color: #2563EB;
        }
        QTableWidget#processTable, QTableWidget#aiCandidateTable,
        QTableWidget#networkTable, QTableWidget#startupTable {
            background: white; alternate-background-color: #F6F8FC; color: #243247;
            border: none; selection-background-color: #C9DDFB; selection-color: #111827;
            outline: none;
        }
        QTableWidget#processTable::item, QTableWidget#aiCandidateTable::item,
        QTableWidget#networkTable::item, QTableWidget#startupTable::item {
            padding: 7px; border-bottom: 1px solid #E2E8F0;
        }
        QHeaderView::section {
            background: #EDF2F8; color: #64748B; border: none;
            border-bottom: 1px solid #CBD5E1; padding: 10px 7px;
            font-size: 8pt; font-weight: 700;
        }
        QTextEdit#detailsText, QTextEdit#aiAnalysisText, QTextEdit#aiLabText,
        QTextEdit#startupDetailsText {
            background: #F8FAFC; color: #243247; border: 1px solid #CBD5E1;
            border-radius: 8px; padding: 14px; selection-background-color: #2563EB;
            font-family: "Segoe UI"; font-size: 11pt;
        }
        QTextEdit#aiLabText { font-size: 12pt; padding: 18px; }
        QFrame#separator { max-height: 1px; border: none; background: #D7E0EC; }
        QProgressBar#scanProgress { background: #E2E8F0; border: none; border-radius: 2px; }
        QProgressBar#scanProgress::chunk { background: #2563EB; border-radius: 2px; }
        QSplitter::handle { background: #F3F6FB; width: 7px; }
        QTabWidget::pane { border: 1px solid #CBD5E1; border-radius: 8px; top: -1px; }
        QTabBar::tab {
            background: #EDF2F8; color: #64748B; padding: 10px 13px;
            margin-right: 4px; border-top-left-radius: 6px; border-top-right-radius: 6px;
        }
        QTabBar::tab:selected { background: #2563EB; color: white; }
        QScrollBar:vertical { background: white; width: 10px; margin: 0; }
        QScrollBar::handle:vertical { background: #B6C3D4; min-height: 25px; border-radius: 4px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """

        self.setStyleSheet(dark if self.current_theme == "dark" else light)
        self.theme_button.setText(
            "☀  Light mode" if self.current_theme == "dark" else "☾  Dark mode"
        )

    def _toggle_theme(self) -> None:
        self.current_theme = (
            "light" if self.current_theme == "dark" else "dark"
        )
        self._apply_theme()

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.ai_scan_button.setEnabled(not busy)
        self.retry_button.setEnabled(not busy)
        self.startup_scan_button.setEnabled(not busy)

        if busy:
            self.progress_bar.setRange(0, 0)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(1)

    def _start_scan(self) -> None:
        self._run_scan(include_ai=False)

    def _start_ai_scan(self) -> None:
        self._run_scan(include_ai=True)

    def _run_scan(self, include_ai: bool) -> None:
        if self.scan_service is None:
            QMessageBox.warning(
                self, "Scanner unavailable",
                "The scan service is not connected. Check main.py."
            )
            return

        self._set_busy(True)
        self.status_label.setText("Scanning running processes...")
        self.details_text.clear()

        if include_ai:
            self.ai_lab_text.setPlainText(
                "Scanning processes and preparing AI explanations for up to "
                "10 risk-ranked or contextual-review candidates..."
            )
            self.ai_analysis_text.setPlainText(
                "AI scan is running. Open the Explainable AI Lab for reports."
            )
            self.workspace_tabs.setCurrentWidget(self.ai_lab_page)

        def operation(report_progress):
            return self.scan_service.run_scan(
                include_ai=include_ai,
                progress_callback=report_progress,
            )

        self.worker = TaskWorker(operation, self)
        self.worker.progress.connect(self._update_progress)
        self.worker.succeeded.connect(self._scan_succeeded)
        self.worker.failed.connect(self._operation_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    @Slot(str)
    def _update_progress(self, message: str) -> None:
        self.status_label.setText(message)

    @Slot(object)
    def _scan_succeeded(self, result: dict[str, Any]) -> None:
        self.analyses = result.get("analyses", [])
        self.ai_selection_mode = result.get(
            "ai_selection_mode", "not_requested"
        )

        supplied_pids = result.get("ai_candidate_pids", [])
        self.ai_candidate_pids = []
        for pid in supplied_pids:
            try:
                if pid is not None:
                    self.ai_candidate_pids.append(int(pid))
            except (TypeError, ValueError):
                continue

        self.analyses_by_pid = {
            int(item["pid"]): item
            for item in self.analyses
            if item.get("pid") is not None
        }

        self.ai_explanations = {}
        self.ai_errors = {}

        for item in result.get("ai_explanations", []):
            if isinstance(item, dict) and item.get("pid") is not None:
                if item.get("explanation"):
                    self.ai_explanations[int(item["pid"])] = str(
                        item["explanation"]
                    )

        for item in result.get("ai_errors", []):
            if isinstance(item, dict) and item.get("pid") is not None:
                if item.get("error"):
                    self.ai_errors[int(item["pid"])] = str(item["error"])

        self._populate_table()
        self._render_ai_analysis(result)
        self._populate_network(result)

        scanned = result.get("scanned_count", len(self.analyses))
        flagged = sum(
            1 for item in self.analyses
            if (item.get("risk_score") or 0) > 0
        )

        self.scanned_value.setText(str(scanned))
        self.flagged_value.setText(str(flagged))
        self.explained_value.setText(str(len(self.ai_explanations)))
        self.failures_value.setText(str(len(self.ai_errors)))
        self.status_label.setText(
            f"Scan completed. {scanned} processes scanned."
        )

        if flagged == 0:
            self.details_text.setPlainText(
                "No processes received a positive score from the current "
                "security rules.\n\nThis does not prove the computer is safe. "
                "It means the configured rules did not flag a process.\n\n"
                "Risk scores are heuristic indicators, not malware probabilities."
            )
        elif not self.ai_explanations and self.ai_errors:
            self.details_text.setPlainText(
                "The process scan completed, but AI explanations failed.\n\n"
                "Check GROQ_API_KEY, the network connection, model availability, "
                "and Groq API limits."
            )

    def _render_ai_analysis(self, result: dict[str, Any]) -> None:
        """Populate the AI candidate list and full-size report workspace."""
        if not result.get("ai_enabled_for_scan", False):
            self.ai_lab_mode_label.setText(
                "This scan did not request AI analysis. Use Scan + AI analysis."
            )
            return

        # Fallback for older scan-service versions.
        if not self.ai_candidate_pids:
            self.ai_candidate_pids = [
                int(item["pid"])
                for item in sorted(
                    self.analyses,
                    key=lambda item: (
                        -int(item.get("risk_score", 0) or 0),
                        int(item.get("pid", 0) or 0),
                    ),
                )
                if item.get("pid") is not None
                and int(item.get("risk_score", 0) or 0) > 0
            ][:10]

        if self.ai_selection_mode == "contextual_review":
            mode_text = (
                "CONTEXTUAL REVIEW: no positive rule scores were available. "
                "Candidates were selected for additional context, not because "
                "they were automatically considered suspicious."
            )
        elif self.ai_selection_mode == "positive_score":
            mode_text = (
                "RISK REVIEW: candidates were selected using positive "
                "rule-based scores. Scores are not malware verdicts."
            )
        else:
            mode_text = (
                "Candidate selection mode was not supplied by the scan service."
            )

        self.ai_lab_mode_label.setText(mode_text)
        self.ai_candidate_table.setRowCount(0)

        for pid in self.ai_candidate_pids:
            analysis = self.analyses_by_pid.get(pid)
            if analysis is None:
                continue

            row = self.ai_candidate_table.rowCount()
            self.ai_candidate_table.insertRow(row)

            values = [
                NumericTableWidgetItem(str(pid)),
                QTableWidgetItem(str(analysis.get("name") or "Unknown")),
                NumericTableWidgetItem(
                    str(analysis.get("risk_score", 0) or 0)
                ),
                QTableWidgetItem(
                    str(analysis.get("risk_level", "low")).upper()
                ),
            ]

            for column, item in enumerate(values):
                self.ai_candidate_table.setItem(row, column, item)

        if self.ai_candidate_table.rowCount() == 0:
            message = (
                "No AI review candidates were returned for this scan.\n\n"
                "This does not prove that every process is safe. Review the "
                "rule findings and verify that AI analysis was enabled."
            )
            self.ai_lab_text.setPlainText(message)
            self.ai_analysis_text.setPlainText(message)
            return

        self.ai_analysis_text.setPlainText(
            "AI review candidates are available in the Explainable AI Lab.\n\n"
            + mode_text
        )
        self.ai_candidate_table.selectRow(0)
        self._show_ai_candidate_report()

    @Slot()
    def _show_ai_candidate_report(self) -> None:
        """Display the selected candidate's full AI report."""
        row = self.ai_candidate_table.currentRow()
        if row < 0:
            return

        pid_item = self.ai_candidate_table.item(row, 0)
        if pid_item is None:
            return

        try:
            pid = int(pid_item.text())
        except ValueError:
            return

        analysis = self.analyses_by_pid.get(pid, {})
        name = analysis.get("name") or "Unknown process"
        score = analysis.get("risk_score", 0) or 0
        level = str(analysis.get("risk_level", "low")).upper()
        path = analysis.get("exe_path") or "Unavailable"

        if pid in self.ai_explanations:
            report = self.ai_explanations[pid]
        elif pid in self.ai_errors:
            report = (
                f"AI explanation failed for PID {pid}:\n\n"
                f"{self.ai_errors[pid]}"
            )
        else:
            report = (
                "No AI explanation was returned for this candidate.\n\n"
                "Select the process in Security overview and click "
                "'Explain selected process' to retry."
            )

        self.ai_lab_text.setPlainText(
            "PROCESS SECURITY REPORT\n"
            + "=" * 72
            + f"\nProcess: {name}\nPID: {pid}\n"
            + f"Rule-based score: {score}\nRisk level: {level}\n"
            + f"Executable path: {path}\n\n"
            + "-" * 72
            + "\nAI EXPLANATION\n"
            + "-" * 72
            + f"\n\n{report}\n\n"
            + "SAFETY NOTE\n"
            + "This is an advisory explanation based on supplied evidence. "
            "It is not proof that a process is malicious or safe. "
            "ProcessSentinel remains read-only."
        )

    def _populate_table(self) -> None:
        self.process_table.setSortingEnabled(False)
        self.process_table.setRowCount(0)

        ordered = sorted(
            self.analyses,
            key=lambda item: (
                -int(item.get("risk_score", 0) or 0),
                int(item.get("pid", 0) or 0),
            ),
        )

        for analysis in ordered:
            row = self.process_table.rowCount()
            self.process_table.insertRow(row)

            pid_item = NumericTableWidgetItem(
                str(analysis.get("pid", ""))
            )
            name_item = QTableWidgetItem(
                str(analysis.get("name") or "Unknown")
            )
            score_item = NumericTableWidgetItem(
                str(analysis.get("risk_score", 0) or 0)
            )
            level = str(analysis.get("risk_level", "low")).upper()
            level_item = QTableWidgetItem(level)
            signature_status = analysis.get("signature_status")
            signature_item = QTableWidgetItem(
                signature_label(signature_status)
            )
            if signature_status == "invalid":
                signature_item.setForeground(Qt.GlobalColor.red)
            elif signature_status == "unsigned":
                signature_item.setForeground(Qt.GlobalColor.yellow)
            path_item = QTableWidgetItem(
                str(analysis.get("exe_path") or "Unavailable")
            )

            if level == "HIGH":
                level_item.setForeground(Qt.GlobalColor.red)
            elif level == "MEDIUM":
                level_item.setForeground(Qt.GlobalColor.yellow)
            else:
                level_item.setForeground(Qt.GlobalColor.green)

            for column, item in enumerate(
                [
                    pid_item, name_item, score_item, level_item,
                    signature_item, path_item,
                ]
            ):
                self.process_table.setItem(row, column, item)

        self.process_table.setSortingEnabled(True)
        self._filter_processes(self.search_input.text())

        if self.process_table.rowCount():
            self.process_table.selectRow(0)
        else:
            self.selected_process_label.setText("No processes found")
            self.selected_pid_label.setText(
                "Run a scan to populate the process explorer."
            )
            self.details_text.clear()

    @Slot(str)
    def _filter_processes(self, query: str) -> None:
        query = query.strip().casefold()
        visible = 0

        for row in range(self.process_table.rowCount()):
            searchable = " ".join(
                self.process_table.item(row, column).text()
                if self.process_table.item(row, column) is not None
                else ""
                for column in range(self.process_table.columnCount())
            ).casefold()

            hidden = query not in searchable
            self.process_table.setRowHidden(row, hidden)
            if not hidden:
                visible += 1

        self.result_count.setText(
            f"{visible} of {self.process_table.rowCount()} processes"
            if query
            else f"{self.process_table.rowCount()} processes"
        )

    def _selected_pid(self) -> int | None:
        row = self.process_table.currentRow()
        if row < 0 or self.process_table.isRowHidden(row):
            return None

        item = self.process_table.item(row, 0)
        if item is None:
            return None

        try:
            return int(item.text())
        except ValueError:
            return None

    @Slot()
    def _show_selected_process(self) -> None:
        pid = self._selected_pid()
        analysis = (
            self.analyses_by_pid.get(pid) if pid is not None else None
        )
        self.virustotal_button.setEnabled(
            analysis is not None
            and virustotal_url(analysis.get("sha256")) is not None
        )

        if analysis is None:
            return

        name = str(analysis.get("name") or "Unknown process")
        score = analysis.get("risk_score", 0) or 0
        level = str(analysis.get("risk_level", "low")).upper()
        path = analysis.get("exe_path") or "Unavailable"

        self.selected_process_label.setText(name)
        self.selected_pid_label.setText(
            f"PID {pid}  •  Risk score {score}  •  {level}\n{path}"
        )

        lines = [
            "PROCESS EVIDENCE",
            "=" * 32,
            f"Process: {name}",
            f"PID: {pid}",
            f"Executable path: {path}",
            f"Risk score: {score}",
            f"Risk level: {level}",
            "",
            "FILE IDENTITY",
            "=" * 32,
            "Digital signature: "
            + signature_label(analysis.get("signature_status")),
            f"Signer: {analysis.get('signer') or 'Unavailable'}",
            f"SHA-256: {analysis.get('sha256') or 'Unavailable'}",
            "",
            *self._network_detail_lines(analysis),
            "",
            "RULE FINDINGS",
            "=" * 32,
        ]

        findings = analysis.get("findings", [])
        if findings:
            for finding in findings:
                if isinstance(finding, dict):
                    code = finding.get("code", finding.get("rule_id"))
                    title = finding.get("title", "Finding")
                    description = finding.get(
                        "description", finding.get("explanation", "")
                    )
                    points = finding.get("points", 0)
                    prefix = f"[{code}] " if code else ""
                    lines.append(f"{prefix}{title} (+{points})")
                    if description:
                        lines.append(f"  {description}")
                    lines.append("")
                else:
                    lines.append(f"- {finding}")
        else:
            lines.append("No findings from the current rules.")

        lines.extend([
            "",
            "INTERPRETATION",
            "=" * 32,
            "This score is based on heuristic rules. It is not a probability "
            "that the process is malware.",
            "",
            "For a detailed AI explanation, use the Explain selected process "
            "button or open the Explainable AI Lab.",
            "",
            "SAFETY",
            "=" * 32,
            "ProcessSentinel is read-only. It does not terminate processes "
            "or delete files.",
        ])

        self.details_text.setPlainText("\n".join(lines))

    @staticmethod
    def _network_detail_lines(analysis: dict[str, Any]) -> list[str]:
        lines = ["NETWORK", "=" * 32]
        if "outbound_connection_count" not in analysis:
            lines.append("Network information was not collected.")
            return lines

        ports = analysis.get("listening_ports") or []
        endpoints = analysis.get("remote_endpoints") or []
        lines.append(
            "Outbound connections: "
            f"{analysis.get('outbound_connection_count') or 0}"
        )
        lines.append(
            "Listening ports: "
            + (", ".join(str(port) for port in ports) or "None")
        )
        if endpoints:
            lines.append("Remote endpoints:")
            lines.extend(
                f"  {endpoint}"
                for endpoint in endpoints[:MAX_DETAIL_ENDPOINTS]
            )
            if len(endpoints) > MAX_DETAIL_ENDPOINTS:
                lines.append(
                    f"  ... and {len(endpoints) - MAX_DETAIL_ENDPOINTS} more"
                )
        else:
            lines.append("Remote endpoints: None")
        return lines

    # ------------------------------------------------------------------
    # Network tab
    # ------------------------------------------------------------------

    def _populate_network(self, result: dict[str, Any]) -> None:
        self.network_connections = [
            item for item in result.get("network_connections") or []
            if isinstance(item, dict)
        ]

        notes = list(result.get("network_notes") or [])
        if result.get("network_error"):
            notes.insert(
                0,
                "Network connections could not be listed: "
                f"{result['network_error']}",
            )
        self.network_notes_label.setText(
            "\n".join(notes)
            if notes
            else "Connections open at the time of this scan."
        )

        table = self.network_table
        table.setSortingEnabled(False)
        table.setRowCount(0)

        for connection in self.network_connections:
            row = table.rowCount()
            table.insertRow(row)

            local = connection.get("local_address")
            local_port = connection.get("local_port")
            if local and ":" in local:
                local = f"[{local}]"
            local_text = (
                f"{local}:{local_port}" if local and local_port is not None
                else local or "—"
            )
            remote_port = connection.get("remote_port")

            values = [
                QTableWidgetItem(
                    str(connection.get("process_name") or "Unknown")
                ),
                NumericTableWidgetItem(str(connection.get("pid", ""))),
                QTableWidgetItem(str(connection.get("protocol") or "?")),
                QTableWidgetItem(local_text),
                QTableWidgetItem(
                    str(connection.get("remote_address") or "—")
                ),
                NumericTableWidgetItem(
                    str(remote_port) if remote_port is not None else "—"
                ),
                QTableWidgetItem(str(connection.get("status") or "—")),
            ]
            for column, item in enumerate(values):
                table.setItem(row, column, item)

        table.setSortingEnabled(True)
        self._filter_network()

    def _filter_network(self, *_args) -> None:
        """Re-filter; connected to both textChanged(str) and toggled(bool)."""
        query = self.network_search_input.text().strip().casefold()
        established_only = self.established_only_checkbox.isChecked()
        table = self.network_table
        visible = 0

        for row in range(table.rowCount()):
            cells = [
                table.item(row, column).text()
                if table.item(row, column) is not None
                else ""
                for column in range(table.columnCount())
            ]
            hidden = (
                (query and query not in " ".join(cells).casefold())
                or (established_only and cells[6] != "ESTABLISHED")
            )
            table.setRowHidden(row, bool(hidden))
            if not hidden:
                visible += 1

        total = table.rowCount()
        self.network_count_label.setText(
            f"{visible} of {total} connections"
            if visible != total
            else f"{total} connections"
        )

    @Slot(int, int)
    def _select_process_from_network(self, row: int, _column: int = 0) -> bool:
        """Open the clicked connection's process in Security overview."""
        pid_item = self.network_table.item(row, 1)
        if pid_item is None:
            return False

        for table_row in range(self.process_table.rowCount()):
            item = self.process_table.item(table_row, 0)
            if item is None or item.text() != pid_item.text():
                continue

            if self.process_table.isRowHidden(table_row):
                self.search_input.clear()

            self.process_table.selectRow(table_row)
            self._show_selected_process()
            self.workspace_tabs.setCurrentWidget(self.dashboard_page)
            return True

        self.status_label.setText(
            f"PID {pid_item.text()} is not in the process list; it may "
            "have exited."
        )
        return False

    # ------------------------------------------------------------------
    # Startup tab
    # ------------------------------------------------------------------

    def _get_startup_scanner(self):
        if self.startup_scanner is not None:
            return self.startup_scanner

        from pc_security.scanner.persistence import scan_startup_entries

        return scan_startup_entries

    def _start_startup_scan(self) -> None:
        if self.worker is not None:
            return

        scanner = self._get_startup_scanner()
        include_builtin = self.include_builtin_tasks_checkbox.isChecked()

        self._set_busy(True)
        self.status_label.setText("Scanning startup items...")
        self.startup_notes_label.setText("Scanning startup items...")

        def operation(report_progress):
            return scanner(
                include_builtin_tasks=include_builtin,
                progress_callback=report_progress,
            )

        self.worker = TaskWorker(operation, self)
        self.worker.progress.connect(self._update_startup_progress)
        self.worker.succeeded.connect(self._startup_scan_succeeded)
        self.worker.failed.connect(self._startup_scan_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    @Slot(str)
    def _update_startup_progress(self, message: str) -> None:
        self.status_label.setText(message)
        self.startup_notes_label.setText(message)

    @Slot(object)
    def _startup_scan_succeeded(self, result: dict[str, Any]) -> None:
        self.startup_entries = [
            item for item in (result or {}).get("entries") or []
            if isinstance(item, dict)
        ]
        notes = list((result or {}).get("notes") or [])
        flagged = sum(1 for entry in self.startup_entries if entry.get("flags"))

        summary = (
            f"{len(self.startup_entries)} startup entries, "
            f"{flagged} with flags. Flags are indicators to review, "
            "not proof of malware."
        )
        self.startup_notes_label.setText("\n".join([summary, *notes]))
        self.status_label.setText("Startup scan completed.")

        table = self.startup_table
        table.setSortingEnabled(False)
        table.setRowCount(0)

        for index, entry in enumerate(self.startup_entries):
            row = table.rowCount()
            table.insertRow(row)

            flags = entry.get("flags") or []
            values = [
                QTableWidgetItem(str(entry.get("source") or "")),
                QTableWidgetItem(str(entry.get("name") or "")),
                QTableWidgetItem(str(entry.get("command") or "")),
                QTableWidgetItem(
                    str(entry.get("executable_path") or "Unknown")
                ),
                QTableWidgetItem(
                    signature_label(entry.get("signature_status"))
                ),
                QTableWidgetItem(
                    "; ".join(flag.get("title", "") for flag in flags)
                ),
            ]
            # Keep the entry index so sorting cannot mix up details.
            values[0].setData(Qt.ItemDataRole.UserRole, index)

            for column, item in enumerate(values):
                if flags:
                    item.setBackground(FLAGGED_ROW_BRUSH)
                table.setItem(row, column, item)

        table.setSortingEnabled(True)
        self._filter_startup(self.startup_search_input.text())
        self.startup_details_text.clear()
        if table.rowCount():
            table.selectRow(0)

    @Slot(str)
    def _startup_scan_failed(self, message: str) -> None:
        self.status_label.setText("Startup scan failed.")
        self.startup_notes_label.setText(f"Startup scan failed: {message}")
        QMessageBox.warning(self, "ProcessSentinel", message)

    @Slot(str)
    def _filter_startup(self, query: str) -> None:
        query = query.strip().casefold()
        table = self.startup_table
        for row in range(table.rowCount()):
            text = " ".join(
                table.item(row, column).text()
                if table.item(row, column) is not None
                else ""
                for column in range(table.columnCount())
            ).casefold()
            table.setRowHidden(row, bool(query) and query not in text)

    def _selected_startup_entry(self) -> dict[str, Any] | None:
        row = self.startup_table.currentRow()
        if row < 0:
            return None
        item = self.startup_table.item(row, 0)
        if item is None:
            return None
        index = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(index, int) or not (
            0 <= index < len(self.startup_entries)
        ):
            return None
        return self.startup_entries[index]

    @Slot()
    def _show_selected_startup_entry(self) -> None:
        entry = self._selected_startup_entry()
        if entry is None:
            return

        lines = [
            f"Name: {entry.get('name') or 'Unknown'}",
            f"Source: {entry.get('source') or 'Unknown'}",
            f"Location: {entry.get('location') or 'Unknown'}",
            f"Command: {entry.get('command') or 'None'}",
            f"Executable path: {entry.get('executable_path') or 'Unknown'}",
            "Digital signature: "
            + signature_label(entry.get("signature_status")),
            f"Signer: {entry.get('signer') or 'Unavailable'}",
            "",
            "FLAGS",
            "=" * 32,
        ]

        flags = entry.get("flags") or []
        for flag in flags:
            lines.append(
                f"[{flag.get('code')}] {flag.get('title')} "
                f"(+{flag.get('points', 0)})"
            )
            lines.append(f"  {flag.get('explanation', '')}")
        if not flags:
            lines.append(
                "No flags. This does not prove the entry is safe."
            )

        notes = entry.get("notes") or []
        if notes:
            lines.extend(["", "NOTES", "=" * 32])
            lines.extend(f"- {note}" for note in notes)

        self.startup_details_text.setPlainText("\n".join(lines))

    @Slot()
    def _open_virustotal(self) -> None:
        """Open the selected file's VirusTotal page. Never uploads files."""
        pid = self._selected_pid()
        analysis = self.analyses_by_pid.get(pid) if pid is not None else None
        url = virustotal_url((analysis or {}).get("sha256"))

        if url is None:
            QMessageBox.information(
                self,
                "Hash unavailable",
                "No SHA-256 hash is available for the selected process.",
            )
            return

        QDesktopServices.openUrl(QUrl(url))

    def _explain_selected(self) -> None:
        pid = self._selected_pid()
        if pid is None:
            QMessageBox.information(
                self,
                "Select a process",
                "Select a process before requesting an AI explanation.",
            )
            return

        analysis = self.analyses_by_pid.get(pid)
        if analysis is None:
            return

        factory = (
            self.explanation_service_factory
            if self.explanation_service_factory is not None
            else self._create_explanation_service
        )

        self._set_busy(True)
        self.status_label.setText(
            f"Requesting Groq explanation for PID {pid}..."
        )

        def operation(report_progress):
            report_progress("Preparing selected process evidence...")
            service = factory()
            result = service.explain_process(analysis)
            return {
                "pid": pid,
                "explanation": result.get("explanation", "")
                if isinstance(result, dict)
                else str(result),
            }

        self.worker = TaskWorker(operation, self)
        self.worker.progress.connect(self._update_progress)
        self.worker.succeeded.connect(self._explanation_succeeded)
        self.worker.failed.connect(self._operation_failed)
        self.worker.finished.connect(self._worker_finished)
        self.worker.start()

    def _create_explanation_service(self):
        """Create the Groq-backed explanation service."""
        from pc_security.ai.explanation_service import AIExplanationService
        from pc_security.ai.groq_client import GroqClient

        client = GroqClient(
            model=self.ai_model,
            timeout=self.ai_timeout,
            max_tokens=self.ai_max_tokens,
        )
        return AIExplanationService(client=client)

    @Slot(object)
    def _explanation_succeeded(self, result: dict[str, Any]) -> None:
        pid = result.get("pid")
        explanation = result.get("explanation")

        if pid is not None and explanation:
            pid = int(pid)
            self.ai_explanations[pid] = str(explanation)
            self.ai_errors.pop(pid, None)

        self.explained_value.setText(str(len(self.ai_explanations)))
        self.failures_value.setText(str(len(self.ai_errors)))
        self.status_label.setText("Groq explanation received.")

        if pid is not None and explanation:
            if pid not in self.ai_candidate_pids:
                self.ai_candidate_pids.append(pid)
                analysis = self.analyses_by_pid.get(pid, {})
                row = self.ai_candidate_table.rowCount()
                self.ai_candidate_table.insertRow(row)

                values = [
                    NumericTableWidgetItem(str(pid)),
                    QTableWidgetItem(
                        str(analysis.get("name") or "Unknown")
                    ),
                    NumericTableWidgetItem(
                        str(analysis.get("risk_score", 0) or 0)
                    ),
                    QTableWidgetItem(
                        str(analysis.get("risk_level", "low")).upper()
                    ),
                ]
                for column, item in enumerate(values):
                    self.ai_candidate_table.setItem(row, column, item)

                self.ai_candidate_table.selectRow(row)

            for row in range(self.ai_candidate_table.rowCount()):
                item = self.ai_candidate_table.item(row, 0)
                if item and item.text() == str(pid):
                    self.ai_candidate_table.selectRow(row)
                    break

            self.ai_analysis_text.setPlainText(
                f"AI explanation received for PID {pid}.\n\n"
                "Open the Explainable AI Lab to read the complete report."
            )
            self.workspace_tabs.setCurrentWidget(self.ai_lab_page)
            self._show_ai_candidate_report()

        self._show_selected_process()

    @Slot(str)
    def _operation_failed(self, message: str) -> None:
        self.status_label.setText("The operation failed.")

        pid = self._selected_pid()
        if pid is not None:
            self.ai_errors[pid] = message
            self.failures_value.setText(str(len(self.ai_errors)))
            self._show_selected_process()

            self.ai_analysis_text.setPlainText(
                f"AI request failed for PID {pid}:\n\n{message}"
            )
            self.ai_lab_text.setPlainText(
                f"AI request failed for PID {pid}:\n\n{message}"
            )

        QMessageBox.warning(self, "ProcessSentinel", message)

    @Slot()
    def _worker_finished(self) -> None:
        self._set_busy(False)
        self.worker = None





        