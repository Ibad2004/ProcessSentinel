
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from pc_security.ui.main_window import MainWindow


_APP = QApplication.instance() or QApplication([])


class FakeScanService:
    def run_scan(self, include_ai=False, progress_callback=None):
        return {
            "scanned_count": 1,
            "analyses": [
                {
                    "pid": 4321,
                    "name": "example.exe",
                    "exe_path": r"C:\Example\example.exe",
                    "risk_score": 25,
                    "risk_level": "medium",
                    "findings": [
                        {
                            "code": "EXECUTABLE_IN_TEMP",
                            "severity": "warning",
                            "title": "Executable running from a temporary folder",
                            "explanation": "The executable is in a temporary folder.",
                            "points": 25,
                        }
                    ],
                }
            ],
            "ai_enabled_for_scan": False,
            "ai_explanations": [],
            "ai_errors": [],
            "ai_skipped_count": 0,
            "ai_candidate_count": 1 if include_ai else 0,
        }


def test_main_window_initializes():
    window = MainWindow(scan_service=FakeScanService())

    assert window.windowTitle().startswith("ProcessSentinel")
    assert window.process_table.columnCount() == 6
    assert window.scan_button.isEnabled()
    assert not window.ai_enabled

    window.close()


def test_scan_result_populates_process_table():
    window = MainWindow(scan_service=FakeScanService())

    result = window.scan_service.run_scan()
    window._scan_succeeded(result)

    assert window.process_table.rowCount() == 1
    assert window.process_table.item(0, 0).text() == "4321"
    assert window.process_table.item(0, 1).text() == "example.exe"
    assert window.process_table.item(0, 2).text() == "25"
    assert window.process_table.item(0, 3).text().lower() == "medium"

    window.close()


def test_selecting_process_shows_rule_findings():
    window = MainWindow(scan_service=FakeScanService())

    window._scan_succeeded(window.scan_service.run_scan())
    window.process_table.selectRow(0)
    window._show_selected_process()

    details = window.details_text.toPlainText()

    assert "EXECUTABLE_IN_TEMP" in details
    assert "temporary folder" in details

    window.close()


SHA = "ab" * 32


class SignedScanService(FakeScanService):
    def run_scan(self, include_ai=False, progress_callback=None):
        result = super().run_scan(include_ai, progress_callback)
        result["analyses"][0].update({
            "signature_status": "valid",
            "signer": "Example Vendor",
            "sha256": SHA,
        })
        return result


def show_first_process(window):
    window._scan_succeeded(window.scan_service.run_scan())
    window.process_table.selectRow(0)
    window._show_selected_process()


def test_signature_column_and_details_are_shown():
    window = MainWindow(scan_service=SignedScanService())
    show_first_process(window)

    assert window.process_table.horizontalHeaderItem(4).text() == "SIGNATURE"
    assert window.process_table.item(0, 4).text() == "Valid"
    assert window.process_table.item(0, 5).text() == r"C:\Example\example.exe"

    details = window.details_text.toPlainText()
    assert "Digital signature: Valid" in details
    assert "Signer: Example Vendor" in details
    assert f"SHA-256: {SHA}" in details

    window.close()


def test_missing_signature_data_is_shown_as_not_checked():
    window = MainWindow(scan_service=FakeScanService())
    show_first_process(window)

    assert window.process_table.item(0, 4).text() == "Not checked"
    assert "SHA-256: Unavailable" in window.details_text.toPlainText()
    assert not window.virustotal_button.isEnabled()

    window.close()


def test_virustotal_button_only_opens_hash_url(monkeypatch):
    import pc_security.ui.main_window as main_window_module

    opened = []
    monkeypatch.setattr(
        main_window_module.QDesktopServices,
        "openUrl",
        staticmethod(lambda url: opened.append(url.toString())),
    )

    window = MainWindow(scan_service=SignedScanService())
    show_first_process(window)

    assert window.virustotal_button.isEnabled()
    window.virustotal_button.click()

    assert opened == [f"https://www.virustotal.com/gui/file/{SHA}"]

    window.close()


def test_virustotal_url_rejects_non_hashes():
    from pc_security.ui.main_window import virustotal_url

    assert virustotal_url(SHA.upper()) == (
        f"https://www.virustotal.com/gui/file/{SHA}"
    )
    assert virustotal_url(None) is None
    assert virustotal_url("abc") is None
    assert virustotal_url("../../upload?x=" + "a" * 50) is None


# ---------------------------------------------------------------------------
# Network tab
# ---------------------------------------------------------------------------

def connection(pid, name, status, remote=None, remote_port=None,
               protocol="TCP", local_port=50000):
    return {
        "pid": pid, "process_name": name, "protocol": protocol,
        "local_address": "10.0.0.2", "local_port": local_port,
        "remote_address": remote, "remote_port": remote_port,
        "status": status,
    }


class NetworkScanService(FakeScanService):
    def run_scan(self, include_ai=False, progress_callback=None):
        result = super().run_scan(include_ai, progress_callback)
        result["analyses"][0].update({
            "outbound_connection_count": 12,
            "remote_endpoints": [f"10.1.1.{i}:443" for i in range(12)],
            "listening_ports": [8080],
        })
        result["analyses"].append({
            "pid": 1111, "name": "other.exe", "exe_path": None,
            "risk_score": 0, "risk_level": "low", "findings": [],
        })
        result["network_connections"] = [
            connection(4321, "example.exe", "ESTABLISHED", "1.1.1.1", 443),
            connection(4321, "example.exe", "LISTEN", local_port=8080),
            connection(1111, "other.exe", None, protocol="UDP"),
        ]
        result["network_notes"] = ["Run as administrator to see more."]
        return result


def visible_rows(table):
    return [row for row in range(table.rowCount()) if not table.isRowHidden(row)]


def test_network_tab_lists_connections():
    window = MainWindow(scan_service=NetworkScanService())
    window._scan_succeeded(window.scan_service.run_scan())

    table = window.network_table
    headers = [table.horizontalHeaderItem(c).text() for c in range(7)]
    assert headers == [
        "PROCESS", "PID", "PROTOCOL", "LOCAL ADDRESS",
        "REMOTE ADDRESS", "REMOTE PORT", "STATE",
    ]
    assert table.rowCount() == 3

    rows = {
        (table.item(r, 0).text(), table.item(r, 6).text()): r
        for r in range(3)
    }
    established_row = rows[("example.exe", "ESTABLISHED")]
    assert table.item(established_row, 3).text() == "10.0.0.2:50000"
    assert table.item(established_row, 4).text() == "1.1.1.1"
    assert table.item(established_row, 5).text() == "443"
    udp_row = rows[("other.exe", "—")]
    assert table.item(udp_row, 2).text() == "UDP"
    assert table.item(udp_row, 4).text() == "—"
    assert "administrator" in window.network_notes_label.text()

    window.close()


def test_network_filters():
    window = MainWindow(scan_service=NetworkScanService())
    window._scan_succeeded(window.scan_service.run_scan())

    window.established_only_checkbox.setChecked(True)
    assert len(visible_rows(window.network_table)) == 1
    assert window.network_count_label.text() == "1 of 3 connections"

    window.established_only_checkbox.setChecked(False)
    window.network_search_input.setText("other")
    assert len(visible_rows(window.network_table)) == 1

    window.network_search_input.clear()
    assert window.network_count_label.text() == "3 connections"

    window.close()


def test_clicking_connection_selects_process_on_main_tab():
    window = MainWindow(scan_service=NetworkScanService())
    window._scan_succeeded(window.scan_service.run_scan())
    window.search_input.setText("example")  # hides other.exe

    row = next(
        r for r in range(window.network_table.rowCount())
        if window.network_table.item(r, 0).text() == "other.exe"
    )

    assert window._select_process_from_network(row, 0)
    assert window._selected_pid() == 1111
    assert window.workspace_tabs.currentWidget() is window.dashboard_page

    window.close()


def test_clicking_connection_for_exited_process_reports_it():
    window = MainWindow(scan_service=NetworkScanService())
    result = window.scan_service.run_scan()
    result["network_connections"].append(
        connection(9999, None, "ESTABLISHED", "2.2.2.2", 80)
    )
    window._scan_succeeded(result)

    row = next(
        r for r in range(window.network_table.rowCount())
        if window.network_table.item(r, 1).text() == "9999"
    )

    assert not window._select_process_from_network(row, 0)
    assert "9999" in window.status_label.text()

    window.close()


def test_network_error_is_shown():
    window = MainWindow(scan_service=FakeScanService())
    result = window.scan_service.run_scan()
    result["network_error"] = "Access denied"
    window._scan_succeeded(result)

    assert "Access denied" in window.network_notes_label.text()
    assert window.network_table.rowCount() == 0

    window.close()


def test_process_details_show_network_section():
    window = MainWindow(scan_service=NetworkScanService())
    show_first_process(window)

    details = window.details_text.toPlainText()
    assert "NETWORK" in details
    assert "Outbound connections: 12" in details
    assert "Listening ports: 8080" in details
    assert "10.1.1.9:443" in details
    assert "10.1.1.10:443" not in details  # only the first 10
    assert "... and 2 more" in details

    window.close()


def test_process_details_without_network_data():
    window = MainWindow(scan_service=FakeScanService())
    show_first_process(window)

    assert "Network information was not collected." in (
        window.details_text.toPlainText()
    )

    window.close()


# ---------------------------------------------------------------------------
# Startup tab
# ---------------------------------------------------------------------------

def startup_result():
    flag = {
        "code": "STARTUP_UNSIGNED", "severity": "info",
        "title": "Startup program is not signed",
        "explanation": "No digital signature.", "points": 10,
    }
    return {
        "entries": [
            {
                "source": "Registry Run", "location": r"HKCU\...\Run",
                "name": "Good", "command": r'"C:\Good\good.exe"',
                "executable_path": r"C:\Good\good.exe",
                "signature_status": "valid", "signer": "Vendor Ltd",
                "flags": [], "notes": [],
            },
            {
                "source": "Scheduled task", "location": r"\Tool",
                "name": "Tool", "command": r"C:\Tool\tool.exe /x",
                "executable_path": r"C:\Tool\tool.exe",
                "signature_status": "unsigned", "signer": None,
                "flags": [flag], "notes": ["A note."],
            },
        ],
        "notes": ["Listing scheduled tasks timed out."],
    }


def startup_row(window, name):
    return next(
        r for r in range(window.startup_table.rowCount())
        if window.startup_table.item(r, 1).text() == name
    )


def test_startup_tab_is_not_scanned_by_process_scan():
    calls = []
    window = MainWindow(
        scan_service=FakeScanService(),
        startup_scanner=lambda **kwargs: calls.append(kwargs),
    )
    window._scan_succeeded(window.scan_service.run_scan())

    assert calls == []
    assert window.startup_table.rowCount() == 0

    window.close()


def test_startup_scan_runs_in_worker_thread():
    calls = []

    def fake_startup_scanner(include_builtin_tasks, progress_callback):
        calls.append(include_builtin_tasks)
        progress_callback("Reading registry Run keys...")
        return startup_result()

    window = MainWindow(
        scan_service=FakeScanService(), startup_scanner=fake_startup_scanner,
    )
    window.include_builtin_tasks_checkbox.setChecked(True)

    window._start_startup_scan()
    worker = window.worker
    assert worker is not None
    assert not window.startup_scan_button.isEnabled()
    assert worker.wait(5000)
    _APP.processEvents()

    assert calls == [True]
    assert window.startup_table.rowCount() == 2
    assert window.worker is None
    assert window.startup_scan_button.isEnabled()

    window.close()


def test_startup_table_flags_highlight_and_details():
    window = MainWindow(scan_service=FakeScanService())
    window._startup_scan_succeeded(startup_result())

    table = window.startup_table
    headers = [table.horizontalHeaderItem(c).text() for c in range(6)]
    assert headers == [
        "SOURCE", "NAME", "COMMAND", "EXECUTABLE PATH", "SIGNATURE", "FLAGS",
    ]

    tool = startup_row(window, "Tool")
    good = startup_row(window, "Good")
    assert table.item(tool, 4).text() == "Unsigned"
    assert table.item(tool, 5).text() == "Startup program is not signed"
    assert table.item(tool, 0).background().color().alpha() > 0
    assert table.item(good, 0).background().style() == Qt.BrushStyle.NoBrush
    assert "1 with flags" in window.startup_notes_label.text()
    assert "timed out" in window.startup_notes_label.text()

    table.selectRow(tool)
    details = window.startup_details_text.toPlainText()
    assert "Command: C:\\Tool\\tool.exe /x" in details
    assert "[STARTUP_UNSIGNED]" in details
    assert "A note." in details

    window.close()


def test_startup_search_filter():
    window = MainWindow(scan_service=FakeScanService())
    window._startup_scan_succeeded(startup_result())

    window.startup_search_input.setText("not signed")

    visible = visible_rows(window.startup_table)
    assert [window.startup_table.item(r, 1).text() for r in visible] == ["Tool"]

    window.close()


def test_startup_scan_failure_is_reported(monkeypatch):
    import pc_security.ui.main_window as main_window_module

    warnings = []
    monkeypatch.setattr(
        main_window_module.QMessageBox, "warning",
        staticmethod(lambda *args: warnings.append(args)),
    )
    window = MainWindow(scan_service=FakeScanService())

    window._startup_scan_failed("schtasks failed")

    assert "schtasks failed" in window.startup_notes_label.text()
    assert len(warnings) == 1

    window.close()


# ---------------------------------------------------------------------------
# Step 3: history, tree view, admin banner, export, AI settings
# ---------------------------------------------------------------------------

import pytest

import pc_security.ui.main_window as main_window_module
from pc_security.core.history import ScanHistory


@pytest.fixture(autouse=True)
def no_real_admin_check(monkeypatch):
    monkeypatch.setattr(main_window_module, "is_running_as_admin", lambda: True)


def family_analyses():
    def item(pid, parent, name, score=0, level="low", new=False):
        return {
            "pid": pid, "parent_pid": parent, "name": name,
            "exe_path": rf"C:\Users\alice\{name}", "risk_score": score,
            "risk_level": level, "findings": [],
            "is_new_since_last_scan": new,
        }

    return [
        item(100, 4, "explorer.exe"),
        item(200, 100, "child.exe", 35, "medium", new=True),
        item(300, 100, "other.exe"),
    ]


class FamilyScanService:
    def __init__(self, history=None):
        self.history = history

    def run_scan(self, include_ai=False, progress_callback=None):
        return {
            "scanned_count": 3,
            "analyses": family_analyses(),
            "ai_enabled_for_scan": False,
            "ai_explanations": [],
            "ai_errors": [],
        }


def scanned_window(**kwargs):
    window = MainWindow(scan_service=kwargs.pop("service", FamilyScanService()),
                        **kwargs)
    window._scan_succeeded(window.scan_service.run_scan())
    return window


def table_pids(window, visible_only=True):
    return [
        int(window.process_table.item(r, 0).text())
        for r in range(window.process_table.rowCount())
        if not (visible_only and window.process_table.isRowHidden(r))
    ]


# --- Admin banner -----------------------------------------------------------

@pytest.mark.parametrize(
    "admin, visible", [(False, True), (True, False), (None, False)],
)
def test_admin_banner_visibility(admin, visible):
    window = MainWindow(scan_service=FakeScanService(),
                        admin_check=lambda: admin)

    assert window.admin_banner.isHidden() is not visible
    assert "without administrator rights" in (
        window.admin_banner.message_label.text()
    )
    window.close()


def test_admin_banner_can_be_dismissed():
    window = MainWindow(scan_service=FakeScanService(),
                        admin_check=lambda: False)

    window.admin_banner.dismiss_button.click()

    assert window.admin_banner.isHidden()
    window.close()


def test_admin_check_failure_is_unknown():
    def broken():
        raise OSError("no shell32")

    window = MainWindow(scan_service=FakeScanService(), admin_check=broken)

    assert window.is_admin is None
    assert window.admin_banner.isHidden()
    window.close()


# --- New highlighting and Show only new -------------------------------------

def test_new_processes_are_highlighted_and_filterable():
    window = scanned_window()

    row = table_pids(window).index(200)
    name_item = window.process_table.item(row, 1)
    assert name_item.text() == "child.exe"
    assert name_item.font().bold()
    assert name_item.background().style() != Qt.BrushStyle.NoBrush
    assert "New since the last saved scan" in name_item.toolTip()

    window.only_new_checkbox.setChecked(True)
    assert table_pids(window) == [200]
    assert window.result_count.text() == "1 of 3 processes"
    assert not window.process_tree.item_for_pid(200).isHidden()
    assert window.process_tree.item_for_pid(300).isHidden()

    window.only_new_checkbox.setChecked(False)
    assert sorted(table_pids(window)) == [100, 200, 300]
    window.close()


def test_details_show_new_since_last_scan():
    window = scanned_window()

    window._select_pid(200)

    assert "New since last scan: Yes" in window.details_text.toPlainText()
    window.close()


# --- Tree view ------------------------------------------------------------------

def test_tree_toggle_keeps_selection_and_updates_details():
    window = scanned_window()
    window._select_pid(300)

    window.tree_view_button.setChecked(True)

    assert window.process_view_stack.currentWidget() is window.process_tree
    assert window.tree_view_button.text().endswith("Table view")
    assert window._selected_pid() == 300

    root = window.process_tree.topLevelItem(0)
    assert root.text(0) == "explorer.exe"
    assert root.childCount() == 2

    window.process_tree.select_pid(200)
    assert window.selected_process_label.text() == "child.exe"

    window.tree_view_button.setChecked(False)
    assert window.process_view_stack.currentWidget() is window.process_table
    assert window._selected_pid() == 200
    window.close()


def test_tree_follows_search_filter():
    window = scanned_window()
    window.tree_view_button.setChecked(True)

    window.search_input.setText("other")

    assert window.process_tree.item_for_pid(200).isHidden()
    assert not window.process_tree.item_for_pid(300).isHidden()
    assert not window.process_tree.item_for_pid(100).isHidden()  # parent
    window.close()


# --- History tab --------------------------------------------------------------

def test_history_tab_lists_scans_compare_and_clear(tmp_path, monkeypatch):
    history = ScanHistory(tmp_path / "history.db")
    history.record_scan(
        [{"pid": 1, "name": "gone.exe", "exe_path": r"C:\gone.exe",
          "risk_level": "low", "risk_score": 0, "findings": []}],
        scanned_at="2026-11-02T08:00:00",
    )
    history.record_scan(family_analyses(), scanned_at="2026-11-03T09:00:00")

    window = scanned_window(service=FamilyScanService(history))
    tab = window.history_tab

    assert window.workspace_tabs.indexOf(tab) >= 0
    assert tab.scan_table.rowCount() == 2
    assert tab.scan_table.item(0, 0).text() == "2026-11-03  09:00:00"
    assert tab.scan_table.item(0, 2).text() == "1"  # medium

    assert tab.process_table.rowCount() == 3
    tab.process_search_input.setText("child")
    visible = [r for r in range(3) if not tab.process_table.isRowHidden(r)]
    assert [tab.process_table.item(r, 1).text() for r in visible] == ["child.exe"]

    changes = {
        (tab.compare_table.item(r, 0).text(), tab.compare_table.item(r, 1).text())
        for r in range(tab.compare_table.rowCount())
    }
    assert ("Disappeared", "gone.exe") in changes
    assert ("Appeared", "explorer.exe") in changes

    answers = []

    def answer(choice):
        def question(*args, **kwargs):
            answers.append(args[1])
            return choice
        return staticmethod(question)

    from PySide6.QtWidgets import QMessageBox
    import pc_security.ui.history_tab as history_tab_module

    monkeypatch.setattr(history_tab_module.QMessageBox, "question",
                        answer(QMessageBox.StandardButton.No))
    tab.clear_button.click()
    assert len(history.list_scans()) == 2

    monkeypatch.setattr(history_tab_module.QMessageBox, "question",
                        answer(QMessageBox.StandardButton.Yes))
    tab.clear_button.click()
    assert history.list_scans() == []
    assert tab.scan_table.rowCount() == 0
    assert answers == ["Clear scan history", "Clear scan history"]
    window.close()


def test_history_tab_without_history():
    window = MainWindow(scan_service=FakeScanService())

    assert "turned off" in window.history_tab.status_label.text()
    assert not window.history_tab.clear_button.isEnabled()
    window.close()


def test_broken_history_database_shows_message(tmp_path):
    bad = tmp_path / "history.db"
    bad.write_bytes(b"not a database" * 50)

    window = MainWindow(scan_service=FamilyScanService(ScanHistory(bad)))

    assert "unavailable" in window.history_tab.status_label.text()
    window.close()


def test_history_error_is_a_non_blocking_warning():
    window = MainWindow(scan_service=FakeScanService())
    result = window.scan_service.run_scan()
    result["history_error"] = "database is locked"

    window._scan_succeeded(result)

    assert "Scan completed" in window.status_label.text()
    assert "database is locked" in window.status_label.text()
    window.close()


# --- Export -----------------------------------------------------------------------

def test_export_disabled_until_scan():
    window = MainWindow(scan_service=FamilyScanService())

    assert not window.export_button.isEnabled()
    window._scan_succeeded(window.scan_service.run_scan())
    assert window.export_button.isEnabled()
    window.close()


def test_export_writes_masked_html(tmp_path, monkeypatch):
    target = tmp_path / "report.html"
    monkeypatch.setattr(
        main_window_module.QFileDialog, "getSaveFileName",
        staticmethod(lambda *args, **kwargs: (str(target), "HTML files (*.html)")),
    )
    window = scanned_window(admin_check=lambda: False)
    window.ai_explanations = {200: "Explanation for child."}

    window.export_button.click()

    html = target.read_text(encoding="utf-8")
    assert "child.exe" in html
    assert r"C:\Users\&lt;user&gt;\child.exe" in html
    assert "Explanation for child." in html
    assert "<script" not in html.lower()
    assert "Report saved" in window.status_label.text()
    window.close()


def test_export_cancelled_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        main_window_module.QFileDialog, "getSaveFileName",
        staticmethod(lambda *args, **kwargs: ("", "")),
    )
    window = scanned_window()

    window.export_button.click()

    assert list(tmp_path.iterdir()) == []
    window.close()


# --- AI settings ----------------------------------------------------------------

def test_ai_settings_dialog_applies_model_without_restart(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text('ai:\n  model: "openai/gpt-oss-20b"\n', encoding="utf-8")
    ai_config = {"model": "openai/gpt-oss-20b"}

    window = MainWindow(
        scan_service=FakeScanService(),
        ai_config=ai_config,
        env_path=tmp_path / ".env",
        config_path=config,
    )
    dialog = window._create_settings_dialog()
    assert dialog.env_path == tmp_path / ".env"

    dialog.model_combo.setCurrentText("openai/gpt-oss-120b")
    dialog._save()

    assert ai_config["model"] == "openai/gpt-oss-120b"
    assert window.ai_model == "openai/gpt-oss-120b"
    assert window.footer_ai_label.text() == "AI model: openai/gpt-oss-120b"
    assert "next AI request" in window.status_label.text()
    window.close()


def test_network_click_selects_process_in_tree_view():
    window = MainWindow(scan_service=NetworkScanService())
    window._scan_succeeded(window.scan_service.run_scan())
    window.tree_view_button.setChecked(True)

    row = next(
        r for r in range(window.network_table.rowCount())
        if window.network_table.item(r, 0).text() == "other.exe"
    )

    assert window._select_process_from_network(row, 0)
    assert window._selected_pid() == 1111
    window.close()


# ---------------------------------------------------------------------------
# Step 4: no-indicators mode and AI privacy notice
# ---------------------------------------------------------------------------

NO_INDICATORS = (
    "No indicators found by the current rules. Select a process and click "
    "Explain to ask the AI about it."
)


def test_no_indicators_message_and_manual_explain_still_works():
    explained = []

    class FakeService:
        def explain_process(self, analysis):
            explained.append(analysis["pid"])
            return {"pid": analysis["pid"], "explanation": "Manual report."}

    window = MainWindow(
        scan_service=FakeScanService(),
        explanation_service_factory=FakeService,
    )
    result = window.scan_service.run_scan(include_ai=True)
    result.update({
        "ai_enabled_for_scan": True,
        "ai_selection_mode": "no_indicators",
        "ai_candidate_pids": [],
    })

    window._scan_succeeded(result)

    assert window.ai_lab_mode_label.text() == NO_INDICATORS
    assert NO_INDICATORS in window.ai_analysis_text.toPlainText()
    assert window.ai_candidate_table.rowCount() == 0

    window.process_table.selectRow(0)
    window._explain_selected()
    assert window.worker.wait(5000)
    _APP.processEvents()

    assert explained == [4321]
    assert "Manual report." in window.ai_lab_text.toPlainText()
    window.close()


def test_ai_privacy_notice_is_shown():
    window = MainWindow(scan_service=FakeScanService())

    notice = window.ai_privacy_label.text()
    assert "Groq" in notice
    assert "<user>" in notice
    assert "never sent" in notice
    assert "user name masked" in window.ai_privacy_hint.text()
    window.close()
