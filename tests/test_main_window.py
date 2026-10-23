
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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
    assert window.process_table.columnCount() == 5
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
