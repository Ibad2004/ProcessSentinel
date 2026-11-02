
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
