
"""Application entry point for ProcessSentinel."""

import importlib
import sys

from dotenv import load_dotenv
from PySide6.QtWidgets import QApplication, QMessageBox

from pc_security.core.config import load_config
from pc_security.core.history import DEFAULT_MAX_SCANS, ScanHistory
from pc_security.core.paths import (
    ensure_runtime_directories,
    get_app_directory,
    get_history_path,
)
from pc_security.core.scan_service import ProcessScanService
from pc_security.ui.main_window import MainWindow


def build_explanation_service_factory(ai_config):
    """Return a factory that creates AI services using configured limits.

    A new client is created per request so a key saved from the AI
    settings dialog is picked up without restarting the application.
    """

    def factory():
        from pc_security.ai.explanation_service import AIExplanationService
        from pc_security.ai.groq_client import GroqClient

        client = GroqClient(
            model=ai_config.get("model", "openai/gpt-oss-20b"),
            timeout=ai_config.get("timeout", 30),
            max_tokens=ai_config.get("max_tokens", 2000),
        )
        return AIExplanationService(client=client)

    return factory


def build_scan_history(history_config):
    """Create the scan history store (the database opens lazily)."""
    max_scans = (history_config or {}).get("max_scans", DEFAULT_MAX_SCANS)
    try:
        return ScanHistory(get_history_path(), max_scans=max_scans)
    except ValueError:
        return ScanHistory(get_history_path())


SELF_TEST_MODULES = (
    "pc_security.ai.explanation_service",
    "pc_security.ai.groq_client",
    "pc_security.core.config",
    "pc_security.core.history",
    "pc_security.core.platform_info",
    "pc_security.core.privacy",
    "pc_security.core.scan_service",
    "pc_security.core.settings_store",
    "pc_security.scanner.file_inspector",
    "pc_security.scanner.network_scanner",
    "pc_security.scanner.persistence",
    "pc_security.scanner.process_scanner",
    "pc_security.security.analyzer",
    "pc_security.ui.history_tab",
    "pc_security.ui.main_window",
    "pc_security.ui.process_tree",
    "pc_security.ui.report_export",
    "pc_security.ui.settings_dialog",
)


def _say(message):
    # A windowed PyInstaller build has no console (sys.stdout is None).
    if sys.stdout is not None:
        print(message)


def run_self_test() -> int:
    """Check a build without opening a window or scanning anything.

    Imports every module, loads the configuration, and creates data/ and
    logs/ beside the app. Returns 0 on success, 1 on failure.
    """
    try:
        for name in SELF_TEST_MODULES:
            importlib.import_module(name)
        load_config()
        failed = ensure_runtime_directories(get_app_directory())
    except Exception as exc:
        _say(f"ProcessSentinel self-test FAILED: {exc}")
        return 1

    if failed:
        _say(f"ProcessSentinel self-test FAILED: cannot create {failed}")
        return 1

    _say("ProcessSentinel self-test OK")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return run_self_test()

    app_directory = get_app_directory()
    # data/ and logs/ beside the app; failure is not fatal (history then
    # reports a non-blocking warning).
    ensure_runtime_directories(app_directory)

    # Load .env from the application directory.
    env_file = app_directory / ".env"
    load_dotenv(dotenv_path=env_file)

    try:
        config = load_config()
    except (OSError, ValueError) as exc:
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Configuration Error",
            f"Could not load application configuration:\n\n{exc}",
        )
        return 1

    app_config = config.get("app", {})
    ai_config = config.get("ai", {})

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    app.setApplicationName(
        app_config.get("name", "ProcessSentinel")
    )
    app.setStyle("Fusion")

    explanation_service_factory = build_explanation_service_factory(
        ai_config
    )

    scan_service = ProcessScanService(
        explanation_service_factory=explanation_service_factory,
        history=build_scan_history(config.get("history")),
    )

    window = MainWindow(
        scan_service=scan_service,
        ai_enabled=ai_config.get("enabled", False),
        ai_model=ai_config.get("model", "openai/gpt-oss-20b"),
        ai_timeout=ai_config.get("timeout", 30),
        ai_max_tokens=ai_config.get("max_tokens", 2000),
        explanation_service_factory=explanation_service_factory,
        ai_config=ai_config,
    )

    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
