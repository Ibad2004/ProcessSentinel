
"""Application entry point for ProcessSentinel."""

import sys

from dotenv import load_dotenv
from PySide6.QtWidgets import QApplication, QMessageBox

from pc_security.core.config import load_config
from pc_security.core.history import DEFAULT_MAX_SCANS, ScanHistory
from pc_security.core.paths import get_app_directory, get_history_path
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


def main() -> int:
    app_directory = get_app_directory()

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
