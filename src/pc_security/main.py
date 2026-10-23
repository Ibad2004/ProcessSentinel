
"""Application entry point for ProcessSentinel."""

import sys
from pathlib import Path

from dotenv import load_dotenv
from PySide6.QtWidgets import QApplication, QMessageBox

from pc_security.core.config import load_config
from pc_security.core.scan_service import ProcessScanService
from pc_security.ui.main_window import MainWindow


def get_app_directory() -> Path:
    """Return the directory containing the executable or project."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    # main.py is inside src/pc_security/
    return Path(__file__).resolve().parents[2]


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

    scan_service = ProcessScanService()

    window = MainWindow(
        scan_service=scan_service,
        ai_enabled=ai_config.get("enabled", False),
        ai_model=ai_config.get("model", "openai/gpt-oss-20b"),
        ai_timeout=ai_config.get("timeout", 30),
        ai_max_tokens=ai_config.get("max_tokens", 250),
    )

    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
