
"""Locate application files in development and PyInstaller builds."""

import sys
from pathlib import Path


def get_app_directory() -> Path:
    """Return the directory containing the executable or project."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    # This file is inside src/pc_security/core/.
    return Path(__file__).resolve().parents[3]


def get_env_path() -> Path:
    """Return the .env file loaded at startup."""
    return get_app_directory() / ".env"


def get_history_path() -> Path:
    """Return the SQLite scan history location (data/ beside the app)."""
    return get_app_directory() / "data" / "history.db"
