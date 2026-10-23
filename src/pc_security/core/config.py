
"""Load application settings from YAML."""

import sys
from pathlib import Path
from typing import Any

import yaml


def get_config_path(path: str | Path | None = None) -> Path:
    """Locate configuration in development and PyInstaller builds."""

    if path is not None:
        config_path = Path(path)
        if config_path.is_absolute():
            return config_path

    else:
        config_path = Path("config/settings.yaml")

    if getattr(sys, "frozen", False):
        # External configuration beside the executable.
        executable_dir = Path(sys.executable).resolve().parent
        external_path = executable_dir / config_path

        if external_path.is_file():
            return external_path

        # Configuration bundled inside the PyInstaller package.
        bundle_dir = Path(
            getattr(sys, "_MEIPASS", executable_dir)
        )
        bundled_path = bundle_dir / config_path

        if bundled_path.is_file():
            return bundled_path

        return external_path

    # Development mode: project root is three levels above this file.
    project_root = Path(__file__).resolve().parents[3]
    return project_root / config_path


def load_config(
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Load YAML configuration and return a dictionary."""

    config_path = get_config_path(path)

    if not config_path.is_file():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as file:
        loaded = yaml.safe_load(file) or {}

    if not isinstance(loaded, dict):
        raise ValueError(
            "Configuration must contain a YAML mapping at the root."
        )

    return loaded
