"""Load application settings from YAML."""

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path = "config/settings.yaml") -> dict[str, Any]:
    """Load YAML configuration and return it as a dictionary."""
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as file:
        loaded = yaml.safe_load(file) or {}

    if not isinstance(loaded, dict):
        raise ValueError("Configuration must contain a YAML mapping at the root.")

    return loaded
