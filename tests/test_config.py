from pathlib import Path

from pc_security.core.config import load_config


def test_load_default_config() -> None:
    project_root = Path(__file__).resolve().parents[1]
    config = load_config(project_root / "config" / "settings.yaml")

    assert config["app"]["name"] == "PC Security Assistant"
    assert config["security"]["read_only"] is True
    assert config["security"]["allow_process_termination"] is False
