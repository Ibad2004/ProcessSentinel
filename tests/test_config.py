
from pathlib import Path

from pc_security.core.config import load_config


def test_load_default_config() -> None:
    project_root = Path(__file__).resolve().parents[1]
    config = load_config(project_root / "config" / "settings.yaml")

    assert config["app"]["name"] == "ProcessSentinel"
    assert config["app"]["environment"] == "development"
    assert config["security"]["read_only"] is True
    assert config["security"]["allow_process_termination"] is False

    assert config["ai"]["provider"] == "groq"
    assert config["ai"]["enabled"] is True
    assert config["ai"]["model"] == "openai/gpt-oss-20b"
    assert config["ai"]["timeout"] == 30
    assert config["ai"]["max_tokens"] == 250
