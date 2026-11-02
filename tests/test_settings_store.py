
import logging
from types import SimpleNamespace

import pytest
import yaml

import pc_security.core.settings_store as store
from pc_security.core.settings_store import (
    SettingsError,
    mask_secret,
    save_ai_model,
    save_env_value,
    validate_api_key,
)


SECRET = "gsk_test1234567890abcdWXYZ"


def test_env_value_is_added_and_other_lines_kept(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# my settings\nOTHER=1\n\nexport PROXY=http://proxy\n",
        encoding="utf-8",
    )

    save_env_value(env, "GROQ_API_KEY", SECRET)

    assert env.read_text(encoding="utf-8") == (
        "# my settings\nOTHER=1\n\nexport PROXY=http://proxy\n"
        f"GROQ_API_KEY={SECRET}\n"
    )


def test_env_value_replaces_existing_and_duplicates(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes(
        b"A=1\r\nGROQ_API_KEY=old\r\nB=2\r\nexport GROQ_API_KEY=older\r\n"
    )

    save_env_value(env, "GROQ_API_KEY", SECRET)

    assert env.read_bytes() == (
        f"A=1\r\nGROQ_API_KEY={SECRET}\r\nB=2\r\n".encode()
    )


def test_env_file_created_when_missing(tmp_path):
    env = tmp_path / "new" / ".env"

    save_env_value(env, "GROQ_API_KEY", SECRET)

    assert env.read_text(encoding="utf-8") == f"GROQ_API_KEY={SECRET}\n"
    assert list(env.parent.iterdir()) == [env]  # no temp files left


def test_key_is_never_logged_or_printed(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)

    save_env_value(tmp_path / ".env", "GROQ_API_KEY", SECRET)
    with pytest.raises(SettingsError) as error:
        validate_api_key(SECRET + " with spaces")

    captured = capsys.readouterr()
    assert SECRET not in caplog.text
    assert SECRET not in captured.out + captured.err
    assert SECRET not in str(error.value)


def test_unwritable_env_reports_error_without_key(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")

    with pytest.raises(SettingsError) as error:
        save_env_value(blocker / ".env", "GROQ_API_KEY", SECRET)

    assert SECRET not in str(error.value)


@pytest.mark.parametrize(
    "value, expected",
    [(SECRET, "••••WXYZ"), ("abc", "••••"), (None, "Not set"), ("", "Not set")],
)
def test_mask_secret(value, expected):
    assert mask_secret(value) == expected


@pytest.mark.parametrize(
    "key", ["", "short", "has space 12345", 'quote"12345678', "new\nline12345"],
)
def test_invalid_keys_are_rejected(key):
    with pytest.raises(SettingsError):
        validate_api_key(key)


SETTINGS = """app:
  name: "ProcessSentinel"

# AI settings
ai:
  provider: "groq"
  enabled: true
  model: "openai/gpt-oss-20b"   # default model
  timeout: 30

history:
  max_scans: 50
"""


def test_model_saved_keeping_comments_and_other_settings(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text(SETTINGS, encoding="utf-8")

    save_ai_model(config, "llama-3.3-70b-versatile")

    text = config.read_text(encoding="utf-8")
    assert text == SETTINGS.replace(
        'model: "openai/gpt-oss-20b"   # default model',
        'model: "llama-3.3-70b-versatile"   # default model',
    )
    loaded = yaml.safe_load(text)
    assert loaded["ai"]["model"] == "llama-3.3-70b-versatile"
    assert loaded["history"]["max_scans"] == 50


def test_model_added_when_missing(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text("ai:\n  timeout: 30\nother:\n  model: keep\n",
                      encoding="utf-8")

    save_ai_model(config, "openai/gpt-oss-120b")

    loaded = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert loaded["ai"] == {"model": "openai/gpt-oss-120b", "timeout": 30}
    assert loaded["other"]["model"] == "keep"


def test_model_copied_from_source_when_target_missing(tmp_path):
    source = tmp_path / "bundled.yaml"
    source.write_text(SETTINGS, encoding="utf-8")
    target = tmp_path / "beside_exe" / "config" / "settings.yaml"

    save_ai_model(target, "openai/gpt-oss-120b", source_path=source)

    loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert loaded["ai"]["model"] == "openai/gpt-oss-120b"
    assert source.read_text(encoding="utf-8") == SETTINGS


@pytest.mark.parametrize("model", ["", "bad model", "x\ny", "a" * 200])
def test_invalid_model_rejected_and_file_unchanged(tmp_path, model):
    config = tmp_path / "settings.yaml"
    config.write_text(SETTINGS, encoding="utf-8")

    with pytest.raises(SettingsError):
        save_ai_model(config, model)

    assert config.read_text(encoding="utf-8") == SETTINGS


def test_frozen_build_writes_beside_exe(tmp_path, monkeypatch):
    bundle = tmp_path / "_MEI123"
    bundled = bundle / "config" / "settings.yaml"
    bundled.parent.mkdir(parents=True)
    bundled.write_text(SETTINGS, encoding="utf-8")
    exe = tmp_path / "dist" / "ProcessSentinel.exe"

    monkeypatch.setattr(store, "get_config_path", lambda: bundled)
    monkeypatch.setattr(store, "sys", SimpleNamespace(
        frozen=True, _MEIPASS=str(bundle), executable=str(exe),
    ))

    assert store.get_writable_config_path() == (
        exe.resolve().parent / "config" / "settings.yaml"
    )


def test_external_frozen_config_is_used_directly(tmp_path, monkeypatch):
    external = tmp_path / "dist" / "config" / "settings.yaml"
    monkeypatch.setattr(store, "get_config_path", lambda: external)
    monkeypatch.setattr(store, "sys", SimpleNamespace(
        frozen=True, _MEIPASS=str(tmp_path / "_MEI1"),
        executable=str(tmp_path / "dist" / "ProcessSentinel.exe"),
    ))

    assert store.get_writable_config_path() == external


def test_dev_mode_uses_config_path(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "get_config_path", lambda: tmp_path / "s.yaml")
    monkeypatch.setattr(store, "sys", SimpleNamespace())

    assert store.get_writable_config_path() == tmp_path / "s.yaml"


def test_model_save_keeps_crlf_line_endings(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_bytes(SETTINGS.replace("\n", "\r\n").encode("utf-8"))

    save_ai_model(config, "openai/gpt-oss-120b")

    data = config.read_bytes()
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")
