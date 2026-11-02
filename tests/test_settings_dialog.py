
import pytest
from PySide6.QtWidgets import QApplication

from pc_security.ui.settings_dialog import AISettingsDialog


_APP = QApplication.instance() or QApplication([])

SECRET = "gsk_dialogkey1234567890WXYZ"
SETTINGS = 'ai:\n  model: "openai/gpt-oss-20b"\n  timeout: 30\n'


class FakeClient:
    def __init__(self, error=None):
        self.error = error
        self.checked = False

    def check_connection(self):
        self.checked = True
        if self.error is not None:
            raise self.error
        return True


@pytest.fixture
def paths(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("KEEP=me\n", encoding="utf-8")
    config = tmp_path / "settings.yaml"
    config.write_text(SETTINGS, encoding="utf-8")
    return env, config


def make_dialog(paths, client=None):
    calls = []

    def factory(key, model, timeout):
        calls.append((key, model, timeout))
        return client or FakeClient()

    env, config = paths
    dialog = AISettingsDialog(
        env_path=env, config_path=config,
        current_model="openai/gpt-oss-20b", timeout=12,
        client_factory=factory,
    )
    return dialog, calls


def run_worker(dialog):
    worker = dialog.worker
    assert worker is not None
    assert worker.wait(5000)
    _APP.processEvents()


def test_shows_only_masked_key(paths, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", SECRET)
    dialog, _ = make_dialog(paths)

    assert dialog.current_key_label.text() == "••••WXYZ"
    assert SECRET not in dialog.current_key_label.text()
    assert dialog.model_combo.currentText() == "openai/gpt-oss-20b"
    assert dialog.model_combo.isEditable()


def test_save_writes_key_and_model_and_emits(paths, monkeypatch):
    env, config = paths
    dialog, _ = make_dialog(paths)
    saved = []
    dialog.settings_saved.connect(saved.append)

    dialog.key_input.setText(SECRET)
    dialog.model_combo.setCurrentText("llama-3.3-70b-versatile")
    dialog._save()

    assert env.read_text(encoding="utf-8") == f"KEEP=me\nGROQ_API_KEY={SECRET}\n"
    assert 'model: "llama-3.3-70b-versatile"' in config.read_text(encoding="utf-8")
    assert saved == ["llama-3.3-70b-versatile"]
    import os
    assert os.environ["GROQ_API_KEY"] == SECRET
    assert dialog.key_input.text() == ""
    assert dialog.current_key_label.text() == "••••WXYZ"


def test_empty_key_keeps_existing_key(paths):
    env, config = paths
    dialog, _ = make_dialog(paths)

    dialog._save()

    assert env.read_text(encoding="utf-8") == "KEEP=me\n"
    assert config.read_text(encoding="utf-8") == SETTINGS  # model unchanged


def test_invalid_key_is_not_saved(paths):
    env, _ = paths
    dialog, _ = make_dialog(paths)
    saved = []
    dialog.settings_saved.connect(saved.append)

    dialog.key_input.setText("bad key with spaces")
    dialog._save()

    assert env.read_text(encoding="utf-8") == "KEEP=me\n"
    assert saved == []
    assert "bad key" not in dialog.status_label.text()


def test_connection_test_runs_in_worker(paths):
    client = FakeClient()
    dialog, calls = make_dialog(paths, client)
    dialog.key_input.setText(SECRET)

    dialog._start_connection_test()
    assert not dialog.test_button.isEnabled()
    run_worker(dialog)

    assert calls == [(SECRET, "openai/gpt-oss-20b", 12)]
    assert client.checked
    assert "Connected" in dialog.status_label.text()
    assert dialog.test_button.isEnabled()
    assert dialog.worker is None


def test_connection_failure_hides_key(paths):
    client = FakeClient(error=RuntimeError(f"401 for key {SECRET}"))
    dialog, _ = make_dialog(paths, client)
    dialog.key_input.setText(SECRET)

    dialog._start_connection_test()
    run_worker(dialog)

    text = dialog.status_label.text()
    assert "Connection failed" in text
    assert SECRET not in text
    assert "[REDACTED]" in text


def test_connection_test_needs_a_key(paths):
    dialog, calls = make_dialog(paths)

    dialog._start_connection_test()

    assert dialog.worker is None
    assert calls == []
    assert "Enter an API key" in dialog.status_label.text()
