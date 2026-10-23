
import sys

import pc_security.main as main_module


class FakeApplication:
    last_instance = None

    def __init__(self, arguments):
        self.arguments = arguments
        self.application_name = None
        self.style = None
        self.exec_called = False
        FakeApplication.last_instance = self

    @classmethod
    def instance(cls):
        return None

    def setApplicationName(self, name):
        self.application_name = name

    def setStyle(self, style):
        self.style = style

    def exec(self):
        self.exec_called = True
        return 0


class FakeMainWindow:
    last_instance = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.shown = False
        FakeMainWindow.last_instance = self

    def show(self):
        self.shown = True


def test_main_launches_application(monkeypatch):
    monkeypatch.setattr(
        main_module, "QApplication", FakeApplication
    )
    monkeypatch.setattr(
        main_module, "MainWindow", FakeMainWindow
    )
    monkeypatch.setattr(
        main_module,
        "load_config",
        lambda: {
            "app": {"name": "ProcessSentinel"},
            "ai": {
                "enabled": False,
                "provider": "groq",
                "model": "openai/gpt-oss-20b",
            },
        },
    )

    result = main_module.main()

    app = FakeApplication.last_instance
    window = FakeMainWindow.last_instance

    assert result == 0
    assert app.arguments == sys.argv
    assert app.application_name == "ProcessSentinel"
    assert app.style == "Fusion"
    assert app.exec_called
    assert window.shown
    assert window.kwargs["ai_enabled"] is False
    assert window.kwargs["ai_model"] == "openai/gpt-oss-20b"


def test_main_handles_missing_configuration(monkeypatch, capsys):
    def fail_to_load_config():
        raise FileNotFoundError("Configuration file not found")

    monkeypatch.setattr(
        main_module, "load_config", fail_to_load_config
    )

    result = main_module.main()

    captured = capsys.readouterr()

    assert result == 1
    assert "Could not load application configuration" in captured.out

