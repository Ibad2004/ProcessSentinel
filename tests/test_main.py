
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


def test_main_handles_missing_configuration(monkeypatch):
    def fail_to_load_config():
        raise FileNotFoundError("Configuration file not found")

    shown_errors = []

    class FakeMessageBox:
        @staticmethod
        def critical(parent, title, text):
            shown_errors.append((title, text))

    monkeypatch.setattr(
        main_module, "load_config", fail_to_load_config
    )
    monkeypatch.setattr(main_module, "QApplication", FakeApplication)
    monkeypatch.setattr(main_module, "QMessageBox", FakeMessageBox)

    result = main_module.main()

    assert result == 1
    assert len(shown_errors) == 1
    assert "Could not load application configuration" in shown_errors[0][1]


def test_configured_max_tokens_reach_groq_client():
    factory = main_module.build_explanation_service_factory(
        {"model": "test-model", "timeout": 12, "max_tokens": 2000}
    )

    service = factory()

    assert service.client.model == "test-model"
    assert service.client.timeout == 12
    assert service.client.max_tokens == 2000


def test_main_passes_configured_ai_settings(monkeypatch):
    monkeypatch.setattr(main_module, "QApplication", FakeApplication)
    monkeypatch.setattr(main_module, "MainWindow", FakeMainWindow)
    monkeypatch.setattr(
        main_module,
        "load_config",
        lambda: {"ai": {"enabled": True, "max_tokens": 2000}},
    )

    main_module.main()

    kwargs = FakeMainWindow.last_instance.kwargs
    assert kwargs["ai_max_tokens"] == 2000

    scan_service = kwargs["scan_service"]
    service = scan_service.explanation_service_factory()
    assert service.client.max_tokens == 2000

