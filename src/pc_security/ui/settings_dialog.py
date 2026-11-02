"""AI settings: Groq API key, model choice, and a connection test."""

from __future__ import annotations

import os

from PySide6.QtCore import Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from pc_security.core.settings_store import (
    SettingsError,
    mask_secret,
    save_ai_model,
    save_env_value,
    validate_api_key,
    validate_model,
)
from pc_security.ui.workers import TaskWorker


SUGGESTED_MODELS = [
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
]


def _default_client_factory(api_key, model, timeout):
    from pc_security.ai.groq_client import GroqClient

    return GroqClient(model=model, timeout=timeout, api_key=api_key)


class AISettingsDialog(QDialog):
    """Edit ProcessSentinel's own .env key and settings.yaml model.

    The key is never logged or shown; only its last 4 characters appear.
    """

    settings_saved = Signal(str)

    def __init__(
        self,
        env_path,
        config_path,
        current_model: str,
        timeout: int = 30,
        client_factory=None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("AI settings")
        self.setMinimumWidth(520)

        self.env_path = env_path
        self.config_path = config_path
        self.current_model = current_model
        self.timeout = timeout
        self.client_factory = client_factory or _default_client_factory
        self.worker = None

        layout = QVBoxLayout(self)

        intro = QLabel(
            "Your Groq API key is stored in the .env file beside "
            "ProcessSentinel. Process details are only sent to Groq when "
            "you request an AI explanation."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.current_key_label = QLabel()
        form.addRow("Current key:", self.current_key_label)

        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setPlaceholderText("Leave empty to keep the current key")
        form.addRow("New API key:", self.key_input)

        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        for model in [current_model, *SUGGESTED_MODELS]:
            if model and self.model_combo.findText(model) < 0:
                self.model_combo.addItem(model)
        self.model_combo.setCurrentText(current_model)
        form.addRow("Model:", self.model_combo)
        layout.addLayout(form)

        test_row = QHBoxLayout()
        self.test_button = QPushButton("Test connection")
        self.test_button.clicked.connect(self._start_connection_test)
        test_row.addWidget(self.test_button)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        test_row.addWidget(self.status_label, 1)
        layout.addLayout(test_row)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self._update_current_key_label()

    def _update_current_key_label(self) -> None:
        self.current_key_label.setText(mask_secret(os.environ.get("GROQ_API_KEY")))

    def _key_for_request(self) -> str | None:
        return self.key_input.text().strip() or os.environ.get("GROQ_API_KEY")

    @staticmethod
    def _redact(message: str, key: str | None) -> str:
        if key:
            message = message.replace(key, "[REDACTED]")
        return message

    @Slot()
    def _start_connection_test(self) -> None:
        if self.worker is not None:
            return

        key = self._key_for_request()
        model = self.model_combo.currentText().strip()
        if not key:
            self.status_label.setText("Enter an API key first.")
            return

        self.test_button.setEnabled(False)
        self.status_label.setText("Testing connection...")

        def operation(_report_progress):
            try:
                client = self.client_factory(key, model, self.timeout)
                client.check_connection()
            except Exception as exc:
                raise RuntimeError(self._redact(str(exc), key)) from None
            return model

        self.worker = TaskWorker(operation, self)
        self.worker.succeeded.connect(self._connection_test_succeeded)
        self.worker.failed.connect(self._connection_test_failed)
        self.worker.finished.connect(self._connection_test_finished)
        self.worker.start()

    @Slot(object)
    def _connection_test_succeeded(self, model) -> None:
        self.status_label.setText(f"Connected. Groq accepted model {model}.")

    @Slot(str)
    def _connection_test_failed(self, message: str) -> None:
        self.status_label.setText(f"Connection failed: {message}")

    @Slot()
    def _connection_test_finished(self) -> None:
        self.test_button.setEnabled(True)
        self.worker = None

    @Slot()
    def _save(self) -> None:
        key_text = self.key_input.text().strip()
        try:
            model = validate_model(self.model_combo.currentText())
            key = validate_api_key(key_text) if key_text else None

            if key is not None:
                save_env_value(self.env_path, "GROQ_API_KEY", key)
                os.environ["GROQ_API_KEY"] = key

            if model != self.current_model:
                save_ai_model(self.config_path, model)
        except SettingsError as exc:
            self.status_label.setText(str(exc))
            return

        self.key_input.clear()
        self._update_current_key_label()
        self.current_model = model
        self.settings_saved.emit(model)
        self.accept()

    def done(self, result) -> None:
        # Save, Cancel and the close button all end here; never destroy
        # the dialog while its test thread is still running.
        if self.worker is not None:
            self.worker.wait()
        super().done(result)
