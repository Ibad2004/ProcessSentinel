"""Background worker so scans and network requests never freeze the UI."""

from typing import Callable

from PySide6.QtCore import QThread, Signal


class TaskWorker(QThread):
    """Run scanning and AI requests without freezing the UI."""

    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, operation: Callable, parent=None):
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            result = self.operation(self.progress.emit)
            self.succeeded.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
