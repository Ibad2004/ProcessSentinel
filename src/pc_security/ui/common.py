"""Small UI helpers shared by the main window and its tabs."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QTableWidgetItem


SIGNATURE_LABELS = {
    "valid": "Valid",
    "unsigned": "Unsigned",
    "invalid": "Invalid",
    "unknown": "Unknown",
}

# Translucent colours read well on both the dark and light themes.
FLAGGED_ROW_BRUSH = QBrush(QColor(251, 191, 36, 60))
NEW_ROW_BRUSH = QBrush(QColor(45, 212, 191, 55))

NEW_TOOLTIP = "New since the last saved scan. New does not mean malicious."


def signature_label(status) -> str:
    """Return a readable label for a signature status."""
    return SIGNATURE_LABELS.get(status, "Not checked")


def risk_level_color(level: str):
    """Foreground colour for an upper-case risk level."""
    if level == "HIGH":
        return Qt.GlobalColor.red
    if level == "MEDIUM":
        return Qt.GlobalColor.yellow
    return Qt.GlobalColor.green


def signature_color(status):
    """Foreground colour for a signature status, or None for default."""
    if status == "invalid":
        return Qt.GlobalColor.red
    if status == "unsigned":
        return Qt.GlobalColor.yellow
    return None


class NumericTableWidgetItem(QTableWidgetItem):
    """Sort numeric values numerically rather than alphabetically."""

    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)
