"""Dismissible notice shown when ProcessSentinel runs without admin rights."""

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton


ADMIN_BANNER_TEXT = (
    "Running without administrator rights - some paths, signatures, users "
    "and network connections may be unavailable."
)


class AdminBanner(QFrame):
    """Informational only: ProcessSentinel never requests elevation itself."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("adminBanner")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 8, 8)

        self.message_label = QLabel(ADMIN_BANNER_TEXT)
        self.message_label.setObjectName("adminBannerText")
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label, 1)

        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.setObjectName("secondaryButton")
        self.dismiss_button.clicked.connect(self.hide)
        layout.addWidget(self.dismiss_button)
