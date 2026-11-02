
import os

# Qt widgets must never open real windows or block on modal dialogs in tests.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
