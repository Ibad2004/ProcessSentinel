
"""Read-only facts about how ProcessSentinel is running."""

import ctypes
import sys


def is_running_as_admin():
    """Return True, False, or None when it cannot be determined.

    Only checks the current token; never requests elevation.
    """
    if sys.platform != "win32":
        return None

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None
