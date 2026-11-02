
import gc
import os

import pytest

# Qt widgets must never open real windows or block on modal dialogs in tests.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def collect_garbage_on_main_thread():
    """Free each test's unparented Qt widgets on the main thread.

    Without this, Python's cyclic garbage collector may run inside a later
    test's worker thread and delete a widget there, which aborts Qt.
    """
    yield
    gc.collect()
