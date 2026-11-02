
from types import SimpleNamespace

import pc_security.core.platform_info as platform_info


def fake_ctypes(result=None, error=None):
    def is_user_an_admin():
        if error is not None:
            raise error
        return result

    return SimpleNamespace(
        windll=SimpleNamespace(
            shell32=SimpleNamespace(IsUserAnAdmin=is_user_an_admin)
        )
    )


def use(monkeypatch, platform="win32", **kwargs):
    monkeypatch.setattr(platform_info, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(platform_info, "ctypes", fake_ctypes(**kwargs))


def test_admin(monkeypatch):
    use(monkeypatch, result=1)
    assert platform_info.is_running_as_admin() is True


def test_not_admin(monkeypatch):
    use(monkeypatch, result=0)
    assert platform_info.is_running_as_admin() is False


def test_error_is_unknown(monkeypatch):
    use(monkeypatch, error=OSError("call failed"))
    assert platform_info.is_running_as_admin() is None


def test_missing_windll_is_unknown(monkeypatch):
    monkeypatch.setattr(platform_info, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(platform_info, "ctypes", SimpleNamespace())
    assert platform_info.is_running_as_admin() is None


def test_non_windows_is_unknown(monkeypatch):
    use(monkeypatch, platform="linux", result=1)
    assert platform_info.is_running_as_admin() is None
