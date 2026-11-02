
import pytest

from pc_security.core.privacy import (
    account_name,
    is_builtin_account,
    mask_account,
    mask_usernames,
)


@pytest.mark.parametrize(
    "username, masked",
    [
        (r"DESKTOP-1\alice", "<user>"),
        (r"CORP\Jo Smith", "<user>"),
        ("alice", "<user>"),
        (r"NT AUTHORITY\SYSTEM", r"NT AUTHORITY\SYSTEM"),
        (r"NT AUTHORITY\LOCAL SERVICE", r"NT AUTHORITY\LOCAL SERVICE"),
        (r"Window Manager\DWM-1", r"Window Manager\DWM-1"),
        (None, None),
        ("", ""),
    ],
)
def test_mask_account(username, masked):
    assert mask_account(username) == masked


def test_account_name_only_for_people():
    assert account_name(r"PC\alice") == "alice"
    assert account_name(r"NT AUTHORITY\SYSTEM") is None
    assert account_name(None) is None
    assert is_builtin_account(r"nt authority\network service")
    assert not is_builtin_account(r"PC\alice")


def test_extra_names_are_masked_anywhere():
    text = r"D:\Projects\alice-tools\run.exe --owner alice --user=Alice"

    masked = mask_usernames(text, username="nobody", extra_names=["alice"])

    assert "alice" not in masked.lower().replace("<user>", "")
    assert masked == (
        r"D:\Projects\<user>-tools\run.exe --owner <user> --user=<user>"
    )


def test_public_and_default_profiles_are_kept():
    text = r"C:\Users\Public\a.exe C:\Users\Default\b.exe C:\Users\bob\c.exe"

    assert mask_usernames(text, username="nobody") == (
        r"C:\Users\Public\a.exe C:\Users\Default\b.exe C:\Users\<user>\c.exe"
    )


def test_default_username_comes_from_environment(monkeypatch):
    monkeypatch.setenv("USERNAME", "carol")

    assert mask_usernames("owned by carol") == "owned by <user>"
