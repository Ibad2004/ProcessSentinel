
"""Mask personal Windows account names before data leaves the app.

Used for both the AI evidence and exported reports, so they share one
definition of what is hidden.
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable


MASK = "<user>"

# Shared profile folders that do not identify a person.
SHARED_PROFILES = {"public", "default", "default user", "all users"}

# Built-in accounts are evidence (e.g. SYSTEM_PROCESS_WRONG_USER), not
# personal data, so they are kept.
BUILTIN_DOMAINS = {
    "nt authority",
    "nt service",
    "window manager",
    "font driver host",
}

# The profile folder is either followed by a separator (names may contain
# spaces, e.g. C:\Users\Jo Smith\AppData) or is a single word at the end.
_USER_PATH = re.compile(
    r"(?i)([a-z]:[\\/]+users[\\/]+)"
    r"(?:([^\\/\r\n\"'<>:|?*,;]{1,64}?)(?=[\\/])|([^\\/\s\"'<>:|?*,;]+))"
)


def is_builtin_account(username: Any) -> bool:
    if not isinstance(username, str) or "\\" not in username:
        return False
    domain = username.split("\\", 1)[0].strip().lower()
    return domain in BUILTIN_DOMAINS


def account_name(username: Any) -> str | None:
    """Return the person-identifying part of DOMAIN\\name, if any."""
    if not isinstance(username, str) or not username.strip():
        return None
    if is_builtin_account(username):
        return None
    return username.rsplit("\\", 1)[-1].strip() or None


def mask_account(username: Any) -> Any:
    """DOMAIN\\name -> <user>; built-in service accounts are kept."""
    if not isinstance(username, str) or not username.strip():
        return username
    if is_builtin_account(username):
        return username
    return MASK


def mask_usernames(
    text: Any,
    username: str | None = None,
    extra_names: Iterable[str] = (),
) -> str:
    """Replace C:\\Users\\<name> with C:\\Users\\<user> and hide account names.

    username defaults to %USERNAME%. extra_names are further account names
    (for example from a process's DOMAIN\\name) to hide anywhere in text.
    """
    if text is None:
        return ""
    text = str(text)

    def replace(match):
        name = match.group(2) or match.group(3)
        if name.strip().lower() in SHARED_PROFILES:
            return match.group(0)
        return match.group(1) + MASK

    text = _USER_PATH.sub(replace, text)

    username = username if username is not None else os.environ.get("USERNAME")
    names = {username, *extra_names}
    for name in sorted((n for n in names if n), key=len, reverse=True):
        if len(name) >= 2 and name.strip().lower() not in SHARED_PROFILES:
            text = re.sub(
                rf"(?i)(?<![\w]){re.escape(name)}(?![\w])", MASK, text
            )
    return text
