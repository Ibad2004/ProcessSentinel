
"""Save ProcessSentinel's own settings: the .env API key and the AI model.

Only ProcessSentinel's .env and settings.yaml are written. The API key is
never logged, printed, or included in error messages.
"""

import json
import os
import re
import sys
import tempfile
from pathlib import Path

import yaml

from pc_security.core.config import get_config_path


_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{8,256}$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9_.:/\-]{1,128}$")


class SettingsError(ValueError):
    """Raised for invalid values or files that cannot be written."""


def mask_secret(value):
    """Show only the last 4 characters, e.g. ••••abcd."""
    if not isinstance(value, str) or not value:
        return "Not set"
    return "••••" + value[-4:] if len(value) > 4 else "••••"


def validate_api_key(key):
    key = (key or "").strip()
    if not _KEY_PATTERN.match(key):
        raise SettingsError(
            "The API key should be 8 or more letters, digits, '-' or '_' "
            "with no spaces or quotes."
        )
    return key


def validate_model(model):
    model = (model or "").strip()
    if not _MODEL_PATTERN.match(model):
        raise SettingsError(
            "The model name may only contain letters, digits and . _ - : /"
        )
    return model


def _atomic_write(path, text):
    """Write text via a temporary file in the same folder, then replace."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="") as file:
                file.write(text)
            os.replace(temp_name, path)
        except BaseException:
            if os.path.exists(temp_name):
                os.remove(temp_name)
            raise
    except OSError as exc:
        raise SettingsError(
            f"Could not save {path.name}: {exc.strerror or 'write failed'}"
        ) from None


def _read_text_keep_newlines(path, encoding="utf-8"):
    """Read without newline translation so CRLF files stay CRLF."""
    with open(path, encoding=encoding, newline="") as file:
        return file.read()


def save_env_value(env_path, name, value):
    """Set NAME=value in a .env file, keeping every other line unchanged."""
    env_path = Path(env_path)
    try:
        existing = _read_text_keep_newlines(env_path, "utf-8-sig")
    except FileNotFoundError:
        existing = ""
    except OSError as exc:
        raise SettingsError(
            f"Could not read {env_path.name}: {exc.strerror or 'read failed'}"
        ) from None

    newline = "\r\n" if "\r\n" in existing else "\n"
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=")
    replacement = f"{name}={value}"

    lines = existing.splitlines()
    replaced = False
    output = []
    for line in lines:
        if pattern.match(line):
            if not replaced:
                output.append(replacement)
                replaced = True
            continue  # Drop duplicate definitions of the same name.
        output.append(line)

    if not replaced:
        output.append(replacement)

    _atomic_write(env_path, newline.join(output) + newline)


def get_writable_config_path():
    """Return the settings.yaml that should receive saved changes.

    In a PyInstaller build the bundled copy lives in a temporary,
    read-only folder, so changes go to config/settings.yaml beside the
    exe, which get_config_path() already prefers on the next start.
    """
    path = get_config_path()

    if getattr(sys, "frozen", False):
        bundle_dir = Path(getattr(sys, "_MEIPASS", "")).resolve()
        try:
            path.resolve().relative_to(bundle_dir)
        except ValueError:
            return path
        return (
            Path(sys.executable).resolve().parent / "config" / "settings.yaml"
        )

    return path


def save_ai_model(config_path, model, source_path=None):
    """Set ai.model in settings.yaml, keeping other settings and comments.

    source_path is read when config_path does not exist yet (used to copy
    the bundled settings beside a frozen exe).
    """
    model = validate_model(model)
    config_path = Path(config_path)
    read_from = config_path if config_path.is_file() else Path(
        source_path or get_config_path()
    )

    try:
        text = _read_text_keep_newlines(read_from)
    except OSError as exc:
        raise SettingsError(
            f"Could not read settings: {exc.strerror or 'read failed'}"
        ) from None

    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    value = json.dumps(model)  # A JSON string is a valid YAML scalar.

    ai_start = next(
        (i for i, line in enumerate(lines) if re.match(r"^ai:\s*(#.*)?$", line)),
        None,
    )
    if ai_start is None:
        lines.extend(["", "ai:", f"  model: {value}"])
    else:
        ai_end = next(
            (
                i for i in range(ai_start + 1, len(lines))
                if lines[i].strip()
                and not lines[i].startswith((" ", "\t", "#"))
            ),
            len(lines),
        )
        for i in range(ai_start + 1, ai_end):
            match = re.match(r"^(\s+)model:\s*[^#]*?(\s*#.*)?$", lines[i])
            if match:
                lines[i] = f"{match.group(1)}model: {value}{match.group(2) or ''}"
                break
        else:
            lines.insert(ai_start + 1, f"  model: {value}")

    new_text = newline.join(lines) + newline

    try:
        parsed = yaml.safe_load(new_text)
    except yaml.YAMLError:
        parsed = None
    if not isinstance(parsed, dict) or (
        (parsed.get("ai") or {}).get("model") != model
    ):
        raise SettingsError(
            "settings.yaml has an unexpected layout; the model was not saved."
        )

    _atomic_write(config_path, new_text)
