"""Build a self-contained HTML report of the current scan.

The report has inline CSS only: no scripts and no external resources.
Every value is HTML-escaped and Windows user names are masked.
"""

from __future__ import annotations

import html
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any


DISCLAIMER = (
    "ProcessSentinel findings are indicators, not proof of malware. A high "
    "score does not mean a program is malicious, and a low score does not "
    "mean it is safe. AI explanations can be wrong. Verify important "
    "findings with trusted tools before acting. ProcessSentinel is "
    "read-only: it did not stop, change or delete anything."
)

_SHARED_PROFILES = {"public", "default", "default user", "all users"}

# The profile folder is either followed by a separator (names may contain
# spaces, e.g. C:\Users\Jo Smith\AppData) or is a single word at the end.
_USER_PATH = re.compile(
    r"(?i)([a-z]:[\\/]+users[\\/]+)"
    r"(?:([^\\/\r\n\"'<>:|?*,;]{1,64}?)(?=[\\/])|([^\\/\s\"'<>:|?*,;]+))"
)

_STYLE = """
body { font-family: "Segoe UI", Arial, sans-serif; margin: 32px;
       color: #1f2937; background: #ffffff; line-height: 1.45; }
h1 { margin-bottom: 4px; } h2 { margin-top: 32px; border-bottom: 1px solid #d7e0ec; padding-bottom: 4px; }
.muted { color: #64748b; }
.disclaimer { background: #fef3c7; border: 1px solid #f59e0b; padding: 12px 16px; border-radius: 8px; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #d7e0ec; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #edf2f8; }
.high { color: #b91c1c; font-weight: 700; } .medium { color: #b45309; font-weight: 700; }
.mono { font-family: Consolas, monospace; font-size: 0.9em; word-break: break-all; }
.finding { margin: 4px 0; }
pre { white-space: pre-wrap; background: #f8fafc; border: 1px solid #d7e0ec; padding: 12px; border-radius: 8px; }
"""


def mask_usernames(text: Any, username: str | None = None) -> str:
    """Replace C:\\Users\\<name> with C:\\Users\\<user> and hide the account name."""
    if text is None:
        return ""
    text = str(text)

    def replace(match):
        name = match.group(2) or match.group(3)
        if name.strip().lower() in _SHARED_PROFILES:
            return match.group(0)
        return match.group(1) + "<user>"

    text = _USER_PATH.sub(replace, text)

    username = username if username is not None else os.environ.get("USERNAME")
    if username and len(username) >= 2:
        text = re.sub(
            rf"(?i)(?<![\w]){re.escape(username)}(?![\w])", "<user>", text
        )
    return text


def _safe(value: Any, username: str | None) -> str:
    """Mask, then escape: the only way values enter the HTML."""
    return html.escape(mask_usernames(value, username), quote=True)


def _admin_text(is_admin) -> str:
    if is_admin is True:
        return "Yes"
    if is_admin is False:
        return "No (some details may be missing)"
    return "Unknown"


def build_html_report(
    analyses: list[dict[str, Any]],
    ai_explanations: dict[int, str] | None = None,
    scanned_count: int | None = None,
    is_admin: bool | None = None,
    generated_at: datetime | None = None,
    username: str | None = None,
) -> str:
    """Return the report as one HTML string."""
    ai_explanations = ai_explanations or {}
    generated_at = generated_at or datetime.now()
    scanned_count = len(analyses) if scanned_count is None else scanned_count

    def esc(value):
        return _safe(value, username)

    levels = [str(item.get("risk_level") or "low").lower() for item in analyses]
    flagged = sorted(
        (item for item in analyses
         if str(item.get("risk_level") or "").lower() in {"medium", "high"}),
        key=lambda item: (-(item.get("risk_score") or 0), item.get("pid") or 0),
    )
    by_pid = {item.get("pid"): item for item in analyses}

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        # Blocks scripts and every external resource, even if edited later.
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        "<title>ProcessSentinel report</title>",
        f"<style>{_STYLE}</style></head><body>",
        "<h1>ProcessSentinel security report</h1>",
        f'<p class="muted">Generated {esc(generated_at.strftime("%Y-%m-%d %H:%M:%S"))}</p>',
        f'<p class="disclaimer">{esc(DISCLAIMER)}</p>',
        "<h2>Summary</h2><table>",
        f"<tr><th>Processes scanned</th><td>{esc(scanned_count)}</td></tr>",
        f"<tr><th>Running as administrator</th><td>{esc(_admin_text(is_admin))}</td></tr>",
        f"<tr><th>High</th><td>{levels.count('high')}</td></tr>",
        f"<tr><th>Medium</th><td>{levels.count('medium')}</td></tr>",
        f"<tr><th>Low</th><td>{levels.count('low')}</td></tr>",
        "</table>",
        "<h2>Medium and high processes</h2>",
    ]

    if not flagged:
        parts.append(
            "<p>No process reached a medium or high score. This does not "
            "prove the computer is safe.</p>"
        )
    else:
        parts.append(
            "<table><tr><th>Process</th><th>Score</th><th>Signature</th>"
            "<th>File</th><th>Network</th><th>Findings</th></tr>"
        )
        for item in flagged:
            level = str(item.get("risk_level") or "").lower()
            ports = item.get("listening_ports") or []
            network = (
                f"Outbound: {item.get('outbound_connection_count') or 0}<br>"
                f"Listening: {esc(', '.join(str(p) for p in ports) or 'none')}"
                if "outbound_connection_count" in item
                else "Not collected"
            )
            findings = "".join(
                f'<div class="finding"><b>{esc(f.get("title"))}</b> '
                f'({esc(f.get("code"))}, +{esc(f.get("points", 0))})<br>'
                f'{esc(f.get("explanation"))}</div>'
                for f in item.get("findings") or []
                if isinstance(f, dict) and (f.get("points") or 0) > 0
            )
            parts.append(
                "<tr>"
                f"<td><b>{esc(item.get('name') or 'Unknown')}</b><br>"
                f"PID {esc(item.get('pid'))}</td>"
                f'<td class="{esc(level)}">{esc(item.get("risk_score"))} '
                f"{esc(level.upper())}</td>"
                f"<td>{esc((item.get('signature_status') or 'not checked').capitalize())}"
                f"<br>{esc(item.get('signer') or '')}</td>"
                f'<td class="mono">{esc(item.get("exe_path") or "Unavailable")}'
                f"<br>SHA-256: {esc(item.get('sha256') or 'unavailable')}</td>"
                f"<td>{network}</td>"
                f"<td>{findings or 'No scored findings'}</td>"
                "</tr>"
            )
        parts.append("</table>")

    parts.append("<h2>AI explanations from this session</h2>")
    if not ai_explanations:
        parts.append("<p>No AI explanations were requested.</p>")
    for pid, explanation in sorted(ai_explanations.items(), key=lambda kv: str(kv[0])):
        name = (by_pid.get(pid) or {}).get("name") or "Unknown process"
        parts.append(
            f"<h3>{esc(name)} (PID {esc(pid)})</h3><pre>{esc(explanation)}</pre>"
        )

    parts.append(f'<p class="muted">{esc(DISCLAIMER)}</p></body></html>')
    return "\n".join(parts)


def save_html_report(path, report_html: str) -> Path:
    """Write the report to a file the user chose."""
    path = Path(path)
    path.write_text(report_html, encoding="utf-8")
    return path
