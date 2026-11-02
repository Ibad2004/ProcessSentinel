
from datetime import datetime

import pytest

from pc_security.ui.report_export import (
    DISCLAIMER,
    build_html_report,
    mask_usernames,
    save_html_report,
)


def flagged(**extra):
    item = {
        "pid": 4242,
        "name": "<script>alert(1)</script>.exe",
        "exe_path": r"C:\Users\alice\AppData\Roaming\evil & co\x.exe",
        "risk_score": 60,
        "risk_level": "high",
        "signature_status": "unsigned",
        "signer": None,
        "sha256": "ab" * 32,
        "outbound_connection_count": 2,
        "listening_ports": [8080],
        "findings": [{
            "code": "UNSIGNED_IN_USER_WRITABLE_DIR",
            "severity": "warning",
            "title": "Unsigned program in a user-writable folder",
            "explanation": 'Runs from "%APPDATA%" <b>bold</b>',
            "points": 30,
        }],
    }
    item.update(extra)
    return item


def report(analyses, **kwargs):
    kwargs.setdefault("username", "alice")
    kwargs.setdefault("generated_at", datetime(2026, 11, 3, 9, 30))
    return build_html_report(analyses, **kwargs)


def test_values_are_escaped_and_no_script_tags():
    html = report(
        [flagged()],
        ai_explanations={4242: "Use <script>steal()</script> & check"},
    )

    assert "<script" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.exe" in html
    assert "evil &amp; co" in html
    assert "&quot;%APPDATA%&quot; &lt;b&gt;bold&lt;/b&gt;" in html
    assert "Use &lt;script&gt;steal()&lt;/script&gt; &amp; check" in html


def test_self_contained_without_external_resources():
    html = report([flagged()])
    lowered = html.lower()

    assert "<style>" in lowered
    assert "http://" not in lowered and "https://" not in lowered
    assert "<link" not in lowered and "<img" not in lowered
    assert "src=" not in lowered
    assert "default-src 'none'" in html


def test_usernames_are_masked():
    html = report([flagged(
        username=r"DESKTOP\alice",
        findings=[{
            "code": "SYSTEM_PROCESS_WRONG_USER", "severity": "warning",
            "title": "Wrong user", "points": 40,
            "explanation": "Runs as 'DESKTOP\\alice' from C:\\Users\\alice",
        }],
    )])

    assert "alice" not in html.lower()
    assert r"C:\Users\&lt;user&gt;\AppData" in html


@pytest.mark.parametrize(
    "text, expected",
    [
        (r"C:\Users\alice\x.exe", r"C:\Users\<user>\x.exe"),
        (r"c:\users\Jo Smith\AppData\a.exe", r"c:\users\<user>\AppData\a.exe"),
        (r"C:\Users\Public\x.exe", r"C:\Users\Public\x.exe"),
        (r"C:\Users\Default\x.exe", r"C:\Users\Default\x.exe"),
        (r"from C:\Users\Public, a folder", r"from C:\Users\Public, a folder"),
        (r"at C:\Users\bob", r"at C:\Users\<user>"),
        (None, ""),
    ],
)
def test_mask_usernames(text, expected):
    assert mask_usernames(text, username="nobody-here") == expected


def test_summary_counts_admin_and_disclaimer():
    analyses = [
        flagged(),
        flagged(pid=2, risk_level="medium", risk_score=25),
        {"pid": 3, "name": "ok.exe", "risk_score": 0, "risk_level": "low",
         "findings": []},
    ]

    html = report(analyses, scanned_count=3, is_admin=False)

    assert "2026-11-03 09:30:00" in html
    assert "<th>Processes scanned</th><td>3</td>" in html
    assert "<th>High</th><td>1</td>" in html
    assert "<th>Medium</th><td>1</td>" in html
    assert "<th>Low</th><td>1</td>" in html
    assert "No (some details may be missing)" in html
    assert "ok.exe" not in html  # only medium/high are listed
    assert "indicators, not proof of malware" in DISCLAIMER
    assert html.count("indicators, not proof of malware") == 2


def test_signature_hash_network_and_ai_sections():
    html = report([flagged()], ai_explanations={4242: "Looks unusual."})

    assert "Unsigned" in html
    assert "ab" * 32 in html
    assert "Outbound: 2" in html
    assert "Listening: 8080" in html
    assert "UNSIGNED_IN_USER_WRITABLE_DIR" in html
    assert "Looks unusual." in html


def test_empty_scan_report():
    html = report([], is_admin=None)

    assert "No process reached a medium or high score" in html
    assert "No AI explanations were requested." in html
    assert "<th>Running as administrator</th><td>Unknown</td>" in html


def test_save_html_report_writes_utf8(tmp_path):
    path = save_html_report(tmp_path / "r.html", "<p>é</p>")

    assert path.read_text(encoding="utf-8") == "<p>é</p>"
