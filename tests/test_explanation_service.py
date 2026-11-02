
import pytest

from pc_security.ai.explanation_service import AIExplanationService


class FakeAIClient:
    def __init__(self, response="This process needs further review."):
        self.response = response
        self.prompt = None
        self.system_prompt = None

    def generate(self, prompt, system_prompt=None):
        self.prompt = prompt
        self.system_prompt = system_prompt
        return self.response


def sample_analysis():
    return {
        "pid": 1234,
        "name": "example.exe",
        "exe_path": r"C:\Users\Public\example.exe",
        "risk_score": 35,
        "risk_level": "medium",
        "findings": [
            {
                "code": "SYSTEM_NAME_UNUSUAL_PATH",
                "severity": "warning",
                "title": "Windows process name with an unusual path",
                "explanation": "The executable is outside its usual directory.",
                "points": 35,
            }
        ],
    }


def test_explain_process_returns_pid_and_explanation():
    client = FakeAIClient("The executable location should be verified.")
    service = AIExplanationService(client=client)

    result = service.explain_process(sample_analysis())

    assert result["pid"] == 1234
    assert result["explanation"] == (
        "The executable location should be verified."
    )


def test_explain_process_sends_evidence_to_client():
    client = FakeAIClient()
    service = AIExplanationService(client=client)

    service.explain_process(sample_analysis())

    assert "example.exe" in client.prompt
    assert "SYSTEM_NAME_UNUSUAL_PATH" in client.prompt
    assert "35" in client.prompt
    assert "untrusted data" in client.system_prompt


def test_explain_process_does_not_send_unrelated_fields():
    client = FakeAIClient()
    service = AIExplanationService(client=client)

    analysis = sample_analysis()
    analysis["unrelated_secret"] = "should-not-be-sent"

    service.explain_process(analysis)

    assert "should-not-be-sent" not in client.prompt


def test_explain_process_rejects_invalid_input():
    service = AIExplanationService(client=FakeAIClient())

    with pytest.raises(ValueError, match="dictionary"):
        service.explain_process("not an analysis")


def test_explain_process_rejects_invalid_findings():
    service = AIExplanationService(client=FakeAIClient())

    analysis = sample_analysis()
    analysis["findings"] = "invalid"

    with pytest.raises(ValueError, match="findings"):
        service.explain_process(analysis)


def test_explanation_client_errors_are_not_hidden():
    class FailingClient:
        def generate(self, prompt, system_prompt=None):
            raise RuntimeError("AI service unavailable")

    service = AIExplanationService(client=FailingClient())

    with pytest.raises(RuntimeError, match="unavailable"):
        service.explain_process(sample_analysis())


def test_signature_evidence_is_sent_to_ai():
    client = FakeAIClient()
    service = AIExplanationService(client=client)

    analysis = sample_analysis()
    analysis["signature_status"] = "unsigned"
    analysis["signer"] = None
    analysis["sha256"] = "ab" * 32

    service.explain_process(analysis)

    assert '"signature_status": "unsigned"' in client.prompt
    assert '"signer": null' in client.prompt
    assert "ab" * 32 in client.prompt
    assert "does not mean unsigned" in client.system_prompt


def test_network_summary_is_sent_but_not_endpoints():
    client = FakeAIClient()
    service = AIExplanationService(client=client)

    analysis = sample_analysis()
    analysis["outbound_connection_count"] = 3
    analysis["listening_ports"] = [8080, 443]
    analysis["remote_endpoints"] = ["203.0.113.9:4444"]

    service.explain_process(analysis)

    assert '"outbound_connection_count": 3' in client.prompt
    assert "8080" in client.prompt
    assert "203.0.113.9" not in client.prompt
    assert "SCRIPT_HOST_WITH_NETWORK_ACTIVITY" in client.system_prompt
    assert "UNSIGNED_WITH_NETWORK_ACTIVITY" in client.system_prompt


def test_new_since_last_scan_is_sent_and_explained():
    client = FakeAIClient()
    service = AIExplanationService(client=client)

    analysis = sample_analysis()
    analysis["is_new_since_last_scan"] = True

    service.explain_process(analysis)

    assert '"is_new_since_last_scan": true' in client.prompt
    assert "does not mean malicious" in client.system_prompt


# ---------------------------------------------------------------------------
# Step 4: privacy and evidence completeness
# ---------------------------------------------------------------------------

import json
import re
from datetime import datetime
from pathlib import Path

from pc_security.ai.explanation_service import (
    MAX_CMDLINE_CHARS,
    RULE_GLOSSARY,
    SYSTEM_PROMPT,
    build_evidence,
)


def private_analysis():
    analysis = sample_analysis()
    analysis.update({
        "exe_path": r"C:\Users\alice\AppData\Roaming\tool.exe",
        "cmdline": r'"C:\Users\alice\AppData\Roaming\tool.exe" --home C:\Users\alice',
        "username": r"DESKTOP-1\alice",
        "parent_pid": 4000,
        "parent_name": "explorer.exe",
        "create_time": datetime(2026, 11, 3, 9, 30, 15).timestamp(),
        "signature_status": "valid",
        "signer": "Alice Software Ltd",
        "sha256": "ab" * 32,
        "outbound_connection_count": 2,
        "listening_ports": [8080],
        "is_new_since_last_scan": True,
    })
    analysis["findings"][0]["explanation"] = (
        r"Runs as 'DESKTOP-1\alice' from C:\Users\alice\AppData"
    )
    return analysis


def evidence_for(analysis, monkeypatch):
    monkeypatch.setenv("USERNAME", "someone-else")
    client = FakeAIClient()
    AIExplanationService(client=client).explain_process(analysis)
    text = client.prompt.split("PROCESS ANALYSIS EVIDENCE:\n", 1)[1]
    return json.loads(text)


def test_username_is_masked_everywhere_but_signer_kept(monkeypatch):
    evidence = evidence_for(private_analysis(), monkeypatch)

    assert evidence["exe_path"] == r"C:\Users\<user>\AppData\Roaming\tool.exe"
    assert evidence["cmdline"] == (
        r'"C:\Users\<user>\AppData\Roaming\tool.exe" --home C:\Users\<user>'
    )
    assert evidence["username"] == "<user>"
    assert "alice" not in evidence["findings"][0]["description"].lower()
    # The signer is a publisher, not the user: kept as evidence.
    assert evidence["signer"] == "Alice Software Ltd"


def test_system_account_is_kept_for_evidence(monkeypatch):
    analysis = private_analysis()
    analysis["username"] = r"NT AUTHORITY\SYSTEM"

    assert evidence_for(analysis, monkeypatch)["username"] == (
        r"NT AUTHORITY\SYSTEM"
    )


def test_evidence_contains_every_rule_field(monkeypatch):
    evidence = evidence_for(private_analysis(), monkeypatch)

    assert evidence["parent_name"] == "explorer.exe"
    assert evidence["parent_pid"] == 4000
    assert evidence["create_time"] == "2026-11-03T09:30:15"
    assert evidence["signature_status"] == "valid"
    assert evidence["sha256"] == "ab" * 32
    assert evidence["outbound_connection_count"] == 2
    assert evidence["listening_ports"] == [8080]
    assert evidence["is_new_since_last_scan"] is True


def test_long_cmdline_is_truncated(monkeypatch):
    analysis = private_analysis()
    analysis["cmdline"] = "powershell " + "A" * 2000

    cmdline = evidence_for(analysis, monkeypatch)["cmdline"]

    assert len(cmdline) <= MAX_CMDLINE_CHARS + len(" [truncated]")
    assert cmdline.endswith("[truncated]")


def test_findings_are_capped_at_20():
    analysis = sample_analysis()
    analysis["findings"] = analysis["findings"] * 30

    assert len(build_evidence(analysis)["findings"]) == 20


@pytest.mark.parametrize("value", [None, "yesterday", True, 1e20])
def test_bad_create_time_becomes_none(value):
    analysis = sample_analysis()
    analysis["create_time"] = value

    assert build_evidence(analysis)["create_time"] is None


def test_prompt_lists_every_analyzer_rule_code():
    import pc_security.security.analyzer as analyzer

    source = Path(analyzer.__file__).read_text(encoding="utf-8")
    codes = set(re.findall(r'^\s+"([A-Z][A-Z0-9_]{3,})",\s*$', source, re.M))
    codes = {code for code in codes if "_" in code}

    assert "SYSTEM_PROCESS_NOT_MICROSOFT_SIGNED" in codes
    assert len(codes) >= 18
    assert codes <= set(RULE_GLOSSARY)
    for code in codes:
        assert f"- {code}:" in SYSTEM_PROMPT


def test_prompt_states_which_fields_are_masked():
    assert "<user>" in SYSTEM_PROMPT
    assert "exe_path, cmdline, username" in SYSTEM_PROMPT
