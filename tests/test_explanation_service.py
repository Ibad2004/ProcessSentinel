
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
