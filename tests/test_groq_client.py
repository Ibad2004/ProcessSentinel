
import json
from unittest.mock import patch

import pytest

from pc_security.ai.groq_client import GroqClient, GroqClientError


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


def test_generate_returns_response_text():
    payload = {
        "choices": [
            {
                "message": {
                    "content": "This process needs further verification."
                }
            }
        ]
    }

    client = GroqClient(api_key="test-key")

    with patch(
        "pc_security.ai.groq_client.urlopen",
        return_value=FakeResponse(payload),
    ) as mocked_urlopen:
        result = client.generate(
            "Explain this process",
            system_prompt="Be concise",
        )

    assert result == "This process needs further verification."

    request = mocked_urlopen.call_args.args[0]
    body = json.loads(request.data.decode("utf-8"))

    assert request.full_url == GroqClient.API_URL
    assert request.get_header("Authorization") == "Bearer test-key"
    assert body["model"] == "openai/gpt-oss-20b"
    assert body["max_completion_tokens"] == 250
    assert len(body["messages"]) == 2


def test_generate_requires_api_key():
    client = GroqClient(api_key="")

    with patch.dict("os.environ", {"GROQ_API_KEY": ""}):
        with pytest.raises(GroqClientError, match="GROQ_API_KEY"):
            client.generate("Explain this process")


def test_generate_rejects_empty_response():
    client = GroqClient(api_key="test-key")

    with patch(
        "pc_security.ai.groq_client.urlopen",
        return_value=FakeResponse({"choices": []}),
    ):
        with pytest.raises(GroqClientError, match="choices"):
            client.generate("Explain this process")
