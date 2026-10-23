
import io
import json
from unittest.mock import patch
from urllib.error import URLError

import pytest

from pc_security.ai.ollama_client import (
    OllamaClient,
    OllamaClientError,
)


def test_client_uses_default_configuration():
    client = OllamaClient()

    assert client.base_url == "http://localhost:11434"
    assert client.model == "qwen3:8b"
    assert client.timeout == 60


def test_client_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        OllamaClient(base_url=" ")

    with pytest.raises(ValueError):
        OllamaClient(model=" ")

    with pytest.raises(ValueError):
        OllamaClient(timeout=0)


@patch("pc_security.ai.ollama_client.urlopen")
def test_generate_returns_model_response(mock_urlopen):
    response_body = {
        "message": {
            "role": "assistant",
            "content": "This process needs further investigation.",
        }
    }

    mock_response = io.BytesIO(
        json.dumps(response_body).encode("utf-8")
    )
    mock_urlopen.return_value.__enter__.return_value = mock_response

    client = OllamaClient()
    result = client.generate(
        "Explain this process.",
        system_prompt="Explain evidence carefully.",
    )

    assert result == "This process needs further investigation."

    request = mock_urlopen.call_args.args[0]
    payload = json.loads(request.data.decode("utf-8"))

    assert request.full_url == "http://localhost:11434/api/chat"
    assert payload["model"] == "qwen3:8b"
    assert payload["stream"] is False
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["content"] == "Explain this process."


@patch("pc_security.ai.ollama_client.urlopen")
def test_generate_handles_connection_failure(mock_urlopen):
    mock_urlopen.side_effect = URLError("Connection refused")

    client = OllamaClient()

    with pytest.raises(OllamaClientError, match="Could not communicate"):
        client.generate("Explain this process.")


@patch("pc_security.ai.ollama_client.urlopen")
def test_generate_handles_invalid_json(mock_urlopen):
    mock_response = io.BytesIO(b"not valid json")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    client = OllamaClient()

    with pytest.raises(OllamaClientError, match="invalid JSON"):
        client.generate("Explain this process.")


@patch("pc_security.ai.ollama_client.urlopen")
def test_generate_handles_missing_message(mock_urlopen):
    mock_response = io.BytesIO(b'{"done": true}')
    mock_urlopen.return_value.__enter__.return_value = mock_response

    client = OllamaClient()

    with pytest.raises(OllamaClientError, match="valid message"):
        client.generate("Explain this process.")


def test_generate_rejects_empty_prompt():
    client = OllamaClient()

    with pytest.raises(ValueError, match="prompt"):
        client.generate(" ")
