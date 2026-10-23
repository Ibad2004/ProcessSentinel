
"""HTTP client for communicating with a local Ollama instance."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaClientError(Exception):
    """Raised when an Ollama request fails."""


class OllamaClient:
    """A small client for Ollama's local chat API."""

    def __init__(
        self,
        base_url="http://localhost:11434",
        model="qwen3:8b",
        timeout=60,
    ):
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty string")

        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a positive number")

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.base_url = base_url.rstrip("/")
        self.model = model.strip()
        self.timeout = timeout

    def generate(self, prompt, system_prompt=None):
        """
        Send a prompt to Ollama and return the model's text response.

        This method communicates with the local AI service only.
        It does not inspect or modify Windows processes.
        """
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")

        messages = []

        if system_prompt is not None:
            if not isinstance(system_prompt, str) or not system_prompt.strip():
                raise ValueError(
                    "system_prompt must be a non-empty string when provided"
                )

            messages.append({
                "role": "system",
                "content": system_prompt,
            })

        messages.append({
            "role": "user",
            "content": prompt,
        })

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.2,
            },
        }

        request = Request(
            url=f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_text = response.read().decode("utf-8")

        except HTTPError as exc:
            try:
                details = exc.read().decode("utf-8", errors="replace")
            except Exception:
                details = ""

            raise OllamaClientError(
                f"Ollama returned HTTP {exc.code}: "
                f"{details or exc.reason}"
            ) from exc

        except (TimeoutError, URLError, OSError) as exc:
            raise OllamaClientError(
                "Could not communicate with Ollama. "
                "Check that Ollama is installed and running, "
                "and that its local API is accessible. "
                f"Details: {exc}"
            ) from exc

        try:
            result = json.loads(response_text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise OllamaClientError(
                "Ollama returned an invalid JSON response."
            ) from exc

        message = result.get("message")

        if not isinstance(message, dict):
            raise OllamaClientError(
                "Ollama's response did not contain a valid message."
            )

        content = message.get("content")

        if not isinstance(content, str) or not content.strip():
            raise OllamaClientError(
                "Ollama returned an empty or invalid text response."
            )

        return content.strip()
