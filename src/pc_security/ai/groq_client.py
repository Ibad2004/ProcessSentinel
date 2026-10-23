
"""Small HTTP client for the Groq chat-completions API."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class GroqClientError(RuntimeError):
    """Raised when a Groq API request fails."""


class GroqClient:
    """Call Groq without requiring an external SDK."""

    API_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        model="openai/gpt-oss-20b",
        timeout=30,
        api_key=None,
        max_tokens=250,
    ):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be a positive number")

        if not isinstance(max_tokens, int) or max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")

        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.api_key = api_key or os.getenv("GROQ_API_KEY")

    def generate(self, prompt, system_prompt=None):
        """Send a prompt and return the model's text response."""
        if not self.api_key:
            raise GroqClientError(
                "GROQ_API_KEY is not set. Check your .env file."
            )

        messages = []

        if system_prompt:
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
            "temperature": 0.2,
            "max_completion_tokens": self.max_tokens,
            "stream": False,
        }

        request = Request(
            self.API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "ProcessSentinel/1.0",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_text = response.read().decode("utf-8")
                response_data = json.loads(response_text)

        except HTTPError as exc:
            try:
                details = exc.read().decode("utf-8", errors="replace")
            except Exception:
                details = ""

            # Keep the server's diagnostic details, but never expose
            # the API key if it appears in an unexpected response.
            if self.api_key:
                details = details.replace(self.api_key, "[REDACTED]")

            if exc.code == 401:
                message = (
                    "Groq authentication failed. Check that your API key "
                    "is valid and has not been revoked."
                )
            elif exc.code == 403:
                if "1010" in details:
                    message = (
                        "Access was blocked by a security layer "
                        "(error 1010). This is different from a missing "
                        "API key. Check the response details below."
                    )
                else:
                    message = (
                        "Groq denied this request (HTTP 403). Check "
                        "model permissions and API access."
                    )
            elif exc.code == 429:
                message = (
                    "Groq rate limit or usage limit reached. Wait and "
                    "check your Groq Console limits."
                )
            elif exc.code == 404:
                message = (
                    "The requested endpoint or model was not found. "
                    "Check the API URL and model ID."
                )
            else:
                message = f"Groq API returned HTTP {exc.code}."

            details = details.strip()[:1000]
            if not details:
                details = "The server provided no additional details."

            raise GroqClientError(
                f"{message}\nServer details: {details}"
            ) from exc

        except (URLError, TimeoutError, OSError) as exc:
            raise GroqClientError(
                f"Could not connect to Groq. Check your internet "
                f"connection and try again. Details: {exc}"
            ) from exc

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GroqClientError(
                "Groq returned a response that could not be decoded "
                "as valid JSON."
            ) from exc

        if not isinstance(response_data, dict):
            raise GroqClientError(
                "Groq returned an unexpected response format."
            )

        choices = response_data.get("choices")

        if not isinstance(choices, list) or not choices:
            raise GroqClientError(
                "Groq response did not contain any choices."
            )

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise GroqClientError(
                "Groq returned an invalid choice format."
            )

        message = first_choice.get("message", {})
        if not isinstance(message, dict):
            raise GroqClientError(
                "Groq returned an invalid message format."
            )

        content = message.get("content")

        if not isinstance(content, str) or not content.strip():
            raise GroqClientError(
                "Groq returned an empty explanation."
            )

        return content.strip()
