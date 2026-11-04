"""OpenAI-Compatible Target Adapter for PromptShield.

Works with any LLM server implementing the OpenAI Chat Completions API
(OpenAI, Ollama, Groq, vLLM, LM Studio, etc.).
"""

import os
import time
from typing import Optional, Any
import requests
from promptshield.targets.base import BaseTarget, TargetResponse, MessageTurn


class OpenAITargetAdapter(BaseTarget):
    """Adapter for auditing OpenAI-compatible endpoints."""

    def __init__(
        self,
        name: str = "OpenAI-Compatible",
        api_base: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        temperature: float = 0.2,
        timeout_seconds: int = 20,
    ) -> None:
        super().__init__(name=name)
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY") or ""
        self.model = model
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds

    def get_metadata(self) -> dict[str, Any]:
        """Returns target adapter metadata with sanitized secrets."""
        return {
            "name": self.name,
            "api_base": self.api_base,
            "model": self.model,
            "api_key_masked": self._get_masked_key(),
            "timeout_seconds": self.timeout_seconds,
        }

    def _get_masked_key(self) -> str:
        """Returns sanitized representation of API key."""
        if not self.api_key:
            return "none"
        if len(self.api_key) > 8:
            return self.api_key[:4] + "***" + self.api_key[-4:]
        return "***"

    def send(self, prompt: str, conversation_history: Optional[list[MessageTurn]] = None) -> TargetResponse:
        start_time = time.perf_counter()

        # Check for missing API key upfront
        if not self.api_key:
            return TargetResponse(
                text="[Configuration Error]: No OpenAI API key provided. Please set OPENAI_API_KEY in your environment or .env file.",
                latency_ms=0.0,
                status_code=401,
                metadata={"error": "missing_api_key", "api_base": self.api_base}
            )

        # Build messages payload
        messages = []
        if conversation_history:
            for turn in conversation_history:
                messages.append({"role": turn.role, "content": turn.content})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }

        url = f"{self.api_base}/chat/completions"

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code != 200:
                # Sanitize error message to ensure API key is never leaked
                sanitized_error = resp.text.replace(self.api_key, "***") if self.api_key else resp.text
                return TargetResponse(
                    text=f"[API Error {resp.status_code}]: {sanitized_error[:200]}",
                    latency_ms=round(elapsed_ms, 2),
                    status_code=resp.status_code,
                    raw_payload={"status": resp.status_code, "error": sanitized_error[:200]},
                    metadata={"model": self.model, "api_base": self.api_base, "api_key": self._get_masked_key()}
                )

            data = resp.json()
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            content = message.get("content") or choice.get("text") or ""

            return TargetResponse(
                text=content,
                latency_ms=round(elapsed_ms, 2),
                status_code=resp.status_code,
                raw_payload=data,
                metadata={"model": self.model, "usage": data.get("usage", {}), "api_key": self._get_masked_key()}
            )

        except requests.exceptions.Timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TargetResponse(
                text=f"[Timeout Error]: Request exceeded {self.timeout_seconds}s limit",
                latency_ms=round(elapsed_ms, 2),
                status_code=408,
                metadata={"error": "timeout", "model": self.model}
            )
        except requests.exceptions.ConnectionError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TargetResponse(
                text=f"[Connection Error]: Unable to connect to endpoint at {self.api_base}",
                latency_ms=round(elapsed_ms, 2),
                status_code=503,
                metadata={"error": "connection_error", "api_base": self.api_base}
            )
        except Exception as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            sanitized_err = str(err).replace(self.api_key, "***") if self.api_key else str(err)
            return TargetResponse(
                text=f"[Request Error]: {sanitized_err[:150]}",
                latency_ms=round(elapsed_ms, 2),
                status_code=500,
                metadata={"error": sanitized_err[:100]}
            )
