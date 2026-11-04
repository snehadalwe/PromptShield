"""Generic REST API Target Adapter for PromptShield.

Connects to any arbitrary web service or chatbot REST endpoint using
configurable JSON payload templates and dot-notation response extractors.
"""

import time
import json
from typing import Any, Optional
import requests
from promptshield.targets.base import BaseTarget, TargetResponse, MessageTurn


class GenericRestAdapter(BaseTarget):
    """Adapter for testing external REST API chatbot endpoints."""

    def __init__(
        self,
        name: str,
        url: str,
        method: str = "POST",
        headers: Optional[dict[str, str]] = None,
        body_template: Optional[dict[str, Any]] = None,
        prompt_field: str = "message",
        response_extractor: str = "response",
        timeout_seconds: int = 15,
        timeout: Optional[int] = None,
    ) -> None:
        """
        Args:
            name: Target label
            url: Endpoint URL (e.g. http://localhost:5000/chat)
            method: HTTP method (POST/GET)
            headers: Custom request headers (e.g. Auth tokens)
            body_template: JSON dictionary structure sent to endpoint
            prompt_field: Name of the JSON field that receives the prompt
            response_extractor: Dot-notation path to extract response text (e.g. 'choices.0.message.content')
            timeout_seconds: Network timeout
            timeout: Alternative alias for timeout_seconds
        """
        super().__init__(name=name)
        if not url.startswith("http://") and not url.startswith("https://"):
            raise ValueError(f"Invalid target URL '{url}': URL must begin with http:// or https://")

        self.url = url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.body_template = body_template or {}
        self.prompt_field = prompt_field
        self.response_extractor = response_extractor
        self.timeout_seconds = timeout if timeout is not None else timeout_seconds

    def get_metadata(self) -> dict[str, Any]:
        """Returns target adapter metadata with sanitized headers."""
        return {
            "name": self.name,
            "url": self.url,
            "method": self.method,
            "headers": self._mask_headers(self.headers),
            "prompt_field": self.prompt_field,
            "response_extractor": self.response_extractor,
            "timeout_seconds": self.timeout_seconds,
        }

    def _mask_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitizes sensitive authorization headers to prevent credential leakage."""
        masked = {}
        sensitive_keys = {"authorization", "api-key", "x-api-key", "token", "x-auth-token"}
        for k, v in headers.items():
            if k.lower() in sensitive_keys:
                if len(v) > 8:
                    masked[k] = v[:4] + "***" + v[-4:]
                else:
                    masked[k] = "***"
            else:
                masked[k] = v
        return masked

    def send(self, prompt: str, conversation_history: Optional[list[MessageTurn]] = None) -> TargetResponse:
        start_time = time.perf_counter()

        # Build payload by cloning template and setting the prompt field
        payload = dict(self.body_template)
        payload[self.prompt_field] = prompt

        sanitized_headers = self._mask_headers(self.headers)

        try:
            if self.method == "POST":
                resp = requests.post(
                    self.url,
                    headers=self.headers,
                    json=payload,
                    timeout=self.timeout_seconds
                )
            else:
                resp = requests.get(
                    self.url,
                    headers=self.headers,
                    params={self.prompt_field: prompt},
                    timeout=self.timeout_seconds
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code != 200:
                return TargetResponse(
                    text=f"[HTTP Error {resp.status_code}]: {resp.text[:200]}",
                    latency_ms=round(elapsed_ms, 2),
                    status_code=resp.status_code,
                    raw_payload={"status": resp.status_code, "body": resp.text[:200]},
                    metadata={"url": self.url, "headers": sanitized_headers}
                )

            try:
                json_data = resp.json()
            except requests.exceptions.JSONDecodeError:
                return TargetResponse(
                    text=f"[Format Error]: Response is not valid JSON. Raw: {resp.text[:200]}",
                    latency_ms=round(elapsed_ms, 2),
                    status_code=resp.status_code,
                    raw_payload={"raw_body": resp.text[:200]},
                    metadata={"url": self.url, "headers": sanitized_headers}
                )

            extracted_text = self._extract_path(json_data, self.response_extractor)

            return TargetResponse(
                text=str(extracted_text),
                latency_ms=round(elapsed_ms, 2),
                status_code=resp.status_code,
                raw_payload=json_data,
                metadata={"url": self.url, "headers": sanitized_headers}
            )

        except requests.exceptions.Timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TargetResponse(
                text=f"[Timeout Error]: Request exceeded timeout limit of {self.timeout_seconds}s",
                latency_ms=round(elapsed_ms, 2),
                status_code=408,
                metadata={"error": "timeout", "url": self.url}
            )
        except requests.exceptions.ConnectionError as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TargetResponse(
                text=f"[Connection Error]: Unable to reach target endpoint at {self.url}",
                latency_ms=round(elapsed_ms, 2),
                status_code=503,
                metadata={"error": "connection_refused", "url": self.url}
            )
        except Exception as err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TargetResponse(
                text=f"[Request Error]: {str(err)[:150]}",
                latency_ms=round(elapsed_ms, 2),
                status_code=500,
                metadata={"error": str(err)[:100]}
            )

    def _extract_path(self, data: Any, path: str) -> Any:
        """Extracts nested value using dot notation (e.g., 'choices.0.message.content')."""
        if not path:
            return data

        parts = path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    return ""
            else:
                return ""
            if current is None:
                return ""
        return current
