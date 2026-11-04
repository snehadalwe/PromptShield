"""Base Target Adapter Interface.

=============================================================================
CONCEPT: Target Adapters (Adapter Pattern)
=============================================================================
In software engineering and security auditing, different chatbots have different
interfaces:
- Some are accessed via internal Python imports (like our demo target).
- Some use custom REST APIs (e.g. POST https://company.com/api/chat with custom JSON).
- Some use OpenAI-compatible chat endpoints (/v1/chat/completions).

The Adapter Pattern provides a single, uniform interface (`send(prompt)`) so the
rest of PromptShield (detectors, scanners, scorers) never needs to know how the
chatbot is hosted or called!
"""

from abc import ABC, abstractmethod
from typing import Any, Optional
from pydantic import BaseModel, Field
import time


class MessageTurn(BaseModel):
    """Represents a single conversational turn."""
    role: str = Field(..., description="'user', 'assistant', or 'system'")
    content: str = Field(..., description="The message content")


class TargetResponse(BaseModel):
    """Normalized response returned by any target adapter."""
    text: str = Field(..., description="The text output received from the chatbot")
    latency_ms: float = Field(default=0.0, description="Response time in milliseconds")
    status_code: int = Field(default=200, description="HTTP status code or 200 for in-memory")
    raw_payload: Optional[dict[str, Any]] = Field(default=None, description="Raw JSON returned by endpoint")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Custom target details")


class BaseTarget(ABC):
    """Abstract base class that all chatbot target adapters must implement."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def send(self, prompt: str, conversation_history: Optional[list[MessageTurn]] = None) -> TargetResponse:
        """Sends a prompt to the target chatbot and returns the normalized response.

        Args:
            prompt: The latest user prompt to send.
            conversation_history: Optional prior conversation turns for multi-turn testing.

        Returns:
            A TargetResponse object containing the reply text, latency, and metadata.
        """
        pass

    def test_connection(self) -> bool:
        """Sanity check to confirm target is reachable before starting a full audit scan."""
        try:
            res = self.send("Hello, test connection.")
            return res.status_code == 200 and len(res.text) > 0
        except Exception:
            return False
