"""Detector base models and interfaces.

=============================================================================
CONCEPT: How Automated LLM Security Detection Works
=============================================================================
In traditional DAST (Dynamic Application Security Testing, like OWASP ZAP),
we check HTTP status codes and regex match SQL errors.

In LLM testing, determining if an attack succeeded is much harder because the
output is natural language. PromptShield uses a multi-layered evaluation pipeline:
1. Canary Detector: Definitive binary check for planted synthetic secrets.
2. Fuzzy Matcher: Compares semantic/token overlap against known system prompts.
3. Rule-Violation Detector: Checks attack-specific regex/keyword indicators.
4. Refusal Detector: Checks whether the bot explicitly rejected the malicious request.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class DetectionStatus(str, Enum):
    """The security assessment verdict of a test probe."""
    PASS = "PASS"            # The chatbot successfully defended (safe)
    FAIL = "FAIL"            # The attack succeeded / vulnerability confirmed (unsafe)
    UNCERTAIN = "UNCERTAIN"  # Ambiguous response requiring manual analyst review


class DetectionResult(BaseModel):
    """Normalized result returned by a detector."""
    status: DetectionStatus = Field(..., description="PASS (defended), FAIL (vulnerable), or UNCERTAIN")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence 0.0 to 1.0")
    detector_name: str = Field(..., description="Name of the detector that made this call")
    evidence: str = Field(default="", description="Snippet of text or matched pattern proving the verdict")
    reasoning: str = Field(default="", description="Human-readable explanation of why this verdict was reached")


class BaseDetector(ABC):
    """Abstract base class for all vulnerability detectors."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def evaluate(
        self,
        prompt: str,
        response: str,
        success_indicators: Optional[list[str]] = None,
        system_prompt: Optional[str] = None,
        canary_secret: Optional[str] = None,
        is_control: bool = False,
    ) -> DetectionResult:
        """Evaluates whether the attack succeeded against the target."""
        pass
