"""Data models and schema for PromptShield audit test cases.

=============================================================================
CONCEPT: Structured Test Cases in Security Auditing
=============================================================================
In penetration testing, we don't just throw random strings at a target. We
structure our tests with:
1. Target Objective: What vulnerability are we probing? (e.g. Canary extraction)
2. Success Indicators: How do we know if the attack succeeded?
3. OWASP Mapping: Aligning findings with the OWASP Top 10 for LLM Applications
   (e.g., LLM01: Prompt Injection, LLM07: System Prompt Leakage).
"""

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels matching standard CVSS definitions."""
    CRITICAL = "critical"  # Direct secret exfiltration, canary leak
    HIGH = "high"          # Complete system prompt dump, major policy breach
    MEDIUM = "medium"      # Minor rule bypass, partial instruction leak
    LOW = "low"            # Informational discrepancy or weak refusal


class OWASPMapping(str, Enum):
    """OWASP Top 10 for Large Language Model Applications (2025/2026)."""
    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Sensitive Information Disclosure"
    LLM07 = "LLM07: System Prompt Leakage"
    LLM09 = "LLM09: Overreliance / Policy Violation"
    LLM10 = "LLM10: Model Theft / Boundary Bypass"


class AttackCase(BaseModel):
    """Represents a single automated audit probe/attack test case."""
    id: str = Field(..., description="Unique test case identifier (e.g. INJ-001)")
    name: str = Field(..., description="Human-readable title for the test case")
    category: str = Field(..., description="Category group (e.g. direct_injection, policy_bypass)")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity rating if attack succeeds")
    owasp: OWASPMapping = Field(default=OWASPMapping.LLM01, description="OWASP LLM category mapping")
    prompt: str = Field(..., description="The audit prompt string sent to the target")
    description: str = Field(default="", description="Detailed purpose of this test probe")
    success_indicators: list[str] = Field(
        default_factory=list,
        description="List of regex patterns or keywords indicating the attack succeeded"
    )
    is_multi_turn: bool = Field(default=False, description="Whether this involves multi-turn conversation")
    multi_turn_prompts: list[str] = Field(
        default_factory=list,
        description="Sequence of prompts for multi-turn testing"
    )
    is_control: bool = Field(
        default=False,
        description="Whether this is a benign control benchmark to verify authorized behavior and absence of false positives"
    )
    recommended_mitigation: str = Field(
        default="Implement input guardrails and strict output data loss prevention (DLP).",
        description="Remediation guidance presented in the security report"
    )
