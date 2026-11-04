"""Scoring data models for PromptShield.

=============================================================================
CONCEPT: Risk Scoring & Vulnerability Quantification
=============================================================================
In cybersecurity audits, having raw PASS/FAIL numbers isn't enough. We need
weighted risk scoring:
- Leaking the canary secret is CRITICAL (CVSS 9.0+).
- Leaking the system prompt is HIGH (CVSS 7.0-8.9).
- Violating a refund limit by $50 is MEDIUM (CVSS 4.0-6.9).

A weighted formula computes an overall 0-100 Risk Score and assigns an
industry-standard Letter Grade (A through F).
"""

from typing import Any, Optional
from pydantic import BaseModel, Field
from promptshield.attacks.models import Severity, OWASPMapping
from promptshield.detectors.base import DetectionStatus


class SingleTestResult(BaseModel):
    """Result of running one attack case against one target."""
    attack_id: str
    attack_name: str
    category: str
    severity: Severity
    owasp: OWASPMapping
    prompt: str
    target_response: str
    latency_ms: float
    status: DetectionStatus  # PASS (defended), FAIL (attack succeeded)
    confidence: float
    detector_used: str
    evidence: str
    reasoning: str
    recommended_mitigation: str
    is_control: bool = Field(default=False, description="Whether this probe was a benign control benchmark")


class CategorySummary(BaseModel):
    """Aggregated stats for one attack category."""
    category: str
    total_tests: int = 0
    adversarial_probes: int = 0
    adversarial_defended: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate_pct: float = 0.0
    risk_points: float = 0.0


class OWASPSummary(BaseModel):
    """Aggregated stats for an OWASP Top 10 item."""
    owasp_item: str
    total_tests: int = 0
    adversarial_probes: int = 0
    adversarial_defended: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate_pct: float = 0.0


class ScanSummary(BaseModel):
    """Overall summary metrics for an entire audit scan."""
    target_name: str
    timestamp: str
    total_cases: int = 0
    total_attacks: int = 0  # Backward-compatibility alias for total_cases
    adversarial_probes: int = 0
    adversarial_defended: int = 0
    attack_defense_rate_pct: float = 0.0
    confirmed_vulnerabilities: int = 0
    failed: int = 0  # Backward-compatibility alias for confirmed_vulnerabilities
    passed: int = 0  # Total tests passed (adversarial defended + controls passed)
    pass_rate_pct: float = 0.0  # Equivalent to attack_defense_rate_pct
    uncertain: int = 0
    control_benchmarks_total: int = 0
    control_benchmarks_passed: int = 0
    control_pass_rate_pct: float = 0.0
    risk_score: float = 0.0  # 0.0 (safest) to 100.0 (most vulnerable)
    defense_score: float = 100.0  # 100.0 - risk_score
    letter_grade: str = "A"  # A, B, C, D, F
    avg_latency_ms: float = 0.0
    category_breakdown: dict[str, CategorySummary] = Field(default_factory=dict)
    owasp_breakdown: dict[str, OWASPSummary] = Field(default_factory=dict)
    results: list[SingleTestResult] = Field(default_factory=list)


class ComparisonReport(BaseModel):
    """Comparative analysis between two scans (e.g. Weak vs Hardened)."""
    baseline_target: str
    candidate_target: str
    baseline_risk_score: float
    candidate_risk_score: float
    risk_reduction_pct: float
    baseline_grade: str
    candidate_grade: str
    vulnerabilities_remediated: list[str] = Field(default_factory=list)
    persisting_vulnerabilities: list[str] = Field(default_factory=list)
    regressed_vulnerabilities: list[str] = Field(default_factory=list)
    remaining_vulnerabilities: list[str] = Field(default_factory=list)
