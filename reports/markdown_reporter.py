"""Markdown Report Generator for PromptShield.

Produces formatted Markdown documentation suitable for pull request comments
and security auditing dossiers.
"""

from pathlib import Path
from promptshield.detectors.base import DetectionStatus
from promptshield.scoring.models import ScanSummary


class MarkdownReporter:
    """Generates clean GitHub-Flavored Markdown reports."""

    @staticmethod
    def generate(summary: ScanSummary, output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = []
        lines.append(f"# 🧬 PromptShield Security Audit Report")
        lines.append(f"**Target**: `{summary.target_name}` | **Scan Date**: `{summary.timestamp}`\n")

        # Executive Metrics Table
        lines.append("## 📊 Executive Summary\n")
        lines.append("| Metric | Value | Status |")
        lines.append("|---|---|---|")
        lines.append(f"| **Security Grade** | **{summary.letter_grade}** | {'🟢 Pass' if summary.letter_grade in ['A', 'B'] else '🔴 Needs Remediation'} |")
        lines.append(f"| **Vulnerability Risk Score** | **{summary.risk_score} / 100** | {'Low Risk' if summary.risk_score < 25 else 'High Risk'} |")
        lines.append(f"| **Attack Defense Rate** | **{summary.attack_defense_rate_pct}%** | ({summary.adversarial_defended}/{summary.adversarial_probes} adversarial probes repelled) |")
        lines.append(f"| **Confirmed Vulnerabilities** | **{summary.confirmed_vulnerabilities}** | {'Zero Exploits' if summary.confirmed_vulnerabilities == 0 else f'{summary.confirmed_vulnerabilities} vulnerabilities identified'} |")
        lines.append(f"| **Control Benchmarks** | **{summary.control_benchmarks_passed} / {summary.control_benchmarks_total}** | {summary.control_pass_rate_pct}% operational integrity |")
        lines.append(f"| **Total Cases Evaluated** | **{summary.total_cases}** | {summary.adversarial_probes} attacks + {summary.control_benchmarks_total} controls |")
        lines.append(f"| **Average Latency** | **{summary.avg_latency_ms} ms** | Performance benchmark |\n")

        # Category Breakdown
        lines.append("## 🔍 Attack Category Breakdown\n")
        lines.append("| Category | Total Tests | Adversarial | Repelled (Pass) | Vulnerabilities (Fail) | Attack Defense Rate |")
        lines.append("|---|---|---|---|---|---|")
        for cat_name, cat in summary.category_breakdown.items():
            lines.append(f"| `{cat_name}` | {cat.total_tests} | {cat.adversarial_probes} | {cat.adversarial_defended} | {cat.failed} | **{cat.pass_rate_pct}%** |")
        lines.append("")

        # OWASP LLM Top 10 Breakdown
        lines.append("## 🌐 OWASP LLM Top 10 Reference Mapping\n")
        lines.append("| OWASP Category | Tests Run | Adversarial | Defended | Compromised | Defense Rate |")
        lines.append("|---|---|---|---|---|---|")
        for owasp_name, owasp in summary.owasp_breakdown.items():
            lines.append(f"| {owasp_name} | {owasp.total_tests} | {owasp.adversarial_probes} | {owasp.adversarial_defended} | {owasp.failed} | **{owasp.pass_rate_pct}%** |")
        lines.append("")

        # Detailed Findings (Vulnerabilities only)
        failed_tests = [r for r in summary.results if r.status == DetectionStatus.FAIL]
        lines.append("## 🚨 Identified Vulnerabilities & Exploits\n")
        if not failed_tests:
            lines.append("✅ **No vulnerabilities detected!** All security boundaries and guardrails remained intact.\n")
        else:
            lines.append(f"Found **{len(failed_tests)}** attack(s) that bypassed target guardrails:\n")
            for idx, item in enumerate(failed_tests, 1):
                lines.append(f"### {idx}. [{item.severity.upper()}] {item.attack_name} (`{item.attack_id}`)")
                lines.append(f"- **OWASP Classification**: `{item.owasp.value}`")
                lines.append(f"- **Detector**: `{item.detector_used}` (Confidence: {int(item.confidence * 100)}%)")
                lines.append(f"- **Prompt Injected**:\n  ```text\n  {item.prompt}\n  ```")
                lines.append(f"- **Chatbot Response**:\n  ```text\n  {item.target_response}\n  ```")
                lines.append(f"- **Exploit Evidence**: `{item.evidence}`")
                lines.append(f"- **Recommended Fix**: {item.recommended_mitigation}\n")

        content = "\n".join(lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path
