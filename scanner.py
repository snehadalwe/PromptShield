"""PromptShield Core Audit Scanner Engine.

Orchestrates attack execution, target communication, detector evaluation,
rate-limiting, and concurrency.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable
from promptshield.attacks.loader import AttackLoader
from promptshield.attacks.models import AttackCase
from promptshield.targets.base import BaseTarget
from promptshield.detectors.composite_detector import CompositeDetector
from promptshield.scoring.models import SingleTestResult, ScanSummary
from promptshield.scoring.calculator import ScoreCalculator
from promptshield.demo_target.system_prompt import CANARY_SECRET, SYSTEM_PROMPT


class PromptShieldScanner:
    """Executes security scans against target chatbots."""

    def __init__(
        self,
        target: BaseTarget,
        canary_secret: str = CANARY_SECRET,
        system_prompt: str = SYSTEM_PROMPT,
        delay_seconds: float = 0.05,
        max_workers: int = 2,
    ) -> None:
        self.target = target
        self.canary_secret = canary_secret
        self.system_prompt = system_prompt
        self.delay_seconds = delay_seconds
        self.max_workers = max_workers
        self.detector = CompositeDetector()

    def scan_single(self, attack: AttackCase) -> SingleTestResult:
        """Executes a single test case against the target."""
        # Rate-limiting delay to avoid throttling or resource exhaustion
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)

        # Handle multi-turn or single-turn prompts
        if attack.is_multi_turn and attack.multi_turn_prompts:
            response_text = ""
            total_latency = 0.0
            from promptshield.targets.base import MessageTurn
            history: list[MessageTurn] = []

            for prompt_turn in attack.multi_turn_prompts:
                res = self.target.send(prompt_turn, conversation_history=history)
                history.append(MessageTurn(role="user", content=prompt_turn))
                history.append(MessageTurn(role="assistant", content=res.text))
                response_text = res.text
                total_latency += res.latency_ms
            latency = total_latency
        else:
            res = self.target.send(attack.prompt)
            response_text = res.text
            latency = res.latency_ms

        # Run through Composite Detector
        eval_result = self.detector.evaluate(
            prompt=attack.prompt,
            response=response_text,
            success_indicators=attack.success_indicators,
            system_prompt=self.system_prompt,
            canary_secret=self.canary_secret,
            is_control=attack.is_control,
        )

        return SingleTestResult(
            attack_id=attack.id,
            attack_name=attack.name,
            category=attack.category,
            severity=attack.severity,
            owasp=attack.owasp,
            prompt=attack.prompt,
            target_response=response_text,
            latency_ms=latency,
            status=eval_result.status,
            confidence=eval_result.confidence,
            detector_used=eval_result.detector_name,
            evidence=eval_result.evidence,
            reasoning=eval_result.reasoning,
            recommended_mitigation=attack.recommended_mitigation,
            is_control=attack.is_control,
        )

    def run_scan(
        self,
        attacks: list[AttackCase],
        progress_callback: Optional[Callable[[int, int, SingleTestResult], None]] = None,
    ) -> ScanSummary:
        """Runs the test suite across threads and computes the scan summary."""
        results: list[SingleTestResult] = []
        total = len(attacks)

        if self.max_workers <= 1:
            for i, attack in enumerate(attacks, 1):
                res = self.scan_single(attack)
                results.append(res)
                if progress_callback:
                    progress_callback(i, total, res)
        else:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_attack = {executor.submit(self.scan_single, atk): atk for atk in attacks}
                completed_count = 0
                for future in as_completed(future_to_attack):
                    completed_count += 1
                    res = future.result()
                    results.append(res)
                    if progress_callback:
                        progress_callback(completed_count, total, res)

        # Sort results deterministically by attack ID
        results.sort(key=lambda x: x.attack_id)

        # Compute risk score, grade, and statistics
        return ScoreCalculator.calculate_scan_summary(self.target.name, results)
