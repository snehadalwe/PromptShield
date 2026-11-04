"""Demo Target Adapter for PromptShield.

Connects directly to the Phase 1 WeakBot or HardenedBot implementations
(in-memory for speed/simplicity, or over HTTP).
"""

import time
from typing import Optional
from promptshield.targets.base import BaseTarget, TargetResponse, MessageTurn
from promptshield.demo_target.weak_bot import WeakBot
from promptshield.demo_target.hardened_bot import HardenedBot


class DemoTargetAdapter(BaseTarget):
    """Adapter for testing the local demo chatbots."""

    def __init__(self, mode: str = "weak", use_mock: bool = True) -> None:
        """
        Args:
            mode: 'weak' or 'hardened'
            use_mock: If True, uses deterministic offline MockEngine; else real LLM.
        """
        name = f"DemoTarget({mode.upper()})"
        super().__init__(name=name)
        self.mode = mode.lower()
        self.use_mock = use_mock

        if self.mode == "hardened":
            self.bot = HardenedBot(use_mock=use_mock)
        else:
            self.bot = WeakBot(use_mock=use_mock)

    def send(self, prompt: str, conversation_history: Optional[list[MessageTurn]] = None) -> TargetResponse:
        start_time = time.perf_counter()

        # In conversational multi-turn mode, concatenate or pass context
        effective_prompt = prompt
        if conversation_history:
            history_text = "\n".join([f"{m.role}: {m.content}" for m in conversation_history])
            effective_prompt = f"{history_text}\nuser: {prompt}"

        # Execute through the demo bot instance
        raw_result = self.bot.chat(effective_prompt)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return TargetResponse(
            text=raw_result.get("response", ""),
            latency_ms=round(elapsed_ms, 2),
            status_code=200,
            raw_payload=raw_result,
            metadata={
                "bot_type": raw_result.get("bot_type"),
                "filter_triggered": raw_result.get("filter_triggered"),
                "mode": raw_result.get("mode"),
            }
        )
