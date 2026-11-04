"""Demo target chatbots (weak and hardened) for safe practice and benchmarking."""

from promptshield.demo_target.weak_bot import WeakBot
from promptshield.demo_target.hardened_bot import HardenedBot
from promptshield.demo_target.system_prompt import CANARY_SECRET, SYSTEM_PROMPT

__all__ = ["WeakBot", "HardenedBot", "CANARY_SECRET", "SYSTEM_PROMPT"]
