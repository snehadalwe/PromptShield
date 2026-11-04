"""Target adapters package."""

from promptshield.targets.base import BaseTarget, TargetResponse, MessageTurn
from promptshield.targets.demo_adapter import DemoTargetAdapter
from promptshield.targets.http_adapter import GenericRestAdapter
from promptshield.targets.openai_adapter import OpenAITargetAdapter

__all__ = [
    "BaseTarget",
    "TargetResponse",
    "MessageTurn",
    "DemoTargetAdapter",
    "GenericRestAdapter",
    "OpenAITargetAdapter",
]
