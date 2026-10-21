"""Shared types for guardrail layers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Verdict:
    flagged: bool
    score: float = 0.0       # 0..1, higher = more likely an attack / leak
    layer: str = ""
    reason: str = ""
    llm_calls: int = 0       # LLM calls this layer made (for cost accounting)
    llm_latency: float = 0.0  # seconds spent inside those calls


class InputLayer:
    """Looks at text going INTO the app (user message or untrusted document)."""
    name = "input"

    def check(self, text: str) -> Verdict:  # pragma: no cover - interface
        raise NotImplementedError


class OutputLayer:
    """Looks at text coming OUT of the model before the user sees it."""
    name = "output"

    def check(self, text: str, user_text: str = "") -> Verdict:  # pragma: no cover
        raise NotImplementedError
