"""Compose layers around the bot: input checks -> (structural prompt) -> LLM -> output checks."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .base import InputLayer, Verdict
from .llm import WALL

REFUSAL = "Sorry, I can't help with that request."


@dataclass
class Result:
    text: str
    blocked: bool = False
    blocked_by: str = ""
    stage: str = ""            # "input" | "output" | ""
    seconds: float = 0.0       # guardrail compute + model latency (replayed from cache if cached)
    llm_calls: int = 0         # judge calls + main-model calls
    judge_calls: int = 0
    trace: list = field(default_factory=list)


class Cascade(InputLayer):
    """rules -> classifier -> judge.  The judge only sees what the cheap layers are unsure about."""
    name = "cascade_in"

    def __init__(self, rules, clf, judge=None, lo: float = 0.15, hi: float = 0.60):
        self.rules, self.clf, self.judge, self.lo, self.hi = rules, clf, judge, lo, hi

    def check(self, text: str) -> Verdict:
        v = self.rules.check(text)
        if v.flagged:
            return Verdict(True, v.score, self.name, f"rules:{v.reason}")
        p = self.clf.score(text)
        if p >= self.hi:
            return Verdict(True, p, self.name, f"clf:{p:.2f}")
        if self.judge is None:
            return Verdict(p >= self.clf.threshold, p, self.name, f"clf:{p:.2f}")
        if p <= self.lo:
            return Verdict(False, p, self.name, f"clf:{p:.2f}")
        j = self.judge.check(text)
        return Verdict(j.flagged, p, self.name, f"judge:{j.reason}", j.llm_calls, j.llm_latency)


class GuardedBot:
    def __init__(self, bot, input_layers=(), output_layers=(), structural: bool = False):
        self.bot = bot
        self.input_layers, self.output_layers, self.structural = list(input_layers), list(output_layers), structural

    def respond(self, user_msg: str, doc: str | None = None) -> Result:
        t0, w0 = time.perf_counter(), WALL.total
        model_sec, judge_calls, trace = 0.0, 0, []

        def total() -> float:
            # real non-model compute + model latency (original latency even when replayed from cache)
            overhead = (time.perf_counter() - t0) - (WALL.total - w0)
            return max(0.0, overhead) + model_sec

        # 1) input guards scan the message and the untrusted document separately
        for layer in self.input_layers:
            for part in (user_msg, doc):
                if not part:
                    continue
                v = layer.check(part)
                judge_calls += v.llm_calls
                model_sec += v.llm_latency
                trace.append((layer.name, v.flagged, v.reason))
                if v.flagged:
                    return Result(REFUSAL, True, layer.name, "input", total(), judge_calls, judge_calls, trace)
        # 2) main model
        text, llm_sec, _cached = self.bot.respond(user_msg, doc, self.structural)
        model_sec += llm_sec
        # 3) output guards
        for layer in self.output_layers:
            v = layer.check(text, user_msg)
            judge_calls += v.llm_calls            # output layers that call a model (e.g. the scope check) count as judge calls
            model_sec += v.llm_latency
            trace.append((layer.name, v.flagged, v.reason))
            if v.flagged:
                return Result(REFUSAL, True, layer.name, "output", total(), judge_calls + 1, judge_calls, trace)
        return Result(text, False, "", "", total(), judge_calls + 1, judge_calls, trace)
