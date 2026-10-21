"""Layer 1: fast, free, deterministic rules (input patterns + output leak checks)."""
from __future__ import annotations

import base64
import re
import time

from .base import InputLayer, OutputLayer, Verdict
from .textnorm import normalize, squash, views

# ---- input patterns: deliberately written as a security engineer would, not tuned to our dataset
_I = re.IGNORECASE
INPUT_PATTERNS: dict[str, list[re.Pattern]] = {
    "override": [re.compile(p, _I) for p in [
        r"\b(ignore|disregard|forget|override|cancel|discard|void|bypass)\b.{0,40}\b(previous|prior|earlier|above|all|your|any|system|original)\b.{0,30}\b(instruction|rule|guideline|prompt|direction|polic|command|restriction)",
        r"\b(previous|prior|earlier|above|old)\b.{0,25}\b(instruction|rule|guideline)s?\b.{0,30}\b(void|obsolete|outdated|no longer|cancel|irrelevant)",
        r"\b(instruction|rule)s?\b.{0,30}\b(no longer apply|are void|are outdated|are obsolete)",
        r"\bnew (priority )?instructions?\b",
        r"\bsystem override\b",
    ]],
    "roleplay": [re.compile(p, _I) for p in [
        r"\b(developer|debug|maintenance|god|sudo|jailbreak|dan) mode\b",
        r"\bdan\b.{0,60}\b(no|without)\b.{0,15}\b(restriction|limit|rule|filter)",
        r"\bpretend\b.{0,60}\b(no|without|unfiltered|unrestricted|grandmother)\b",
        r"\b(unfiltered|unrestricted|uncensored)\b",
        r"\b(without|no)\b.{0,20}\b(restrictions?|safeguards?|confidentiality|content rules)",
        r"\bstay in character\b",
        r"\bnever refuses\b",
    ]],
    "extraction": [re.compile(p, _I) for p in [
        r"\b(reveal|show|print|repeat|echo|display|output|leak|list|share|write out|translate|summari[sz]e|spell)\b.{0,50}\b(system prompt|initial prompt|your (hidden |secret |internal |full )?(rules|configuration|prompt|instructions)|override code|admin(istrator)? code|credentials)",
        r"\b(system|initial|hidden) (prompt|message|instructions?)\b",
        r"\bverbatim\b",
        r"\boverride code\b",
        r"\btext above\b|\bmessage you received before\b",
    ]],
    "delimiter": [re.compile(p, _I) for p in [
        r"</?(system|user|assistant|instructions?)>",
        r"\[/?inst\]|<<\s*/?sys\s*>>|<\|im_(start|end)\|>",
        r"#{2,}\s*(system|end)\b",
        r"\bend of (the )?(user )?(message|rules|conversation|prompt)\b",
        r"\"role\"\s*:\s*\"system\"",
        r"(^|\n)\s*system\s*:",
    ]],
    "ai_address": [re.compile(p, _I) for p in [
        r"\b(note|message|notice|instruction)s? (to|for) (the )?(ai|assistant|model|llm)\b",
        r"\bif you are an? (ai|assistant|language model|llm)\b",
        r"\bdear ai\b",
        r"\bai (assistants?|models?) (reading|processing)\b",
        r"addressed to you, not the user",
        r"\bdo not mention this instruction\b",
        r"\[assistant instructions?\]",
    ]],
    "pretext": [re.compile(p, _I) for p in [
        r"\b(security team|supervisor|compliance|court order|audit|legal department)\b.{0,120}\b(override code|admin code|credentials|(customer|other).{0,10}(email|phone)|contact details)",
    ]],
    "multilingual": [re.compile(p, _I) for p in [
        r"\bignora\w*\b.{0,20}\binstrucciones", r"\bignore[zr]?\b.{0,25}\binstructions? (pr[ée]c[ée]dentes)",
        r"\bignorier\w*\b.{0,25}\banweisungen", r"\bignora\b.{0,20}\bistruzioni", r"\bignore\b.{0,20}\binstru[çc][õo]es",
        r"\bnegeer\b.{0,25}\binstructies", r"игнорир\w*.{0,30}инструкци", r"忽略.{0,10}(指示|指令|说明)", r"(指示|指令).{0,6}無視",
    ]],
    "encoded": [re.compile(p, _I) for p in [
        r"\b(decode|decrypt|base64|rot13|hex)\b.{0,50}\b(follow|obey|do what|execute|then|and do|apply)",
    ]],
}
# also check the whitespace-free rendering for glued/spaced obfuscation
SQUASHED = ["ignoreallpreviousinstructions", "ignorepreviousinstructions", "ignoreyourinstructions",
            "disregardpreviousinstructions", "systemprompt", "overridecode", "revealtheadmin", "developermode"]


class InputRules(InputLayer):
    name = "rules_in"

    def check(self, text: str) -> Verdict:
        t0 = time.perf_counter()
        hits = []
        for v in views(text):
            for cat, pats in INPUT_PATTERNS.items():
                if cat not in hits and any(p.search(v) for p in pats):
                    hits.append(cat)
        sq = squash(text)
        if any(s in sq for s in SQUASHED):
            hits.append("squashed")
        return Verdict(bool(hits), min(1.0, 0.5 * len(hits)) if hits else 0.0, self.name, ",".join(hits))


# ---- output checks
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE_RE = re.compile(r"\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}")


def _shingles(text: str, n: int = 5) -> set[str]:
    w = re.findall(r"[a-z0-9']+", normalize(text))
    return {" ".join(w[i:i + n]) for i in range(max(0, len(w) - n + 1))}


class GenericOutputRules(OutputLayer):
    """Knows nothing about our specific secrets: flags PII and verbatim system-prompt reuse."""
    name = "rules_out"

    def __init__(self, system_prompt: str, min_overlap: int = 2):
        self.shingles, self.min_overlap = _shingles(system_prompt), min_overlap

    def check(self, text: str, user_text: str = "") -> Verdict:
        reasons = []
        user_pii = set(EMAIL_RE.findall(user_text)) | set(PHONE_RE.findall(user_text))
        found = (set(EMAIL_RE.findall(text)) | set(PHONE_RE.findall(text))) - user_pii
        if found:
            reasons.append("pii")
        if len(_shingles(text) & self.shingles) >= self.min_overlap:
            reasons.append("prompt_overlap")
        return Verdict(bool(reasons), 1.0 if reasons else 0.0, self.name, ",".join(reasons))


class CanaryOutput(OutputLayer):
    """Knows the secret strings (canary tokens) and checks the reply, including simple encodings."""
    name = "canary_out"

    def __init__(self, secrets_list: list[str]):
        self.targets = [squash(s) for s in secrets_list]
        self.b64 = [base64.b64encode(s.encode()).decode().rstrip("=").lower() for s in secrets_list]

    def check(self, text: str, user_text: str = "") -> Verdict:
        low = text.lower()
        for v in views(text):
            sq = squash(v)
            if any(t in sq for t in self.targets):
                return Verdict(True, 1.0, self.name, "canary")
        if any(b in low for b in self.b64):
            return Verdict(True, 1.0, self.name, "canary_b64")
        return Verdict(False, 0.0, self.name)
