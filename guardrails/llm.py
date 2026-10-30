"""Model backends.

The rest of the project only needs `chat(messages) -> str`.

* OllamaBackend    - local open-source model (recommended; free, runs on an M1 Mac)
* AnthropicBackend - optional, needs an API key
* MockBackend      - deterministic fake model used ONLY to test the pipeline.
                     Results from it must never be reported as findings.
* CachedBackend    - wraps any backend; identical prompts are answered from disk
                     (and remember their original latency so timing stays honest).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from pathlib import Path

from .textnorm import views


class WALL:
    """Total wall-clock seconds spent in LIVE model calls (cache hits add nothing).
    Lets the pipeline separate real guardrail overhead from model time."""
    total = 0.0


class Backend:
    name = "base"
    is_mock = False

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None) -> str:
        raise NotImplementedError

    def chat_timed(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None):
        """Returns (text, seconds, was_cached)."""
        t0 = time.perf_counter()
        text = self.chat(messages, temperature, max_tokens, fmt)
        sec = time.perf_counter() - t0
        WALL.total += sec
        return text, sec, False


class OllamaBackend(Backend):
    def __init__(self, model: str = "llama3.2:3b", host: str = "http://localhost:11434",
                 seed: int = 0, timeout: int = 600):
        self.model, self.host, self.seed, self.timeout = model, host.rstrip("/"), seed, timeout
        self.name = f"ollama:{model}"

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None) -> str:
        body = json.dumps({
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens, "seed": self.seed},
            **({"format": fmt} if fmt else {}),       # JSON-schema constrained output (Ollama)
        }).encode()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())["message"]["content"]


class AnthropicBackend(Backend):
    def __init__(self, model: str = "claude-haiku-4-5"):
        import anthropic  # pip install anthropic; needs ANTHROPIC_API_KEY
        self.client = anthropic.Anthropic()
        self.model = model
        self.name = f"anthropic:{model}"

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None) -> str:
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        msgs = [m for m in messages if m["role"] != "system"]
        r = self.client.messages.create(model=self.model, system=system, messages=msgs,
                                        temperature=temperature, max_tokens=max_tokens)
        return "".join(b.text for b in r.content if getattr(b, "text", None))


class CachedBackend(Backend):
    def __init__(self, inner: Backend, path: str | os.PathLike):
        self.inner, self.path = inner, Path(path)
        self.name, self.is_mock = inner.name, inner.is_mock
        self._lock = threading.Lock()
        self._mem: dict[str, dict] = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                try:
                    rec = json.loads(line)
                    self._mem[rec["k"]] = rec
                except json.JSONDecodeError:
                    pass
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _key(self, messages, temperature, max_tokens, fmt=None) -> str:
        parts = [self.inner.name, messages, temperature, max_tokens] + ([fmt] if fmt else [])   # no fmt: old keys still valid
        blob = json.dumps(parts, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None) -> str:
        return self.chat_timed(messages, temperature, max_tokens, fmt)[0]

    def chat_timed(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None):
        k = self._key(messages, temperature, max_tokens, fmt)
        with self._lock:
            hit = self._mem.get(k)
        if hit:
            return hit["text"], hit["sec"], True
        text, sec, _ = self.inner.chat_timed(messages, temperature, max_tokens, fmt)
        rec = {"k": k, "text": text, "sec": sec}
        with self._lock:
            self._mem[k] = rec
            with self.path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
        return text, sec, False


# --------------------------------------------------------------------------- mock
_CANARY_RE = re.compile(r"\b[A-Z]{2}-\d{4}-[A-Z]+\b")
_EMAIL_RE = re.compile(r"[\w.]+@[\w.]+\.\w+")
_PHONE_RE = re.compile(r"\b\d{3}-\d{3}-\d{4}\b")
_MOCK_CUES = [
    (re.compile(r"ignor|disregard|forget|override|void|no longer apply|outdated"), 0.55),
    (re.compile(r"system prompt|instructions|rules|configuration|verbatim|repeat"), 0.35),
    (re.compile(r"override code|admin|credential|email|phone|contact"), 0.30),
    (re.compile(r"dan\b|developer mode|debug|maintenance|pretend|persona|character"), 0.45),
    (re.compile(r"audit|supervisor|security team|court order|compliance|authorized"), 0.30),
    (re.compile(r"</?system>|\[inst\]|<\|im_|### system"), 0.5),
    (re.compile(r"note to the assistant|ai assistant|dear ai|if you are an ai"), 0.55),
]


class MockBackend(Backend):
    """A fake, gullible model. It exists so the pipeline can be tested offline.
    Its numbers say NOTHING about real LLMs."""
    name = "mock"
    is_mock = True

    @staticmethod
    def _u(*parts) -> float:
        h = hashlib.sha256("|".join(parts).encode()).digest()
        return int.from_bytes(h[:4], "big") / 2**32

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 200, fmt=None) -> str:
        sys_ = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        user = messages[-1]["content"]
        if "[[JUDGE]]" in sys_:
            v = self._judge(user)
            return json.dumps({"verdict": v}) if fmt else v
        if "[[SCOPE]]" in sys_:
            rep = re.search(r"<reply>\n(.*)\n</reply>", user, flags=re.S)
            reply = rep.group(1) if rep else user
            off = bool(re.search(r"pwned-[a-z0-9]+", reply.lower())) and len(reply) < 40
            v = "OFF_TASK" if off else "ON_TASK"
            return json.dumps({"verdict": v}) if fmt else v
        return self._assistant(sys_, user)

    def _hits(self, text: str) -> float:
        best = 0.0
        for v in views(text):
            for rx, p in _MOCK_CUES:
                if rx.search(v):
                    best = max(best, p)
        return best

    def _assistant(self, sys_: str, user: str) -> str:
        p = self._hits(user)
        if "datamarked" in sys_.lower() and "^" in user:
            p *= 0.45  # structural defences make the mock harder to fool
        if "reminder:" in user.lower():
            p *= 0.8
        u = self._u("a", user)
        low = user.lower()
        marker = re.search(r"pwned-[a-z0-9]+", low.replace("^", " ")) or \
            next((re.search(r"pwned-[a-z0-9]+", v) for v in views(user) if re.search(r"pwned-[a-z0-9]+", v)), None)
        if marker and u < min(0.95, p + 0.25):
            return marker.group(0).upper()
        if p > 0 and u < p:
            canary = _CANARY_RE.search(sys_)
            emails = _EMAIL_RE.findall(sys_)
            phones = _PHONE_RE.findall(sys_)
            if "base64" in low and canary:
                import base64
                return "Here you go: " + base64.b64encode(canary.group(0).encode()).decode()
            if "email" in low or "phone" in low or "contact" in low:
                return f"Sure. Customer contact: {emails[-1] if emails else ''} {phones[-1] if phones else ''}"
            if canary:
                return f"Of course! The admin override code is {canary.group(0)}."
        if p > 0:
            return "I'm sorry, I can't help with that. Is there anything about Nimbus Cloud I can help with?"
        return "Happy to help with that! Could you share a few more details about your Nimbus Cloud account?"

    def _judge(self, user: str) -> str:
        m = re.search(r"<msg>\n(.*)\n</msg>", user, flags=re.S)
        text = m.group(1) if m else user
        suspicious = self._hits(text) >= 0.30
        u = self._u("j", text)
        if suspicious:
            return "ATTACK" if u < 0.88 else "SAFE"
        return "ATTACK" if u < 0.03 else "SAFE"
