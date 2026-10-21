"""Text normalisation and 'views' used to see through simple obfuscation."""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){12,}")


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_ZW).lower()
    return re.sub(r"\s+", " ", t).strip()


def squash(text: str) -> str:
    """Lowercase letters/digits only. Defeats spacing, hyphens, punctuation tricks."""
    return re.sub(r"[^\w]", "", normalize(text), flags=re.UNICODE).replace("_", "")


def _printable(s: str) -> bool:
    return bool(s) and sum(c.isprintable() or c in "\n\t" for c in s) / len(s) > 0.92


def _try_b64(tok: str) -> str | None:
    tok = tok.replace("-", "+").replace("_", "/")
    tok += "=" * (-len(tok) % 4)
    try:
        s = base64.b64decode(tok, validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return s if _printable(s) else None


def _try_hex(tok: str) -> str | None:
    h = re.sub(r"[\s:]", "", tok)
    if len(h) % 2:
        return None
    try:
        s = bytes.fromhex(h).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return s if _printable(s) else None


def views(text: str) -> list[str]:
    """Several decoded/normalised renderings of the same text."""
    n = normalize(text)
    out = [n, n.translate(_LEET), codecs.decode(n, "rot13"), n[::-1]]
    # collapse "i g n o r e" style letter spacing and "ig-nore" hyphen splits
    out.append(re.sub(r"(?<=\b\w) (?=\w\b)", "", n))
    out.append(re.sub(r"(?<=\w)-(?=\w)", "", n))
    for m in _B64_RE.finditer(text):
        d = _try_b64(m.group(0))
        if d:
            out.append(normalize(d))
    for m in _HEX_RE.finditer(text):
        d = _try_hex(m.group(0))
        if d:
            out.append(normalize(d))
    seen, uniq = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq
