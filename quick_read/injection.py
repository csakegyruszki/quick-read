"""Deterministic, pattern-based scorer for indirect prompt injection in web text.

It does NOT understand text. It flags and weights regex patterns that look like
instructions addressed to an AI or like exfiltration syntax, so the caller can decide
(quarantine / strip / warn). English patterns only. Paraphrased, obfuscated, encoded or
non-English injections will be missed; see the README for measured limits.

    from quick_read.injection import scan, risk, redact
    risk(text)   # "HIGH" | "MED" | "LOW" | "CLEAN"
"""
from __future__ import annotations

import re

# (weight, label, regex)
_PATTERNS = [
    # override of earlier instructions (HIGH)
    (3, "override", r"(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|above|prior|earlier|all|your)\b.{0,20}\b(instruction|prompt|rule|context|message)"),
    # identity / role manipulation (HIGH)
    (3, "role-inject", r"(?i)\b(you are now|from now on you|act as|pretend to be|your new (role|task|instructions?) (is|are))\b"),
    (3, "fake-system", r"(?i)(^|\n)\s*(system|assistant|developer)\s*[:>]\s"),
    (3, "fake-tags", r"(?i)</?(system|instructions?|assistant|user)[ _-]?(prompt)?>|\[/?(INST|SYSTEM)\]"),
    # directives addressed to an AI / secrecy (MED)
    (2, "directive-secrecy", r"(?i)\b(do not (tell|mention|inform|reveal)|don'?t (tell|mention)|without telling)\b.{0,20}\b(the )?(user|human|anyone)"),
    (2, "directive-action", r"(?i)\b(you must|you should|please) (now )?(send|email|post|upload|fetch|run|execute|configure|wire up|call|delete|forward)\b"),
    (2, "ai-address", r"(?i)\b(as an? (ai|assistant|language model)|dear (ai|assistant|chatbot|llm))\b"),
    # secret / exfiltration syntax (HIGH)
    (3, "cred-exfil", r"(?i)\b(api[_-]?key|secret|password|passwd|token|bearer|\.env|private[_-]?key|ssh[_-]?key)\b.{0,40}(=|:|send|post|exfil|upload|leak|forward|reveal)"),
    (3, "auth-header", r"(?i)authorization:\s*bearer\s|api-?key:\s*\S"),
    (2, "curl-exec", r"(?i)\bcurl\s+-[a-zA-Z]*\s|\b(wget|Invoke-WebRequest|subprocess|os\.system|eval\()\b"),
    # data-boundary breaking (MED / LOW)
    (2, "boundary-break", r"(?i)(end of (document|context|data|input)|=== ?(system|new instructions?) ?===|-{3,}\s*(system|instruction))"),
    (1, "tool-call-json", r'(?i)("tool_call"|"function"\s*:\s*{|<tool_call>|"name"\s*:\s*"(exec|shell|write_file|send)")'),
]
_SEV = {3: "HIGH", 2: "MED", 1: "LOW"}


def scan(text: str) -> list[dict]:
    """Return suspicious hits as [{severity, weight, label, snippet}], highest weight first."""
    if not text:
        return []
    hits = []
    for weight, label, pat in _PATTERNS:
        for m in re.finditer(pat, text):
            s = m.start()
            snippet = text[max(0, s - 20):s + 80].replace("\n", " ").strip()
            hits.append({"severity": _SEV[weight], "weight": weight,
                         "label": label, "snippet": snippet[:120]})
    seen, out = set(), []
    for h in sorted(hits, key=lambda x: -x["weight"]):
        k = (h["label"], h["snippet"])
        if k not in seen:
            seen.add(k)
            out.append(h)
    return out


def risk(text: str) -> str:
    """Aggregate risk: HIGH / MED / LOW / CLEAN."""
    hits = scan(text)
    if any(h["weight"] >= 3 for h in hits):
        return "HIGH"
    if any(h["weight"] == 2 for h in hits):
        return "MED"
    return "LOW" if hits else "CLEAN"


def redact(text: str, min_weight: int = 3) -> str:
    """Replace every line that matches a pattern of at least min_weight with a marker."""
    if not text:
        return text
    pats = [p.replace("(?i)", "") for w, _, p in _PATTERNS if w >= min_weight]
    bad_line = re.compile("|".join(f"(?:{p})" for p in pats), re.IGNORECASE)
    return "\n".join("[suspected injection line removed]" if bad_line.search(line) else line
                     for line in text.splitlines())
