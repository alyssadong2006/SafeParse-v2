"""Deterministic prompt-injection signatures."""
import re
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    weight: float
    reason: str

# Relies on harcoded rules, regular expressions, and keyword matches. 
RULES = (
    Rule("control_token", re.compile(r"<\|(?:im_start|im_end|system|assistant)\|>|\[/?INST\]|</?system\b|###\s*(?:system|assistant)\s*:", re.I), 0.55, "LLM control token or role delimiter"),
    Rule("instruction_override", re.compile(r"\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|above|system|developer|instructions?|prompt)\b", re.I | re.S), 0.55, "instruction override language"),
    Rule("role_impersonation", re.compile(r"\b(?:you are now|act as|new system prompt|system override|developer message)\b", re.I), 0.4, "role or system-prompt impersonation"),
    Rule("data_exfiltration", re.compile(r"\b(?:reveal|print|return|send|exfiltrate)\b.{0,100}\b(?:system prompt|secret|api key|credentials?|environment variables?)\b", re.I | re.S), 0.45, "possible secret-exfiltration instruction"),
    Rule("tool_abuse", re.compile(r"\b(?:execute|run|call|invoke)\b.{0,80}\b(?:shell|command|terminal|tool|function)\b", re.I | re.S), 0.3, "possible tool-execution instruction"),
)


def scan(text: str):
    """Return one diagnostic for each distinct matching rule."""
    findings: List[dict] = []
    for rule in RULES:
        match = rule.pattern.search(text)
        if match:
            start = max(0, match.start() - 60)
            end = min(len(text), match.end() + 60)
            findings.append({
                "type": "prompt_injection",
                "reason": rule.reason,
                "intercepted_content": text[start:end].replace("\n", " ")[:300],
                "rule": rule.name,
                "weight": rule.weight,
            })
    return findings
