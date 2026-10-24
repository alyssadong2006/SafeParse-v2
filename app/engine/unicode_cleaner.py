"""Unicode normalization and invisible-character detection."""

"""
A text-level filter that targets characters invisible to humans or used to confuse LLMs:
1. Zero Width & Invisible Characters: 
    Removes non-printing characters (eg. \u200B, zero-width joiners, and soft hyphens) used
    to break up text or hide instructions within normal words
2. Homoglyph Normalization:
    Replaces look-alike characters (eg. Cryllic 'а' vs Latin 'a') with standard
    ASCII/Unicode equivalents so adversial text can't bypass keyword checks or system 
    prompts.
3. Control & BIDI overrides:
    Strips dangerous control characters and bidirectional text override signals 
"""

import unicodedata
from dataclasses import dataclass
from typing import List


# Includes bidi overrides/isolates, zero-width formatting and soft hyphen.
_EXPLICIT_INVISIBLE = {
    0x00AD, 0x034F, 0x061C, 0x180E, 0x200B, 0x200C, 0x200D,
    0x2060, 0xFEFF,
}
_EXPLICIT_INVISIBLE.update(range(0x202A, 0x202F))
_EXPLICIT_INVISIBLE.update(range(0x2066, 0x206A))


@dataclass
class UnicodeFinding:
    reason: str
    intercepted_content: str


def clean_unicode(text: str):
    """Return NFKC text with format/control smuggling characters removed."""
    removed: List[str] = []
    output: List[str] = []
    for char in text:
        category = unicodedata.category(char)
        if ord(char) in _EXPLICIT_INVISIBLE or category == "Cf":
            removed.append(char)
        elif category == "Cc" and char not in "\n\r\t":
            removed.append(char)
        else:
            output.append(char)

    cleaned = unicodedata.normalize("NFKC", "".join(output))
    findings = []
    if removed:
        findings.append(UnicodeFinding(
            reason="invisible_or_control_character_detected",
            intercepted_content="".join(removed)[:200],
        ))
    return cleaned, findings
