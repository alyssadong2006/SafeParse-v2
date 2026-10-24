"""Unicode normalization and invisible-character detection."""
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
