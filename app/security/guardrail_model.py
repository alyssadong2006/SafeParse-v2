"""Transparent aggregate threat scoring (no external model required)."""
from typing import Iterable


def threat_score(hidden_findings: Iterable[dict], heuristic_findings: Iterable[dict], unicode_count: int) -> float:
    hidden = list(hidden_findings)
    heuristic = list(heuristic_findings)
    # Combining independent probabilities avoids exceeding one and lets multiple
    # weak signals build confidence without declaring ordinary hidden UI malicious.
    probabilities = [min(0.8, float(item.get("weight", 0.0))) for item in heuristic]
    if hidden:
        probabilities.append(min(0.45, 0.12 + 0.04 * len(hidden)))
    if unicode_count:
        probabilities.append(min(0.35, 0.12 + 0.02 * unicode_count))
    remaining = 1.0
    for probability in probabilities:
        remaining *= 1.0 - probability
    return round(1.0 - remaining, 3)
