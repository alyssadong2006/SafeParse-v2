"""Structured security audit logging."""
import json
import logging

logger = logging.getLogger("safeparse.security")


def log_audit(url: str, score: float, actions):
    logger.info(json.dumps({
        "event": "sanitize_complete",
        "url": url,
        "threat_score": score,
        "actions": actions,
    }, separators=(",", ":")))
