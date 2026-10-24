"""Version 1 sanitization API."""
import asyncio
import logging
import time

from fastapi import APIRouter, HTTPException
from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from config import settings
from app.api.v1.models import (
    FlaggedElement, Performance, SanitizedData, SanitizeRequest,
    SanitizeResponse, SecurityAudit,
)
from app.engine.renderer import UnsafeURLError, render
from app.engine.unicode_cleaner import clean_unicode
from app.security.guardrail_model import (
    GuardrailModelError,
    predict_prompt_injection,
    threat_score,
)
from app.security.heuristics import scan
from app.security.prompt_enclosure import enclose
from app.telemetry.logger import log_audit

router = APIRouter()
logger = logging.getLogger(__name__)

"""
/sanitize endpoint: Accepts a URL and optional timeout, renders the page, sanitizes the
 content, and returns a structured response with sanitized data, security audit, and 
 performance metrics.

Three stages:
1. DOM Cleaning and Normalization:
    Strips out dangerous or hidden elements (eg. <script> tags, hidden CSS, zero-width
    characters, and invisible text) using modules dom_cleaner.py and unicode_cleaner.py.
2. Security & Threat Detection:
    Scans the cleaned text for prompt injection attempts, jailbreaks, or sus heuristics
    using heuristics.py and guardrail_model.py. 
3. Safe Enclosure:
    Wraps the sanitized output in strict safety bounderies (prompt_enclosure.py) so that
    when the text is passed to an LLM, the model treats it strictly as untrusted data rather
    than executable instructions. 
"""
@router.post("/sanitize", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest):
    started = time.perf_counter()
    url = str(request.url)
    timeout = min(request.timeout_seconds, settings.max_timeout_seconds)
    try:
        rendered = await render(url, timeout)
    except UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PlaywrightTimeoutError as exc:
        raise HTTPException(status_code=504, detail="Target page timed out") from exc
    except PlaywrightError as exc:
        raise HTTPException(status_code=502, detail="Target page could not be rendered") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    clean_text, unicode_findings = clean_unicode(rendered.text)
    clean_text = clean_text[:settings.max_output_characters]

    # Attack language removed with hidden elements still contributes to the audit.
    inspection_text = clean_text + "\n" + "\n".join(
        item.get("intercepted_content", "") for item in rendered.findings
    )
    heuristic_findings = scan(inspection_text)
    unicode_count = sum(len(item.intercepted_content) for item in unicode_findings)
    try:
        model_prediction = await asyncio.to_thread(predict_prompt_injection, inspection_text)
    except GuardrailModelError as exc:
        logger.exception("Guardrail model inference failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    positive_model_probability = None
    if (
        model_prediction is not None
        and model_prediction.injection_probability >= settings.guardrail_model_flag_threshold
    ):
        positive_model_probability = model_prediction.injection_probability

    score = threat_score(
        rendered.findings,
        heuristic_findings,
        unicode_count,
        positive_model_probability,
    )

    public_findings = list(rendered.findings)
    public_findings.extend({
        "type": "unicode_smuggling",
        "reason": item.reason,
        "intercepted_content": item.intercepted_content,
    } for item in unicode_findings)
    public_findings.extend({
        "type": item["type"],
        "reason": item["reason"],
        "intercepted_content": item["intercepted_content"],
    } for item in heuristic_findings)
    if positive_model_probability is not None:
        public_findings.append({
            "type": "prompt_injection_model",
            "reason": "Pretrained classifier detected prompt injection (confidence {:.1%})".format(
                positive_model_probability
            ),
            "intercepted_content": model_prediction.intercepted_content,
        })

    actions = []
    if rendered.findings:
        actions.append("STRIPPED_HIDDEN_CSS_ELEMENTS")
    if unicode_findings:
        actions.append("REMOVED_INVISIBLE_UNICODE_CHARS")
    if heuristic_findings:
        actions.append("FLAGGED_PROMPT_INJECTION_KEYWORDS")
    if positive_model_probability is not None:
        actions.append("FLAGGED_ML_PROMPT_INJECTION")

    threshold = min(settings.threat_threshold, 0.2) if request.strict_mode else settings.threat_threshold
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    log_audit(url, score, actions)
    return SanitizeResponse(
        url=url,
        data=SanitizedData(clean_text=clean_text, safe_prompt_payload=enclose(clean_text)),
        security_audit=SecurityAudit(
            is_threat_detected=score >= threshold,
            threat_score=score,
            threat_actions_taken=actions,
            flagged_elements=[FlaggedElement(**item) for item in public_findings],
        ),
        performance=Performance(execution_time_ms=elapsed_ms),
    )
