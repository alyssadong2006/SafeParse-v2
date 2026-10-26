"""Orchestrate the rendering, inspection, and sanitization pipeline."""
import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Optional

from app.api.v1.models import (
    FlaggedElement,
    Performance,
    SanitizedData,
    SanitizeRequest,
    SanitizeResponse,
    SecurityAudit,
)
from app.engine.renderer import RenderResult
from app.engine.unicode_cleaner import UnicodeFinding, clean_unicode
from app.security.guardrail_model import ModelPrediction, threat_score
from app.security.heuristics import scan
from app.security.prompt_enclosure import enclose
from config import settings

Renderer = Callable[[str, int], Awaitable[RenderResult]]
Predictor = Callable[[str], Optional[ModelPrediction]]
AuditLogger = Callable[[str, float, list[str]], None]


def _inspection_text(clean_text: str, rendered: RenderResult) -> str:
    # Attack language removed with hidden elements still contributes to the audit.
    hidden_text = "\n".join(
        item.get("intercepted_content", "") for item in rendered.findings
    )
    return clean_text + "\n" + hidden_text


def _public_findings(
    clean_text: str,
    rendered: RenderResult,
    unicode_findings: list[UnicodeFinding],
    heuristic_findings: list[dict],
    model_prediction: Optional[ModelPrediction],
) -> list[dict]:
    findings = list(rendered.findings)
    findings.extend(
        {
            "type": "unicode_smuggling",
            "reason": item.reason,
            "intercepted_content": item.intercepted_content,
        }
        for item in unicode_findings
    )
    for item in heuristic_findings:
        text_start = item["text_start"]
        text_end = item["text_end"]
        is_visible = 0 <= text_start < text_end <= len(clean_text)
        findings.append(
            {
                "type": item["type"],
                "reason": item["reason"],
                "intercepted_content": item["intercepted_content"],
                "text_start": text_start if is_visible else None,
                "text_end": text_end if is_visible else None,
            }
        )
    if model_prediction is not None:
        text_start = (
            clean_text.find(model_prediction.intercepted_content)
            if model_prediction.intercepted_content
            else -1
        )
        text_end = (
            text_start + len(model_prediction.intercepted_content)
            if text_start >= 0
            else None
        )
        findings.append(
            {
                "type": "prompt_injection_model",
                "reason": "SafeParse classifier detected prompt injection (confidence {:.1%})".format(
                    model_prediction.injection_probability
                ),
                "intercepted_content": model_prediction.intercepted_content,
                "text_start": text_start if text_start >= 0 else None,
                "text_end": text_end,
            }
        )
    return findings


def _actions(
    rendered: RenderResult,
    unicode_findings: list[UnicodeFinding],
    heuristic_findings: list[dict],
    model_prediction: Optional[ModelPrediction],
) -> list[str]:
    actions = []
    if rendered.findings:
        actions.append("STRIPPED_HIDDEN_CSS_ELEMENTS")
    if unicode_findings:
        actions.append("REMOVED_INVISIBLE_UNICODE_CHARS")
    if heuristic_findings:
        actions.append("FLAGGED_PROMPT_INJECTION_KEYWORDS")
    if model_prediction is not None:
        actions.append("FLAGGED_ML_PROMPT_INJECTION")
    return actions


async def sanitize_request(
    request: SanitizeRequest,
    renderer: Renderer,
    predictor: Predictor,
    audit_logger: AuditLogger,
) -> SanitizeResponse:
    """Run a request through the complete sanitization pipeline."""
    started = time.perf_counter()
    url = str(request.url)
    timeout = min(request.timeout_seconds, settings.max_timeout_seconds)
    rendered = await renderer(url, timeout)

    clean_text, unicode_findings = clean_unicode(rendered.text)
    clean_text = clean_text[: settings.max_output_characters]
    inspection_text = _inspection_text(clean_text, rendered)
    heuristic_findings = scan(inspection_text)
    unicode_count = sum(len(item.intercepted_content) for item in unicode_findings)
    model_prediction = await asyncio.to_thread(predictor, inspection_text)
    if (
        model_prediction is not None
        and model_prediction.injection_probability
        < settings.guardrail_model_flag_threshold
    ):
        model_prediction = None

    score = threat_score(
        rendered.findings,
        heuristic_findings,
        unicode_count,
        model_prediction.injection_probability if model_prediction is not None else None,
    )
    actions = _actions(
        rendered,
        unicode_findings,
        heuristic_findings,
        model_prediction,
    )
    threshold = (
        min(settings.threat_threshold, 0.2)
        if request.strict_mode
        else settings.threat_threshold
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    audit_logger(url, score, actions)

    return SanitizeResponse(
        url=url,
        data=SanitizedData(clean_text=clean_text, safe_prompt_payload=enclose(clean_text)),
        security_audit=SecurityAudit(
            is_threat_detected=score >= threshold,
            threat_score=score,
            threat_actions_taken=actions,
            flagged_elements=[
                FlaggedElement(**item)
                for item in _public_findings(
                    clean_text,
                    rendered,
                    unicode_findings,
                    heuristic_findings,
                    model_prediction,
                )
            ],
        ),
        performance=Performance(execution_time_ms=elapsed_ms),
    )
