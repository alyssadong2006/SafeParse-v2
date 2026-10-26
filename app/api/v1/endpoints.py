"""Version 1 sanitization API."""
import logging

from fastapi import APIRouter, HTTPException
from playwright.async_api import (
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from app.api.v1.models import (
    BatchSanitizeRequest,
    BatchSanitizeResponse,
    SanitizeError,
    SanitizeFailure,
    SanitizeRequest,
    SanitizeResponse,
)
from app.engine.renderer import UnsafeURLError, render
from app.security.guardrail_model import GuardrailModelError, predict_prompt_injection
from app.services.sanitizer import sanitize_request
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
    try:
        return await sanitize_request(
            request,
            renderer=render,
            predictor=predict_prompt_injection,
            audit_logger=log_audit,
        )
    except UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PlaywrightTimeoutError as exc:
        raise HTTPException(status_code=504, detail="Target page timed out") from exc
    except PlaywrightError as exc:
        raise HTTPException(
            status_code=502,
            detail="Target page could not be rendered",
        ) from exc
    except GuardrailModelError as exc:
        logger.exception("Guardrail model inference failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/sanitize/batch", response_model=BatchSanitizeResponse)
async def sanitize_batch(request: BatchSanitizeRequest):
    """Sanitize up to ten pages, preserving input order and individual failures."""
    results = []
    # Process sequentially to avoid launching ten Chromium processes at once.
    # Each page uses the same URL safeguards, timeout, classifier, and audit path
    # as the single-page endpoint. Cancellation is intentionally not caught.
    for item in request.items:
        try:
            results.append(await sanitize(item))
        except HTTPException as exc:
            results.append(SanitizeFailure(
                url=str(item.url),
                error=SanitizeError(status_code=exc.status_code, detail=exc.detail),
            ))
        except Exception:
            logger.exception("Unexpected batch item sanitization failure")
            results.append(SanitizeFailure(
                url=str(item.url),
                error=SanitizeError(status_code=500, detail="Page could not be sanitized"),
            ))
    return BatchSanitizeResponse(results=results)
