"""Public API request and response schemas."""
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl

from config import settings


class SanitizeRequest(BaseModel):
    url: HttpUrl
    timeout_seconds: int = Field(
        default=settings.default_timeout_seconds,
        ge=1,
        le=settings.max_timeout_seconds,
    )
    strict_mode: bool = True


class FlaggedElement(BaseModel):
    type: str
    reason: str
    intercepted_content: str


class SanitizedData(BaseModel):
    clean_text: str
    safe_prompt_payload: str


class SecurityAudit(BaseModel):
    is_threat_detected: bool
    threat_score: float = Field(ge=0.0, le=1.0)
    threat_actions_taken: List[str]
    flagged_elements: List[FlaggedElement]


class Performance(BaseModel):
    execution_time_ms: int


class SanitizeResponse(BaseModel):
    status: Literal["success"] = "success"
    url: str
    data: SanitizedData
    security_audit: SecurityAudit
    performance: Performance
