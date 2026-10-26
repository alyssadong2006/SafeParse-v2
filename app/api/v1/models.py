"""Public API request and response schemas."""
from typing import Annotated, List, Literal, Optional, Union

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


class BatchSanitizeRequest(BaseModel):
    items: List[SanitizeRequest] = Field(min_length=1, max_length=10)


class FlaggedElement(BaseModel):
    type: str
    reason: str
    intercepted_content: str
    text_start: Optional[int] = Field(default=None, ge=0)
    text_end: Optional[int] = Field(default=None, ge=0)


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


class SanitizeError(BaseModel):
    status_code: int
    detail: str


class SanitizeFailure(BaseModel):
    status: Literal["error"] = "error"
    url: str
    error: SanitizeError


BatchSanitizeResult = Annotated[
    Union[SanitizeResponse, SanitizeFailure], Field(discriminator="status")
]


class BatchSanitizeResponse(BaseModel):
    results: List[BatchSanitizeResult]
