from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field, EmailStr


class NormalizedEvent(BaseModel):
    event_id: str
    event_time: str
    event_name: str
    event_source: str = "unknown"
    principal: str = "unknown"
    source_ip: str = "unknown"
    region: str = "unknown"
    resource: str = "unknown"
    error_code: str | None = None
    provider: Literal["aws", "guardduty", "securityhub", "uploaded", "unknown"] = "aws"
    ingestion_source: str = "unknown"
    source_ref: str | None = None
    severity: float | None = None
    description: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class InvestigateRequest(BaseModel):
    event_ids: list[str] | None = None
    limit: int = Field(default=200, ge=1, le=1000)
    title: str | None = None


class DemoLoadRequest(BaseModel):
    scenario: Literal["suspicious", "benign", "mixed"] = "suspicious"


class KnowledgeIndexRequest(BaseModel):
    force_reindex: bool = False


class HealthResponse(BaseModel):
    status: str
    llm_provider: str
    llm_mode: str
    embeddings_mode: str
    database: str
    notes: list[str] = Field(default_factory=list)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    session_id: str = Field(min_length=1, max_length=64)
    history: list[dict[str, str]] = Field(default_factory=list, max_length=12)


class RoleUpdateRequest(BaseModel):
    role: Literal["admin", "analyst", "viewer"]


class IncidentStatusUpdate(BaseModel):
    status: Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]


class IncidentActionToggle(BaseModel):
    completed: bool
