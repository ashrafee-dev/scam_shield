"""Schemas for the /analyze/email endpoint."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import AnalysisResponseBase


class EmailRequest(BaseModel):
    subject: str = Field(..., min_length=1, description="Email subject line")
    from_address: str = Field(
        ...,
        alias="fromAddress",
        description="Sender email address",
    )
    body: str = Field(..., min_length=1, description="Email body text (plain text or HTML stripped)")
    links: list[str] = Field(
        default_factory=list,
        description="URLs extracted from the email body",
    )

    model_config = {"populate_by_name": True}


class SenderRiskSchema(BaseModel):
    is_suspicious: bool = Field(..., alias="isSuspicious")
    reasons: list[str]

    model_config = {"populate_by_name": True}


class EmailAnalysisResponse(AnalysisResponseBase):
    sender_risk: SenderRiskSchema | None = Field(
        default=None,
        alias="senderRisk",
        description="Optional sender/domain risk assessment",
    )

    model_config = {"populate_by_name": True}
