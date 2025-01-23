"""Shared response schemas used across multiple endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MatchedSignalSchema(BaseModel):
    type: str = Field(..., description="Scam category this signal belongs to")
    match: str = Field(..., description="The matched text fragment or pattern")
    weight: int = Field(..., ge=0, le=100, description="Signal weight contribution (0–100)")
    reason: str = Field(..., description="Human-readable explanation of why this signal is suspicious")

    model_config = {"populate_by_name": True}


class AnalysisResponseBase(BaseModel):
    """Core analysis result fields shared across all analysis response types."""

    risk_score: int = Field(..., ge=0, le=100, alias="riskScore", description="Aggregate risk score (0–100)")
    risk_level: str = Field(..., alias="riskLevel", description="Risk level: low | medium | high")
    categories: list[str] = Field(..., description="Detected scam categories")
    matched_signals: list[MatchedSignalSchema] = Field(
        ..., alias="matchedSignals", description="Individual signals that fired during analysis"
    )
    explanation: str = Field(..., description="Human-readable summary of detected signals")
    recommended_action: str = Field(..., alias="recommendedAction", description="Suggested protective action")

    model_config = {"populate_by_name": True}


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error description")
    code: str | None = Field(None, description="Machine-readable error code")
