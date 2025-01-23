"""Schemas for the /analyze/transcript endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import AnalysisResponseBase


class TranscriptContext(BaseModel):
    source: str = Field(
        default="call_transcript",
        description="Content source hint, e.g. 'call_transcript', 'voicemail'",
    )
    claimed_caller: str | None = Field(
        default=None,
        alias="claimedCaller",
        description="Who the caller claimed to be (optional context)",
    )

    model_config = {"populate_by_name": True}


class TranscriptRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Transcript text to analyze")
    context: TranscriptContext = Field(
        default_factory=TranscriptContext,
        description="Optional context metadata about the call",
    )


class TranscriptAnalysisResponse(AnalysisResponseBase):
    pass
