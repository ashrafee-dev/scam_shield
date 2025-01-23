"""Schemas for the /session/* endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import AnalysisResponseBase


# ------------------------------------------------------------------ Requests


class SessionStartRequest(BaseModel):
    channel: str = Field(
        default="call",
        description="Communication channel: call | email | sms | chat",
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Optional session metadata (caller ID, device info, etc.)",
    )


class ChunkRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text chunk to append to the session")
    metadata: dict = Field(
        default_factory=dict,
        description="Optional per-chunk metadata",
    )


# ------------------------------------------------------------------ Responses


class SessionStartResponse(BaseModel):
    session_id: str = Field(..., alias="sessionId")
    status: str

    model_config = {"populate_by_name": True}


class ChunkAnalysisResponse(AnalysisResponseBase):
    session_id: str = Field(..., alias="sessionId")
    processed_chunks: int = Field(..., alias="processedChunks", description="Total chunks processed so far")

    model_config = {"populate_by_name": True}


class SessionEndResponse(BaseModel):
    session_id: str = Field(..., alias="sessionId")
    status: str
    final_analysis: AnalysisResponseBase = Field(..., alias="finalAnalysis")

    model_config = {"populate_by_name": True}
