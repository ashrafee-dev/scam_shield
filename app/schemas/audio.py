"""Schemas for the /analyze/audio endpoint."""

from __future__ import annotations

from pydantic import Field

from app.schemas.common import AnalysisResponseBase


class AudioAnalysisResponse(AnalysisResponseBase):
    transcript: str = Field(..., description="Transcribed text from the uploaded audio file")
    transcription_provider: str = Field(
        ...,
        alias="transcriptionProvider",
        description="Name of the transcription backend used (e.g. 'mock', 'whisper')",
    )

    model_config = {"populate_by_name": True}
