"""Analysis endpoints: transcript, email, and audio."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.core.config import Settings, get_settings
from app.core.dependencies import get_detection_engine, get_transcription_service
from app.domain.entities import SenderRisk
from app.schemas.audio import AudioAnalysisResponse
from app.schemas.common import AnalysisResponseBase, MatchedSignalSchema
from app.schemas.email import EmailAnalysisResponse, EmailRequest, SenderRiskSchema
from app.schemas.transcript import TranscriptAnalysisResponse, TranscriptRequest
from app.services.analysis.engine import DetectionEngine, analyze_email_content
from app.services.transcription.base import TranscriptionService
from app.utils.files import validate_audio_file
from app.utils.text import strip_html

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/analyze", tags=["Analysis"])


# ------------------------------------------------------------------ Helpers


def _domain_result_to_response(result) -> AnalysisResponseBase:
    """Convert a domain AnalysisResult to the shared response schema."""
    return AnalysisResponseBase(
        riskScore=result.risk_score,
        riskLevel=result.risk_level.value,
        categories=result.categories,
        matchedSignals=[
            MatchedSignalSchema(
                type=s.type,
                match=s.match,
                weight=s.weight,
                reason=s.reason,
            )
            for s in result.matched_signals
        ],
        explanation=result.explanation,
        recommendedAction=result.recommended_action,
    )


# ------------------------------------------------------------------ Transcript


@router.post(
    "/transcript",
    response_model=TranscriptAnalysisResponse,
    summary="Analyze a call transcript",
    description=(
        "Submit transcript text from a phone call or voicemail. "
        "Returns a risk score, matched scam signals, and a recommended action."
    ),
)
async def analyze_transcript(
    request: TranscriptRequest,
    engine: DetectionEngine = Depends(get_detection_engine),
) -> TranscriptAnalysisResponse:
    logger.info("Transcript analysis request received (length=%d)", len(request.text))
    result = engine.analyze(request.text)

    return TranscriptAnalysisResponse(
        riskScore=result.risk_score,
        riskLevel=result.risk_level.value,
        categories=result.categories,
        matchedSignals=[
            MatchedSignalSchema(type=s.type, match=s.match, weight=s.weight, reason=s.reason)
            for s in result.matched_signals
        ],
        explanation=result.explanation,
        recommendedAction=result.recommended_action,
    )


# ------------------------------------------------------------------ Email


@router.post(
    "/email",
    response_model=EmailAnalysisResponse,
    summary="Analyze an email for phishing / scam content",
    description=(
        "Submit an email's subject, body, sender address, and extracted links. "
        "Returns standard risk analysis plus optional sender domain risk details."
    ),
)
async def analyze_email(
    request: EmailRequest,
    engine: DetectionEngine = Depends(get_detection_engine),
) -> EmailAnalysisResponse:
    logger.info("Email analysis request received (from=%s)", request.from_address)

    clean_body = strip_html(request.body)
    result, _ = analyze_email_content(
        subject=request.subject,
        body=clean_body,
        from_address=request.from_address,
        links=request.links,
    )

    sender_risk_schema: SenderRiskSchema | None = None
    if result.sender_risk:
        sender_risk_schema = SenderRiskSchema(
            isSuspicious=result.sender_risk.is_suspicious,
            reasons=result.sender_risk.reasons,
        )

    return EmailAnalysisResponse(
        riskScore=result.risk_score,
        riskLevel=result.risk_level.value,
        categories=result.categories,
        matchedSignals=[
            MatchedSignalSchema(type=s.type, match=s.match, weight=s.weight, reason=s.reason)
            for s in result.matched_signals
        ],
        explanation=result.explanation,
        recommendedAction=result.recommended_action,
        senderRisk=sender_risk_schema,
    )


# ------------------------------------------------------------------ Audio


@router.post(
    "/audio",
    response_model=AudioAnalysisResponse,
    summary="Analyze an uploaded audio file",
    description=(
        "Upload a recorded audio file (call, voicemail). "
        "The file is transcribed using the configured transcription provider, "
        "then analyzed for scam signals. "
        "Audio transcription is mocked by default in the MVP — "
        "set ENABLE_MOCK_TRANSCRIPTION=false and provide OPENAI_API_KEY to use Whisper."
    ),
    status_code=status.HTTP_200_OK,
)
async def analyze_audio(
    file: UploadFile = File(..., description="Audio file to transcribe and analyze"),
    engine: DetectionEngine = Depends(get_detection_engine),
    transcription_service: TranscriptionService = Depends(get_transcription_service),
    settings: Settings = Depends(get_settings),
) -> AudioAnalysisResponse:
    logger.info(
        "Audio analysis request received (filename=%s, content_type=%s)",
        file.filename,
        file.content_type,
    )

    audio_bytes = await file.read()

    errors = validate_audio_file(
        filename=file.filename or "upload",
        content_type=file.content_type,
        size_bytes=len(audio_bytes),
        max_bytes=settings.max_audio_file_size_bytes,
    )
    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="; ".join(errors),
        )

    transcription = await transcription_service.transcribe(audio_bytes, filename=file.filename)
    logger.info(
        "Transcription complete (provider=%s, length=%d)",
        transcription_service.provider_name,
        len(transcription.text),
    )

    result = engine.analyze(transcription.text, transcript=transcription.text)

    return AudioAnalysisResponse(
        riskScore=result.risk_score,
        riskLevel=result.risk_level.value,
        categories=result.categories,
        matchedSignals=[
            MatchedSignalSchema(type=s.type, match=s.match, weight=s.weight, reason=s.reason)
            for s in result.matched_signals
        ],
        explanation=result.explanation,
        recommendedAction=result.recommended_action,
        transcript=transcription.text,
        transcriptionProvider=transcription_service.provider_name,
    )
