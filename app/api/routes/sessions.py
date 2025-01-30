"""Session lifecycle endpoints: start, chunk, end."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app.core.dependencies import get_session_manager
from app.schemas.common import AnalysisResponseBase, MatchedSignalSchema
from app.schemas.session import (
    ChunkAnalysisResponse,
    ChunkRequest,
    SessionEndResponse,
    SessionStartRequest,
    SessionStartResponse,
)
from app.services.sessions.manager import SessionAlreadyEndedError, SessionManager, SessionNotFoundError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/session", tags=["Sessions"])


# ------------------------------------------------------------------ Helpers


def _build_manager() -> SessionManager:
    """Build a fresh SessionManager for each request.

    In FastAPI terms, this is a simple factory. For the MVP singleton
    in-memory store, this always returns a manager wrapping the same
    shared repository instance.
    """
    return get_session_manager()


def _result_to_base(result) -> AnalysisResponseBase:
    return AnalysisResponseBase(
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


# ------------------------------------------------------------------ Endpoints


@router.post(
    "/start",
    response_model=SessionStartResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new analysis session",
    description=(
        "Creates a new session for near-real-time scam detection. "
        "Returns a session ID to use with subsequent /chunk and /end calls."
    ),
)
async def start_session(request: SessionStartRequest) -> SessionStartResponse:
    manager = _build_manager()
    session = await manager.start_session(channel=request.channel, metadata=request.metadata)
    logger.info("Session started (id=%s, channel=%s)", session.session_id, session.channel)
    return SessionStartResponse(sessionId=session.session_id, status=session.status.value)


@router.post(
    "/{session_id}/chunk",
    response_model=ChunkAnalysisResponse,
    summary="Submit a text chunk to an active session",
    description=(
        "Appends a text chunk to the session history and runs a rolling analysis "
        "across all cumulative text received so far. Use this for near-real-time "
        "risk updates during an ongoing call."
    ),
)
async def submit_chunk(session_id: str, request: ChunkRequest) -> ChunkAnalysisResponse:
    manager = _build_manager()
    try:
        session, result = await manager.add_chunk(
            session_id=session_id,
            text=request.text,
            metadata=request.metadata,
        )
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except SessionAlreadyEndedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    logger.info(
        "Chunk processed (session=%s, chunk=%d, score=%d)",
        session_id,
        session.processed_chunks,
        result.risk_score,
    )

    return ChunkAnalysisResponse(
        sessionId=session.session_id,
        riskScore=result.risk_score,
        riskLevel=result.risk_level.value,
        categories=result.categories,
        matchedSignals=[
            MatchedSignalSchema(type=s.type, match=s.match, weight=s.weight, reason=s.reason)
            for s in result.matched_signals
        ],
        explanation=result.explanation,
        recommendedAction=result.recommended_action,
        processedChunks=session.processed_chunks,
    )


@router.post(
    "/{session_id}/end",
    response_model=SessionEndResponse,
    summary="End a session and retrieve final analysis",
    description=(
        "Marks the session as ended and returns the final cumulative analysis "
        "across all submitted chunks. The session cannot receive further chunks after this call."
    ),
)
async def end_session(session_id: str) -> SessionEndResponse:
    manager = _build_manager()
    try:
        session, result = await manager.end_session(session_id=session_id)
    except SessionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except SessionAlreadyEndedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    logger.info("Session ended (id=%s, final_score=%d)", session_id, result.risk_score)

    return SessionEndResponse(
        sessionId=session.session_id,
        status=session.status.value,
        finalAnalysis=_result_to_base(result),
    )
