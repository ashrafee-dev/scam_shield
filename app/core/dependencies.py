"""FastAPI dependency providers.

All injectable services are defined here. Routes import from this module
instead of instantiating services directly, which makes testing and
future DI framework adoption straightforward.
"""

from __future__ import annotations

from functools import lru_cache

from app.core.config import Settings, get_settings
from app.repositories.in_memory_session_repository import InMemorySessionRepository
from app.repositories.session_repository import SessionRepository
from app.services.analysis.engine import DetectionEngine
from app.services.sessions.manager import SessionManager
from app.services.transcription.base import TranscriptionService
from app.services.transcription.mock import MockTranscriptionService
from app.services.transcription.whisper import WhisperTranscriptionService


# ------------------------------------------------------------------ Singletons
# These are module-level singletons for the MVP in-memory implementation.
# In a multi-worker production setup, the session repository would be backed
# by Redis or DynamoDB and instantiated per-request or per-worker.

_session_repository = InMemorySessionRepository()
_detection_engine = DetectionEngine()


# ------------------------------------------------------------------ Factories


def get_detection_engine() -> DetectionEngine:
    """Return the shared detection engine instance."""
    return _detection_engine


def get_session_repository() -> SessionRepository:
    """Return the session repository.

    MVP scaffolding: Returns an in-memory repository. To use DynamoDB or Redis,
    instantiate the appropriate repository class here and return it.
    """
    return _session_repository


def get_session_manager(
    repo: SessionRepository | None = None,
    engine: DetectionEngine | None = None,
) -> SessionManager:
    """Build a SessionManager with injected dependencies."""
    return SessionManager(
        repository=repo or get_session_repository(),
        engine=engine or get_detection_engine(),
    )


def get_transcription_service(settings: Settings | None = None) -> TranscriptionService:
    """Return the appropriate transcription service based on configuration.

    When ENABLE_MOCK_TRANSCRIPTION=true (default), returns MockTranscriptionService.
    When false and OPENAI_API_KEY is set, returns WhisperTranscriptionService.
    """
    cfg = settings or get_settings()

    if cfg.enable_mock_transcription or not cfg.openai_api_key:
        return MockTranscriptionService()

    return WhisperTranscriptionService(api_key=cfg.openai_api_key)
