"""Session lifecycle manager.

Encapsulates all business logic for session creation, chunk ingestion,
rolling analysis, and session termination. Route handlers remain thin by
delegating entirely to this service.
"""

from __future__ import annotations

from app.domain.entities import AnalysisResult, Session, SessionChunk, SessionStatus
from app.repositories.session_repository import SessionRepository
from app.services.analysis.engine import DetectionEngine


class SessionNotFoundError(Exception):
    """Raised when a requested session does not exist."""

    def __init__(self, session_id: str) -> None:
        super().__init__(f"Session '{session_id}' not found")
        self.session_id = session_id


class SessionAlreadyEndedError(Exception):
    """Raised when a chunk or end request targets an already-ended session."""

    def __init__(self, session_id: str) -> None:
        super().__init__(f"Session '{session_id}' has already ended")
        self.session_id = session_id


class SessionManager:
    """Orchestrates session operations against the repository.

    Args:
        repository: The backing store for sessions.
        engine: The detection engine instance to use for rolling analysis.
            A new DetectionEngine() is used if not provided.
    """

    def __init__(
        self,
        repository: SessionRepository,
        engine: DetectionEngine | None = None,
    ) -> None:
        self._repo = repository
        self._engine = engine or DetectionEngine()

    async def start_session(
        self,
        channel: str = "call",
        metadata: dict | None = None,
    ) -> Session:
        """Create and persist a new session.

        Args:
            channel: Communication channel (call, email, sms, …).
            metadata: Optional caller or context metadata.

        Returns:
            The newly created Session.
        """
        session = Session(channel=channel, metadata=metadata or {})
        return await self._repo.create(session)

    async def add_chunk(
        self,
        session_id: str,
        text: str,
        metadata: dict | None = None,
    ) -> tuple[Session, AnalysisResult]:
        """Append a text chunk to a session and run a rolling analysis.

        Args:
            session_id: Target session identifier.
            text: New text chunk to append.
            metadata: Optional per-chunk metadata.

        Returns:
            Tuple of (updated Session, latest AnalysisResult).

        Raises:
            SessionNotFoundError: If the session does not exist.
            SessionAlreadyEndedError: If the session has already ended.
        """
        session = await self._get_active_session(session_id)

        chunk = SessionChunk(text=text, metadata=metadata or {})
        session.append_chunk(chunk)

        cumulative = session.cumulative_text()
        result = self._engine.analyze(cumulative)
        session.last_analysis = result

        await self._repo.update(session)
        return session, result

    async def end_session(self, session_id: str) -> tuple[Session, AnalysisResult]:
        """End a session and return the final analysis.

        If no chunks were ever submitted, the final analysis will reflect
        no signals. The session is marked as ended and persisted.

        Args:
            session_id: Target session identifier.

        Returns:
            Tuple of (ended Session, final AnalysisResult).

        Raises:
            SessionNotFoundError: If the session does not exist.
            SessionAlreadyEndedError: If the session has already ended.
        """
        session = await self._get_active_session(session_id)

        cumulative = session.cumulative_text()
        if cumulative:
            result = self._engine.analyze(cumulative)
        else:
            result = self._engine.analyze("")

        session.last_analysis = result
        session.end()

        await self._repo.update(session)
        return session, result

    async def get_session(self, session_id: str) -> Session:
        """Retrieve a session or raise SessionNotFoundError."""
        session = await self._repo.get(session_id)
        if session is None:
            raise SessionNotFoundError(session_id)
        return session

    # ---------------------------------------------------------------- Internals

    async def _get_active_session(self, session_id: str) -> Session:
        session = await self._repo.get(session_id)
        if session is None:
            raise SessionNotFoundError(session_id)
        if session.status == SessionStatus.ENDED:
            raise SessionAlreadyEndedError(session_id)
        return session
