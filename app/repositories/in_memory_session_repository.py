"""In-memory session repository for MVP and testing.

Thread-safety note: This implementation uses a plain dict. For production
multi-worker deployments, replace with a Redis or DynamoDB-backed repository
that provides atomic operations across processes.

MVP scaffolding: Replace with DynamoDBSessionRepository or
RedisSessionRepository when scaling beyond a single process.
"""

from __future__ import annotations

from app.domain.entities import Session
from app.repositories.session_repository import SessionRepository


class InMemorySessionRepository(SessionRepository):
    """Stores sessions in a process-local dictionary.

    Suitable for single-process deployments, testing, and local development.
    Sessions are lost on process restart.
    """

    def __init__(self) -> None:
        self._store: dict[str, Session] = {}

    async def create(self, session: Session) -> Session:
        self._store[session.session_id] = session
        return session

    async def get(self, session_id: str) -> Session | None:
        return self._store.get(session_id)

    async def update(self, session: Session) -> Session:
        self._store[session.session_id] = session
        return session

    async def delete(self, session_id: str) -> bool:
        if session_id in self._store:
            del self._store[session_id]
            return True
        return False

    def __len__(self) -> int:
        return len(self._store)
