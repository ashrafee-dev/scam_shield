"""Abstract session repository interface.

The SessionRepository contract decouples session storage from the rest of the
application. The in-memory implementation ships with the MVP; a DynamoDB or
Redis implementation can be dropped in without touching any service or route code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.domain.entities import Session


class SessionRepository(ABC):
    """Abstract persistence layer for Session objects."""

    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Persist a newly created session and return it."""
        ...

    @abstractmethod
    async def get(self, session_id: str) -> Session | None:
        """Retrieve a session by ID. Returns None if not found."""
        ...

    @abstractmethod
    async def update(self, session: Session) -> Session:
        """Persist updated session state."""
        ...

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Remove a session. Returns True if it existed, False otherwise."""
        ...
