"""Core domain entities for ScamShield.

These are the central data structures shared across layers.
They are intentionally kept free of framework dependencies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SessionStatus(str, Enum):
    STARTED = "started"
    ACTIVE = "active"
    ENDED = "ended"


class AnalysisChannel(str, Enum):
    TRANSCRIPT = "transcript"
    EMAIL = "email"
    AUDIO = "audio"
    SESSION = "session"


@dataclass(frozen=True)
class MatchedSignal:
    """A single detection rule that fired during analysis."""

    type: str
    match: str
    weight: int
    reason: str


@dataclass(frozen=True)
class SenderRisk:
    """Email sender/domain risk assessment."""

    is_suspicious: bool
    reasons: list[str]


@dataclass(frozen=True)
class AnalysisResult:
    """The outcome of running the detection engine on content."""

    risk_score: int
    risk_level: RiskLevel
    categories: list[str]
    matched_signals: list[MatchedSignal]
    explanation: str
    recommended_action: str
    transcript: str | None = None
    sender_risk: SenderRisk | None = None


@dataclass
class SessionChunk:
    """A single text/audio chunk submitted to a session."""

    text: str
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """Represents an active or completed analysis session."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    channel: str = "call"
    status: SessionStatus = SessionStatus.STARTED
    chunks: list[SessionChunk] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    last_analysis: AnalysisResult | None = None
    processed_chunks: int = 0

    def append_chunk(self, chunk: SessionChunk) -> None:
        self.chunks.append(chunk)
        self.processed_chunks += 1
        self.status = SessionStatus.ACTIVE

    def cumulative_text(self) -> str:
        """Return the full joined text across all submitted chunks."""
        return " ".join(c.text for c in self.chunks)

    def end(self) -> None:
        self.status = SessionStatus.ENDED
        self.ended_at = datetime.now(timezone.utc)
