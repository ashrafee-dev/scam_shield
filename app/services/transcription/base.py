"""Abstract base for transcription providers.

Any concrete transcription service must implement TranscriptionService.
This decouples the audio analysis route from the specific provider (mock,
OpenAI Whisper, AWS Transcribe, etc.) and enables clean dependency injection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class TranscriptionResult:
    """Container for a transcription response."""

    def __init__(self, text: str, language: str | None = None, confidence: float | None = None) -> None:
        self.text = text
        self.language = language
        self.confidence = confidence

    def __repr__(self) -> str:
        return f"TranscriptionResult(text={self.text!r}, language={self.language!r})"


class TranscriptionService(ABC):
    """Protocol for all audio transcription backends.

    Implementations must be async-friendly: transcribe() is async to support
    both synchronous mocks and real network-bound providers without blocking.
    """

    @abstractmethod
    async def transcribe(self, audio_bytes: bytes, filename: str | None = None) -> TranscriptionResult:
        """Transcribe audio bytes to text.

        Args:
            audio_bytes: Raw audio file bytes.
            filename: Original filename hint (used by some providers for format detection).

        Returns:
            TranscriptionResult with at minimum a `text` field populated.
        """
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier (e.g. 'mock', 'whisper')."""
        ...
