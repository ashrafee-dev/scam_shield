"""Mock transcription provider for MVP and testing.

Returns a deterministic, realistic-sounding scam transcript so that the full
audio analysis pipeline (upload → transcribe → score) can be exercised end-to-end
without requiring any external service credentials.

MVP scaffolding: Replace with WhisperTranscriptionService for production use.
"""

from __future__ import annotations

from app.services.transcription.base import TranscriptionResult, TranscriptionService

MOCK_TRANSCRIPT = (
    "Hello, this is the bank security department. We have detected suspicious "
    "activity on your account. Your account will be suspended unless you verify "
    "your identity immediately. Please read me the verification code we just sent "
    "to your phone. Do not hang up. This is urgent."
)


class MockTranscriptionService(TranscriptionService):
    """Returns a fixed mock transcript regardless of input audio.

    Useful for:
    - Local development and integration testing
    - CI pipelines that cannot call external APIs
    - Demonstrating the full analysis pipeline

    In production, inject WhisperTranscriptionService instead via the
    get_transcription_service() dependency factory in app/core/dependencies.py.
    """

    def __init__(self, mock_text: str | None = None) -> None:
        """
        Args:
            mock_text: Override the default mock transcript (useful in tests).
        """
        self._mock_text = mock_text or MOCK_TRANSCRIPT

    async def transcribe(self, audio_bytes: bytes, filename: str | None = None) -> TranscriptionResult:
        """Return the mock transcript. Audio bytes are intentionally ignored."""
        return TranscriptionResult(
            text=self._mock_text,
            language="en",
            confidence=1.0,
        )

    @property
    def provider_name(self) -> str:
        return "mock"
