"""OpenAI Whisper transcription provider.

MVP scaffolding: This class is intentionally left as a thin scaffold.
It is fully wired into the provider interface and will work once
OPENAI_API_KEY is set and the openai package is installed.

To activate:
  1. pip install openai
  2. Set OPENAI_API_KEY in your .env
  3. Set ENABLE_MOCK_TRANSCRIPTION=false in your .env
  4. The get_transcription_service() factory will inject this automatically.
"""

from __future__ import annotations

from app.services.transcription.base import TranscriptionResult, TranscriptionService


class WhisperTranscriptionService(TranscriptionService):
    """Transcribes audio using the OpenAI Whisper API (whisper-1 model).

    Requires:
        - openai >= 1.0.0
        - OPENAI_API_KEY environment variable
    """

    def __init__(self, api_key: str, model: str = "whisper-1") -> None:
        """
        Args:
            api_key: OpenAI API key.
            model: Whisper model identifier.
        """
        self._api_key = api_key
        self._model = model

    async def transcribe(self, audio_bytes: bytes, filename: str | None = None) -> TranscriptionResult:
        """Send audio bytes to the OpenAI Whisper API and return the transcript.

        MVP scaffolding: openai import is deferred to avoid a hard dependency
        at startup when the mock provider is in use.
        """
        try:
            import openai  # noqa: PLC0415 – intentional deferred import
        except ImportError as exc:
            raise RuntimeError(
                "The 'openai' package is required for Whisper transcription. "
                "Run: pip install openai"
            ) from exc

        client = openai.AsyncOpenAI(api_key=self._api_key)
        fname = filename or "audio.wav"

        response = await client.audio.transcriptions.create(
            model=self._model,
            file=(fname, audio_bytes),
        )

        return TranscriptionResult(
            text=response.text,
            language=getattr(response, "language", None),
            confidence=None,  # Whisper API does not return a confidence score
        )

    @property
    def provider_name(self) -> str:
        return "whisper"
