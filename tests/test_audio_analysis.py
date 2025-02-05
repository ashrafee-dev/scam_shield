"""Tests for POST /api/v1/analyze/audio.

The audio endpoint uses the mock transcription service in the test environment
(ENABLE_MOCK_TRANSCRIPTION defaults to true). Tests verify the full pipeline:
  file upload → mock transcription → analysis engine → response.
"""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient


def _make_fake_audio(size_bytes: int = 1024) -> io.BytesIO:
    """Return a BytesIO object that mimics a small audio file."""
    return io.BytesIO(b"\x00" * size_bytes)


class TestAudioEndpoint:
    def test_valid_wav_upload_returns_200(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("test.wav", audio, "audio/wav")},
        )
        assert response.status_code == 200

    def test_response_contains_transcript(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("test.wav", audio, "audio/wav")},
        )
        data = response.json()
        assert "transcript" in data
        assert len(data["transcript"]) > 0

    def test_response_contains_transcription_provider(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("test.mp3", audio, "audio/mpeg")},
        )
        data = response.json()
        assert "transcriptionProvider" in data
        assert data["transcriptionProvider"] == "mock"

    def test_mock_transcript_triggers_high_risk(self, client: TestClient) -> None:
        """The mock transcript is a high-risk scam call — score should be high."""
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("call.wav", audio, "audio/wav")},
        )
        data = response.json()
        assert data["riskScore"] >= 50

    def test_response_has_all_required_fields(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("call.wav", audio, "audio/wav")},
        )
        data = response.json()
        required = [
            "riskScore", "riskLevel", "categories", "matchedSignals",
            "explanation", "recommendedAction", "transcript", "transcriptionProvider",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_unsupported_file_type_returns_400(self, client: TestClient) -> None:
        pdf_bytes = io.BytesIO(b"%PDF-1.4 fake pdf content")
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("document.pdf", pdf_bytes, "application/pdf")},
        )
        assert response.status_code == 400

    def test_empty_file_returns_400(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("empty.wav", io.BytesIO(b""), "audio/wav")},
        )
        assert response.status_code == 400

    def test_mp3_content_type_accepted(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("recording.mp3", audio, "audio/mpeg")},
        )
        assert response.status_code == 200

    def test_ogg_content_type_accepted(self, client: TestClient) -> None:
        audio = _make_fake_audio()
        response = client.post(
            "/api/v1/analyze/audio",
            files={"file": ("recording.ogg", audio, "audio/ogg")},
        )
        assert response.status_code == 200
