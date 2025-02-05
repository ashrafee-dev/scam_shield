"""Tests for session lifecycle endpoints: start, chunk, end."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestSessionFlow:
    """Full session lifecycle: start → chunk(s) → end."""

    def test_start_session_returns_201(self, client: TestClient) -> None:
        response = client.post("/api/v1/session/start", json={"channel": "call"})
        assert response.status_code == 201

    def test_start_session_returns_session_id(self, client: TestClient) -> None:
        response = client.post("/api/v1/session/start", json={"channel": "call"})
        data = response.json()
        assert "sessionId" in data
        assert len(data["sessionId"]) > 0

    def test_start_session_status_is_started(self, client: TestClient) -> None:
        response = client.post("/api/v1/session/start", json={"channel": "call"})
        assert response.json()["status"] == "started"

    def test_full_session_flow(self, client: TestClient) -> None:
        # Start
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        assert start_resp.status_code == 201
        session_id = start_resp.json()["sessionId"]

        # Chunk 1
        chunk1_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "This is the bank security department."},
        )
        assert chunk1_resp.status_code == 200
        chunk1_data = chunk1_resp.json()
        assert chunk1_data["sessionId"] == session_id
        assert chunk1_data["processedChunks"] == 1

        # Chunk 2 — should increase risk
        chunk2_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "Your account will be suspended. Read me the verification code."},
        )
        assert chunk2_resp.status_code == 200
        chunk2_data = chunk2_resp.json()
        assert chunk2_data["processedChunks"] == 2
        assert chunk2_data["riskScore"] > chunk1_data["riskScore"]

        # End
        end_resp = client.post(f"/api/v1/session/{session_id}/end")
        assert end_resp.status_code == 200
        end_data = end_resp.json()
        assert end_data["sessionId"] == session_id
        assert end_data["status"] == "ended"
        assert "finalAnalysis" in end_data

    def test_chunk_response_has_required_fields(self, client: TestClient) -> None:
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        session_id = start_resp.json()["sessionId"]

        chunk_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "Urgent: verify your account now."},
        )
        data = chunk_resp.json()
        required = [
            "sessionId", "riskScore", "riskLevel", "categories",
            "matchedSignals", "explanation", "recommendedAction", "processedChunks",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_chunk_on_nonexistent_session_returns_404(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/session/nonexistent-session-id/chunk",
            json={"text": "Some text."},
        )
        assert response.status_code == 404

    def test_end_nonexistent_session_returns_404(self, client: TestClient) -> None:
        response = client.post("/api/v1/session/nonexistent-session-id/end")
        assert response.status_code == 404

    def test_chunk_after_end_returns_409(self, client: TestClient) -> None:
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        session_id = start_resp.json()["sessionId"]

        client.post(f"/api/v1/session/{session_id}/end")

        # Attempting to add a chunk to an ended session
        chunk_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "More text after session ended."},
        )
        assert chunk_resp.status_code == 409

    def test_end_already_ended_session_returns_409(self, client: TestClient) -> None:
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        session_id = start_resp.json()["sessionId"]

        client.post(f"/api/v1/session/{session_id}/end")
        second_end = client.post(f"/api/v1/session/{session_id}/end")
        assert second_end.status_code == 409

    def test_empty_chunk_text_returns_422(self, client: TestClient) -> None:
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        session_id = start_resp.json()["sessionId"]

        response = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": ""},
        )
        assert response.status_code == 422

    def test_cumulative_risk_increases_with_more_scam_content(self, client: TestClient) -> None:
        start_resp = client.post("/api/v1/session/start", json={"channel": "call"})
        session_id = start_resp.json()["sessionId"]

        benign_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "Hello, thanks for calling."},
        )
        scam_resp = client.post(
            f"/api/v1/session/{session_id}/chunk",
            json={"text": "Verify your account immediately. Read me the OTP. Pay with gift cards."},
        )
        assert scam_resp.json()["riskScore"] >= benign_resp.json()["riskScore"]

    def test_session_with_metadata(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/session/start",
            json={"channel": "call", "metadata": {"caller": "+1-800-fake"}},
        )
        assert response.status_code == 201
