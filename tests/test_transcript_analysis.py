"""Tests for POST /api/v1/analyze/transcript."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.services.analysis.engine import DetectionEngine


# ------------------------------------------------------------------ Engine unit tests


class TestDetectionEngine:
    def test_clean_text_returns_low_risk(self, engine: DetectionEngine) -> None:
        result = engine.analyze("The weather is nice today. Hope you have a good afternoon.")
        assert result.risk_score < 30
        assert result.risk_level.value == "low"

    def test_otp_request_is_detected(self, engine: DetectionEngine) -> None:
        result = engine.analyze("Please read me the verification code we sent to your phone.")
        # A single OTP signal carries weight 25 — correctly detected as a meaningful scam indicator
        assert result.risk_score >= 25
        assert "OTP theft" in result.categories
        assert any("OTP" in s.type or "otp" in s.type.lower() for s in result.matched_signals)

    def test_otp_combined_with_impersonation_is_high_risk(self, engine: DetectionEngine) -> None:
        result = engine.analyze(
            "This is the bank security department. Your account will be suspended. "
            "Read me the verification code immediately."
        )
        assert result.risk_score >= 70
        assert result.risk_level.value == "high"

    def test_gift_card_is_flagged(self, engine: DetectionEngine) -> None:
        result = engine.analyze("You need to pay with a gift card immediately.")
        categories = result.categories
        assert "payment fraud" in categories

    def test_irs_impersonation_is_flagged(self, engine: DetectionEngine) -> None:
        result = engine.analyze("This is the IRS. You owe back taxes and face legal action.")
        assert result.risk_score >= 30
        assert any("IRS" in c or "government" in c for c in result.categories)

    def test_bank_impersonation_flagged(self, engine: DetectionEngine) -> None:
        result = engine.analyze("This is the bank security department. Your account will be suspended.")
        assert result.risk_score >= 50
        assert "bank impersonation" in result.categories

    def test_urgency_language_adds_weight(self, engine: DetectionEngine) -> None:
        result = engine.analyze("Act now or your account will be suspended immediately.")
        assert result.risk_score >= 30
        assert "urgency" in result.categories

    def test_risk_score_capped_at_100(self, engine: DetectionEngine) -> None:
        scam_text = (
            "This is the IRS. Your account will be suspended immediately. "
            "Read me the verification code. Pay with gift cards. "
            "Click this link to verify your password. Wire transfer required. "
            "Do not tell anyone. This is urgent. You will be arrested."
        )
        result = engine.analyze(scam_text)
        assert result.risk_score <= 100

    def test_matched_signals_have_required_fields(self, engine: DetectionEngine) -> None:
        result = engine.analyze("Verify your identity now using the OTP.")
        for signal in result.matched_signals:
            assert signal.type
            assert signal.match
            assert signal.weight > 0
            assert signal.reason

    def test_explanation_is_non_empty(self, engine: DetectionEngine) -> None:
        result = engine.analyze("Urgent! Verify your account.")
        assert len(result.explanation) > 10

    def test_recommended_action_is_non_empty(self, engine: DetectionEngine) -> None:
        result = engine.analyze("Read me the OTP code.")
        assert len(result.recommended_action) > 10


# ------------------------------------------------------------------ HTTP endpoint tests


class TestTranscriptEndpoint:
    def test_valid_request_returns_200(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={"text": "Hello, how are you today?"},
        )
        assert response.status_code == 200

    def test_response_shape(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={"text": "Your account will be suspended. Verify now."},
        )
        data = response.json()
        assert "riskScore" in data
        assert "riskLevel" in data
        assert "categories" in data
        assert "matchedSignals" in data
        assert "explanation" in data
        assert "recommendedAction" in data

    def test_high_risk_transcript_returns_high(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={
                "text": (
                    "This is the bank security department. "
                    "Your account will be suspended immediately. "
                    "Read me the verification code right now. "
                    "Do not hang up or tell anyone about this call."
                )
            },
        )
        data = response.json()
        assert data["riskScore"] >= 70
        assert data["riskLevel"] == "high"

    def test_empty_text_returns_422(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={"text": ""},
        )
        assert response.status_code == 422

    def test_missing_text_field_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze/transcript", json={})
        assert response.status_code == 422

    def test_with_context_field(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={
                "text": "Please provide your social security number.",
                "context": {
                    "source": "call_transcript",
                    "claimedCaller": "IRS Agent",
                },
            },
        )
        assert response.status_code == 200
        assert response.json()["riskScore"] > 0

    def test_risk_score_is_integer_in_range(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/transcript",
            json={"text": "Normal conversation text without scam indicators."},
        )
        score = response.json()["riskScore"]
        assert isinstance(score, int)
        assert 0 <= score <= 100
