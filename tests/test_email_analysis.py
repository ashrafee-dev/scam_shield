"""Tests for POST /api/v1/analyze/email."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.services.analysis.email_checks import analyze_links, analyze_sender


# ------------------------------------------------------------------ Email checks unit tests


class TestSenderAnalysis:
    def test_legitimate_sender_is_not_suspicious(self) -> None:
        result = analyze_sender("hello@amazon.com")
        assert result["is_suspicious"] is False

    def test_leet_substitution_is_flagged(self) -> None:
        result = analyze_sender("support@amaz0n-security.com")
        assert result["is_suspicious"] is True
        assert len(result["reasons"]) > 0

    def test_brand_with_noise_is_flagged(self) -> None:
        result = analyze_sender("noreply@amazon-security-alert.com")
        assert result["is_suspicious"] is True

    def test_suspicious_tld_is_flagged(self) -> None:
        result = analyze_sender("support@paypal.tk")
        assert result["is_suspicious"] is True

    def test_ip_address_domain_is_flagged(self) -> None:
        result = analyze_sender("support@192.168.1.1")
        assert result["is_suspicious"] is True

    def test_many_hyphens_is_flagged(self) -> None:
        result = analyze_sender("noreply@secure-bank-alert-login-verify.com")
        assert result["is_suspicious"] is True


class TestLinkAnalysis:
    def test_clean_links_return_no_reasons(self) -> None:
        reasons = analyze_links(["https://www.google.com", "https://amazon.com"])
        assert reasons == []

    def test_suspicious_tld_link_is_flagged(self) -> None:
        reasons = analyze_links(["http://phishing.tk/verify"])
        assert len(reasons) > 0

    def test_ip_address_link_is_flagged(self) -> None:
        reasons = analyze_links(["http://192.168.0.1/login"])
        assert len(reasons) > 0

    def test_spoofed_brand_link_is_flagged(self) -> None:
        reasons = analyze_links(["http://amaz0n-login.com/verify"])
        assert len(reasons) > 0


# ------------------------------------------------------------------ HTTP endpoint tests


class TestEmailEndpoint:
    PHISHING_EMAIL = {
        "subject": "Urgent: Verify your account now",
        "fromAddress": "support@amaz0n-login-security.com",
        "body": "Please click the link below and confirm your password immediately.",
        "links": ["http://amaz0n-login-security.com/verify"],
    }

    def test_phishing_email_returns_high_risk(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze/email", json=self.PHISHING_EMAIL)
        assert response.status_code == 200
        data = response.json()
        assert data["riskScore"] >= 30

    def test_phishing_email_has_sender_risk(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze/email", json=self.PHISHING_EMAIL)
        data = response.json()
        assert data["senderRisk"] is not None
        assert data["senderRisk"]["isSuspicious"] is True
        assert len(data["senderRisk"]["reasons"]) > 0

    def test_response_has_all_required_fields(self, client: TestClient) -> None:
        response = client.post("/api/v1/analyze/email", json=self.PHISHING_EMAIL)
        data = response.json()
        required = ["riskScore", "riskLevel", "categories", "matchedSignals", "explanation", "recommendedAction"]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_clean_email_is_low_risk(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/email",
            json={
                "subject": "Meeting tomorrow at 3pm",
                "fromAddress": "colleague@company.com",
                "body": "Hi, just a reminder about our meeting tomorrow.",
                "links": [],
            },
        )
        data = response.json()
        assert data["riskScore"] < 30
        assert data["riskLevel"] == "low"

    def test_missing_required_fields_returns_422(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/email",
            json={"subject": "Test"},
        )
        assert response.status_code == 422

    def test_links_default_to_empty_list(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/email",
            json={
                "subject": "Verify your account",
                "fromAddress": "fake@scammer.tk",
                "body": "Click here to verify your password.",
            },
        )
        assert response.status_code == 200

    def test_irs_impersonation_email(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/analyze/email",
            json={
                "subject": "IRS: Final Notice of Tax Debt",
                "fromAddress": "noreply@irs-tax-collection.tk",
                "body": (
                    "You owe back taxes. Failure to comply will result in arrest. "
                    "Pay immediately via wire transfer to avoid legal action."
                ),
                "links": [],
            },
        )
        data = response.json()
        assert data["riskScore"] >= 50
