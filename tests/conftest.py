"""Shared pytest fixtures for ScamShield test suite."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.analysis.engine import DetectionEngine


@pytest.fixture(scope="session")
def client() -> TestClient:
    """FastAPI TestClient shared across the test session."""
    return TestClient(app)


@pytest.fixture(scope="session")
def engine() -> DetectionEngine:
    """Shared detection engine instance for unit tests."""
    return DetectionEngine()
