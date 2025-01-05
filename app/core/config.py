"""Application configuration.

Settings are loaded from environment variables (with .env file support via
python-dotenv). All configuration is centralized here — no os.environ calls
should appear elsewhere in the codebase.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-level settings loaded from environment variables.

    All fields have sensible defaults for local development. Override via
    environment variables or a .env file at the project root.
    """

    # Core
    app_name: str = "ScamShield API"
    app_env: Literal["development", "staging", "production"] = "development"
    app_version: str = "1.0.0"

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    # Transcription
    enable_mock_transcription: bool = True
    openai_api_key: str = ""

    # AWS (placeholder for future DynamoDB/S3 integration)
    aws_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    # File upload limits
    max_audio_file_size_mb: int = 25

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def max_audio_file_size_bytes(self) -> int:
        return self.max_audio_file_size_mb * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings singleton."""
    return Settings()
