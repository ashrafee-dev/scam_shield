"""Service info endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.config import Settings, get_settings

router = APIRouter(prefix="/api/v1", tags=["Info"])


class ServiceInfoResponse(BaseModel):
    service: str
    version: str
    environment: str
    supported_channels: list[str]
    endpoints: list[str]


@router.get(
    "/info",
    response_model=ServiceInfoResponse,
    summary="Service metadata",
    description="Returns service name, version, supported channels, and available endpoint paths.",
)
async def service_info(settings: Settings = Depends(get_settings)) -> ServiceInfoResponse:
    return ServiceInfoResponse(
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        supported_channels=["transcript", "email", "audio", "session"],
        endpoints=[
            "GET  /health",
            "GET  /api/v1/info",
            "POST /api/v1/analyze/transcript",
            "POST /api/v1/analyze/email",
            "POST /api/v1/analyze/audio",
            "POST /api/v1/session/start",
            "POST /api/v1/session/{session_id}/chunk",
            "POST /api/v1/session/{session_id}/end",
        ],
    )
