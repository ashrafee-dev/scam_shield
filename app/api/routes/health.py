"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    status: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns `ok` when the service is running. Suitable for load balancer and container health probes.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(status="ok")
