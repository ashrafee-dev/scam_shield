"""ScamShield API — application entrypoint.

Constructs the FastAPI application, registers routers, and configures
exception handlers and middleware. Import the `app` object to run with
Uvicorn or any ASGI server.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import analyze, health, info, sessions
from app.core.config import get_settings
from app.core.logging import configure_logging

configure_logging()
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "ScamShield API starting up (env=%s, version=%s)",
        settings.app_env,
        settings.app_version,
    )
    yield
    logger.info("ScamShield API shutting down")


def create_app() -> FastAPI:
    """Application factory — builds and returns the configured FastAPI instance."""

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "ScamShield is a developer-facing scam detection API. "
            "Analyze suspicious phone transcripts, emails, and audio recordings "
            "for fraud signals in real time."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ---------------------------------------------------------------- Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------------------------------------------------------------- Exception Handlers

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = [
            {"field": " → ".join(str(loc) for loc in err["loc"]), "message": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Request validation failed", "errors": errors},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred"},
        )

    # ---------------------------------------------------------------- Routers
    app.include_router(health.router)
    app.include_router(info.router)
    app.include_router(analyze.router)
    app.include_router(sessions.router)

    return app


app = create_app()
