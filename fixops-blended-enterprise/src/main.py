"""Application factory for FixOps blended backend."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.v1 import router as api_router
from src.config.settings import get_settings
from src.core.middleware import PerformanceMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from src.services.feeds_service import FeedsService

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    scheduler_task: asyncio.Task | None = None
    if settings.FIXOPS_SCHED_ENABLED:
        async def _run_scheduler() -> None:
            await FeedsService.scheduler(settings, settings.FIXOPS_SCHED_INTERVAL_HOURS)

        scheduler_task = asyncio.create_task(_run_scheduler())
    try:
        yield
    finally:
        if scheduler_task:
            scheduler_task.cancel()
            with suppress(asyncio.CancelledError):
                await scheduler_task


def create_app() -> FastAPI:
    settings = get_settings()
    if settings.ENVIRONMENT.lower() == "production" and not settings.FIXOPS_ALLOWED_ORIGINS:
        logger.error("FIXOPS_ALLOWED_ORIGINS must be configured in production mode")
        raise RuntimeError("FIXOPS_ALLOWED_ORIGINS must be configured in production mode")

    app = FastAPI(title="FixOps Blended Enterprise", version="2.0.0", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(PerformanceMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.FIXOPS_ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )

    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()

