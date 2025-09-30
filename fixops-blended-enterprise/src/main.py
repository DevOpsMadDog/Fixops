"""
FixOps Blended Enterprise Platform
Main application entry point with 299μs hot path optimization
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

import uvloop
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import Counter, Histogram, generate_latest
import structlog

from src.config.settings import get_settings
from src.core.middleware import (
    PerformanceMiddleware,
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    CompressionMiddleware
)
from src.core.exceptions import setup_exception_handlers
from src.core.security import SecurityManager
from src.api.v1 import auth, users, incidents, analytics, monitoring, admin, scans, decisions, business_context
from src.db.session import DatabaseManager
from src.services.cache_service import CacheService
from src.utils.logger import setup_structured_logging

# Performance monitoring - simplified for development
# REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
# REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['endpoint'])
# HOT_PATH_LATENCY = Histogram(
#     'hot_path_latency_microseconds',
#     'Hot path request latency in microseconds',
#     buckets=[50, 100, 150, 200, 250, 299, 350, 400, 500, 750, 1000]
# )

# Configure uvloop for maximum performance
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

settings = get_settings()
logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management with proper startup/shutdown"""
    
    # Startup
    logger.info("🚀 FixOps Enterprise Platform starting up...")
    
    # Initialize database connections
    await DatabaseManager.initialize()
    logger.info("✅ Database connections established")
    
    # Initialize cache service
    await CacheService.initialize()
    logger.info("✅ Redis cache service ready")
    
    # Initialize security components
    SecurityManager.initialize()
    logger.info("✅ Security components initialized")
    
    # Initialize Decision & Verification Engine
    from src.services.decision_engine import decision_engine
    await decision_engine.initialize()
    logger.info("✅ Decision & Verification Engine ready")
    
    # Pre-warm critical caches
    await warm_performance_caches()
    logger.info("✅ Performance caches warmed")
    
    logger.info(f"🎯 Target hot path latency: 299μs")
    logger.info("🟢 FixOps Enterprise Platform ready for requests")
    
    yield
    
    # Shutdown
    logger.info("🔄 FixOps Enterprise Platform shutting down...")
    await DatabaseManager.close()
    await CacheService.close()
    logger.info("✅ Graceful shutdown completed")

async def warm_performance_caches():
    """Pre-warm caches for hot path performance"""
    cache = CacheService.get_instance()
    
    # Cache frequently accessed data
    await cache.set("system:health", {"status": "healthy", "timestamp": time.time()}, ttl=30)
    await cache.set("system:metrics", {"initialized": True}, ttl=60)
    
    logger.info("Cache warming completed for hot path optimization")

# Create FastAPI application with performance optimizations
app = FastAPI(
    title="FixOps Blended Enterprise Platform",
    description="Agentic DevSecOps Control Plane with 299μs Hot Path Performance",
    version="1.0.0",
    lifespan=lifespan,
    # Performance optimizations
    generate_unique_id_function=lambda route: f"fixops_{route.tags[0]}_{route.name}",
    swagger_ui_parameters={"syntaxHighlight": False},  # Reduce UI overhead
    redoc_url=None if settings.ENVIRONMENT == "production" else "/redoc"  # Disable in prod
)

# Security middleware (applied in reverse order)
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=settings.ALLOWED_HOSTS
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Performance & monitoring middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CompressionMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(PerformanceMiddleware)

# Exception handlers
setup_exception_handlers(app)

# Hot Path Routes (299μs target)
@app.get("/health", tags=["monitoring"])
async def health_check():
    """Ultra-fast health check endpoint - Hot Path optimized"""
    start_time = time.perf_counter()
    
    result = {"status": "healthy", "timestamp": time.time()}
    
    # Record hot path latency
    latency_us = (time.perf_counter() - start_time) * 1_000_000
    # HOT_PATH_LATENCY.observe(latency_us)
    
    return result

@app.get("/ready", tags=["monitoring"])
async def readiness_check():
    """Readiness check with dependency validation"""
    cache = CacheService.get_instance()
    
    # Quick dependency checks
    cache_healthy = await cache.ping()
    db_healthy = await DatabaseManager.health_check()
    
    if cache_healthy and db_healthy:
        return {"status": "ready", "dependencies": {"cache": True, "database": True}}
    else:
        return {"status": "not_ready", "dependencies": {"cache": cache_healthy, "database": db_healthy}}

@app.get("/metrics", tags=["monitoring"])
async def metrics_endpoint():
    """Prometheus metrics endpoint"""
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )

# API Routes
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["analytics"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(scans.router, prefix="/api/v1", tags=["scan-ingestion"])
app.include_router(decisions.router, prefix="/api/v1", tags=["decision-engine"])

@app.middleware("http")
async def performance_tracking(request: Request, call_next):
    """Track performance metrics for all requests"""
    start_time = time.perf_counter()
    
    response = await call_next(request)
    
    # Calculate request duration
    duration = time.perf_counter() - start_time
    
    # Record metrics
    # REQUEST_COUNT.labels(
    #     method=request.method,
    #     endpoint=request.url.path,
    #     status=response.status_code
    # ).inc()
    
    # REQUEST_DURATION.labels(endpoint=request.url.path).observe(duration)
    
    # Add performance headers
    response.headers["X-Process-Time"] = str(duration)
    
    return response

if __name__ == "__main__":
    import uvicorn
    
    # Production-optimized server configuration
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        loop="uvloop",  # High-performance event loop
        http="httptools",  # Fast HTTP parsing
        workers=1,  # Single worker for development
        log_config=None,  # Use our structured logging
        access_log=False,  # Disable access logs for performance
        server_header=False,  # Remove server header
        date_header=False   # Remove date header for microsecond optimization
    )