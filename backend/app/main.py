from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.config import settings
from backend.app.database import engine, Base, SessionLocal
import backend.app.models  # Ensures all models are registered
from backend.app.services.seeder import seed_database

# Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.events import router as events_router
from backend.app.api.findings import router as findings_router
from backend.app.api.privacy import router as privacy_router
from backend.app.api.audit import router as audit_router
from backend.app.api.users import router as users_router
from backend.app.api.metrics import router as metrics_router
from backend.app.api.health import router as health_router
from backend.app.api.settings import router as settings_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database schema on startup
    Base.metadata.create_all(bind=engine)
    # Seed initial demo state if database is empty
    db = SessionLocal()
    try:
        seed_database(db, force=False)
    finally:
        db.close()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SentinelZ AI — Privacy-First AI Security & Threat Detection Platform for IBM LinuxONE",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Request size limitation middleware (Reject payloads > 1MB)
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_REQUEST_SIZE_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": f"Payload exceeds maximum allowed limit of {settings.MAX_REQUEST_SIZE_BYTES} bytes."}
        )
    return await call_next(request)

# Safe global exception handler to avoid leaking internal stack traces
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    import logging
    logging.getLogger("sentinelz").error(f"Unhandled error processing {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Correlation logged for administrator review."}
    )

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(events_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(privacy_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(metrics_router, prefix=settings.API_V1_STR)
app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(settings_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "tagline": settings.TAGLINE,
        "theme": settings.THEME,
        "version": settings.VERSION,
        "target_platform": settings.TARGET_PLATFORM,
        "status": "online",
        "docs": "/api/docs",
        "privacy_shield_default": "ACTIVE_ZERO_LEAKAGE"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
