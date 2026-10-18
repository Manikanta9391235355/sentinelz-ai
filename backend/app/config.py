import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelZ AI — Privacy-First AI Security & Threat Detection Platform"
    TAGLINE: str = "Intelligence Without Exposure"
    THEME: str = "AI Secured: Innovation Without Exposure"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Database
    DATABASE_URL: str = "sqlite:///./sentinelz.db"
    
    # Cryptographic secret for signing session tokens
    SECRET_KEY: str = os.getenv("SENTINELZ_SECRET_KEY", "sentinelz-dev-key-change-in-production-ibm-z-2026")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Privacy Shield & AI Engine Configuration
    # Safe default: External AI is strictly DISABLED out of the box
    AI_PROVIDER_ENABLED: bool = os.getenv("SENTINELZ_AI_ENABLED", "false").lower() in ("true", "1", "yes")
    AI_PROVIDER_TYPE: str = os.getenv("SENTINELZ_AI_PROVIDER", "local_deterministic")  # "local_deterministic" or "external"
    AI_API_KEY: str = os.getenv("SENTINELZ_AI_API_KEY", "")
    AI_MODEL_NAME: str = os.getenv("SENTINELZ_AI_MODEL", "sentinelz-sec-bert-local")
    
    # Request & Ingestion Constraints (Security Defense-in-Depth)
    MAX_REQUEST_SIZE_BYTES: int = 1024 * 1024  # 1MB
    MAX_EVENT_BATCH_SIZE: int = 100
    
    # Demo & Simulation Mode
    DEMO_MODE: bool = True
    
    # CORS Configuration
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]
    
    # Target Platform
    TARGET_PLATFORM: str = "IBM LinuxONE / s390x Compatible"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
