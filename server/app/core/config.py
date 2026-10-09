from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project root path (parent of server/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SERVER_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_ROOT / ".env", SERVER_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "ForenSight Investigation Server"
    APP_VERSION: str = "0.1.0"
    FORENSIGHT_SERVER_HOST: str = "127.0.0.1"
    FORENSIGHT_SERVER_PORT: int = 8000
    FORENSIGHT_ENV: str = "development"
    FORENSIGHT_DEBUG: bool = True

    # Database
    DATABASE_URL: str = "sqlite:///./forensight.db"

    # Local Storage Paths
    EVIDENCE_STORAGE_PATH: str = "./storage/evidence"
    REPORTS_STORAGE_PATH: str = "./storage/reports"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # HMAC-SHA256 Authentication
    # Pre-shared secret for collector → server request signing.
    # Must be set in .env — no hardcoded default for security.
    FORENSIGHT_HMAC_SECRET: str = ""
    # Allowed clock skew for replay protection (seconds)
    HMAC_REPLAY_WINDOW_SECONDS: int = 300

    # AES-256-GCM Evidence Encryption
    # Pre-shared 256-bit key for Collector → Server and at-rest evidence encryption.
    # Must be set in .env (hex or raw 32-byte string) — never hardcoded.
    FORENSIGHT_ENCRYPTION_KEY: str = ""
    # When enabled, ingestion strictly rejects unencrypted storage if key is missing
    FORENSIGHT_REQUIRE_ENCRYPTION: bool = False

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def resolved_evidence_dir(self) -> Path:
        path = Path(self.EVIDENCE_STORAGE_PATH)
        if not path.is_absolute():
            path = SERVER_DIR / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def resolved_reports_dir(self) -> Path:
        path = Path(self.REPORTS_STORAGE_PATH)
        if not path.is_absolute():
            path = SERVER_DIR / path
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
