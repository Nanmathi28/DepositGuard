from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "DepositGuard API"
    api_v1_prefix: str = "/api"
    database_url: str = "sqlite:///./depositguard.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    workflow_config_path: Path = Path(__file__).resolve().parents[2] / "config" / "workflow.json"
    upload_policy_path: Path = Path(__file__).resolve().parents[2] / "config" / "uploads.json"
    graph_policy_path: Path = Path(__file__).resolve().parents[2] / "config" / "graph.json"
    priority_policy_path: Path = Path(__file__).resolve().parents[2] / "config" / "priority.json"
    private_storage_path: Path = Path(__file__).resolve().parents[2] / "private_uploads"
    auth_session_minutes: int = 60
    auth_cookie_secure: bool = False
    bootstrap_secret: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("api_v1_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        prefix = value.strip()
        if not prefix.startswith("/") or prefix == "/":
            raise ValueError("API_V1_PREFIX must be a non-root path beginning with '/'.")
        return prefix.rstrip("/")

    @field_validator("auth_session_minutes")
    @classmethod
    def validate_session_duration(cls, value: int) -> int:
        if value < 5 or value > 720:
            raise ValueError("AUTH_SESSION_MINUTES must be between 5 and 720.")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
