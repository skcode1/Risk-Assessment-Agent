
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
ROOT_DIR = BACKEND_DIR.parent


def _resolve_env_files() -> tuple[str, ...]:
    """Resolves .env files deterministically across root and backend directories."""
    custom_env = os.getenv("ENV_FILE")
    if custom_env:
        return (custom_env,)
    candidates = [
        str(ROOT_DIR / ".env"),
        str(BACKEND_DIR / ".env"),
        ".env",
    ]
    return tuple(dict.fromkeys(candidates))


ENV_FILES = _resolve_env_files()

FORBIDDEN_JWT_PLACEHOLDERS = {
    "change-me",
    "secret",
    "change-me-in-production-super-secret-risk-key-1234567890",
    "your-256-bit-secret",
}


class AppSettings(BaseSettings):
    """Core FastAPI application settings."""

    PROJECT_NAME: str = "Cyber Risk Orchestration Engine"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    ALLOWED_ORIGINS: list[str] | str = ["*"]
    SLIDING_WINDOW_SECONDS: int = 3600

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return v
        return ["*"]

    @field_validator("SLIDING_WINDOW_SECONDS", mode="before")
    @classmethod
    def validate_sliding_window(cls, v: Any) -> int:
        if isinstance(v, str):
            return int(v)
        return int(v)

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class DatabaseSettings(BaseSettings):
    """
    PostgreSQL connection pooling and asyncpg driver parameters.
    Supports both POSTGRES_* and DB_* configurations with URL-safe credential escaping.
    """

    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "risk_engine"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: SecretStr = SecretStr("postgres")

    # Connection pool parameters matching app/core/database.py
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # Backwards compatibility and alternative environment names
    POSTGRES_POOL_SIZE: int | None = None
    POSTGRES_MAX_OVERFLOW: int | None = None
    POSTGRES_POOL_TIMEOUT: int | None = None

    DATABASE_URL: str | None = None
    _ASYNC_URI_OVERRIDE: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reconcile_pool_settings(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "POSTGRES_POOL_SIZE" in data and "DB_POOL_SIZE" not in data:
                data["DB_POOL_SIZE"] = data["POSTGRES_POOL_SIZE"]
            if "POSTGRES_MAX_OVERFLOW" in data and "DB_MAX_OVERFLOW" not in data:
                data["DB_MAX_OVERFLOW"] = data["POSTGRES_MAX_OVERFLOW"]
            if "POSTGRES_POOL_TIMEOUT" in data and "DB_POOL_TIMEOUT" not in data:
                data["DB_POOL_TIMEOUT"] = data["POSTGRES_POOL_TIMEOUT"]
        return data

    @property
    def ASYNC_DATABASE_URI(self) -> str:
        """Primary URI attribute consumed by app/core/database.py."""
        if self._ASYNC_URI_OVERRIDE:
            return self._ASYNC_URI_OVERRIDE
        if self.DATABASE_URL:
            if self.DATABASE_URL.startswith("postgresql+psycopg2://"):
                return self.DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
            if self.DATABASE_URL.startswith("postgresql://"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
            return self.DATABASE_URL

        raw_pwd = (
            self.POSTGRES_PASSWORD.get_secret_value()
            if isinstance(self.POSTGRES_PASSWORD, SecretStr)
            else str(self.POSTGRES_PASSWORD)
        )
        encoded_user = quote_plus(self.POSTGRES_USER)
        encoded_pwd = quote_plus(raw_pwd)
        return (
            f"postgresql+asyncpg://{encoded_user}:{encoded_pwd}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def async_url(self) -> str:
        """Alias for ASYNC_DATABASE_URI."""
        return self.ASYNC_DATABASE_URI

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class RedisSettings(BaseSettings):
    """Redis cluster / standalone sliding-window counter settings."""

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: SecretStr | None = None
    REDIS_DB: int = 0
    REDIS_URL: str | None = None

    @property
    def connection_url(self) -> str:
        if self.REDIS_URL:
            return self.REDIS_URL
        if self.REDIS_PASSWORD and self.REDIS_PASSWORD.get_secret_value():
            encoded_pwd = quote_plus(self.REDIS_PASSWORD.get_secret_value())
            return f"redis://:{encoded_pwd}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class OpenSearchSettings(BaseSettings):
    """Threat intelligence and security telemetry search cluster settings."""

    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str | None = "admin"
    OPENSEARCH_PASSWORD: SecretStr = SecretStr("admin")
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_VERIFY_CERTS: bool = False

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class SecuritySettings(BaseSettings):
    """JWT, cryptographic hashing, and RBAC authorization settings."""

    JWT_SECRET_KEY: SecretStr = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=5, le=1440)
    
    # RS256 / JWKS settings (optional, for production)
    JWT_PRIVATE_KEY: SecretStr | None = Field(default=None, description="PEM-encoded RSA private key for RS256 signing")
    JWT_PUBLIC_KEY: SecretStr | None = Field(default=None, description="PEM-encoded RSA public key for RS256 validation (alternative to JWKS)")
    JWT_JWKS_URL: str | None = Field(default=None, description="JWKS endpoint URL for RS256 key rotation")
    JWT_ISSUER: str | None = Field(default=None, description="Expected JWT issuer claim")
    JWT_AUDIENCE: str | None = Field(default=None, description="Expected JWT audience claim")
    
    # Refresh token settings
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def reject_placeholder_secrets(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value().strip()
        if raw in FORBIDDEN_JWT_PLACEHOLDERS or len(raw) < 32:
            raise ValueError(
                "CRITICAL: JWT_SECRET_KEY matches a forbidden placeholder or is shorter than 32 bytes."
            )
        return v

    @property
    def SECRET_KEY(self) -> SecretStr:
        """Backward-compatible alias for JWT_SECRET_KEY."""
        return self.JWT_SECRET_KEY

    @property
    def ALGORITHM(self) -> str:
        """Backward-compatible alias for JWT_ALGORITHM."""
        return self.JWT_ALGORITHM

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class LLMSettings(BaseSettings):
    """Constrained Explainable AI (XAI) runtime settings."""

    LLM_PROVIDER: str = "openai"
    OPENAI_API_KEY: SecretStr = SecretStr("")
    OPENAI_MODEL: str = "gpt-4o"
    ANTHROPIC_API_KEY: SecretStr = SecretStr("")
    ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"
    TEMPERATURE: float = 0.0
    MAX_TOKENS: int = 1024
    LLM_REQUEST_TIMEOUT: float = 30.0
    LLM_MAX_RETRIES: int = 3

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        extra="ignore",
    )


class Settings(BaseSettings):
    """Unified Application Settings."""

    app: AppSettings = Field(default_factory=AppSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    opensearch: OpenSearchSettings = Field(default_factory=OpenSearchSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)

    model_config = SettingsConfigDict(
        env_file=ENV_FILES,
        env_nested_delimiter="__",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
