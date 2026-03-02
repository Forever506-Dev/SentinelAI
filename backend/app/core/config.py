"""
Application Configuration

Central configuration management using Pydantic Settings.
All values can be overridden via environment variables or .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # --- Application ---
    APP_NAME: str = "SentinelAI"
    VERSION: str = "0.1.0"
    DEBUG: bool = True
    SECRET_KEY: str = "CHANGE-ME-IN-PRODUCTION-USE-openssl-rand-hex-32"

    # --- CORS & Hosts ---
    # Allow local + LAN origins so remote browsers and agents can connect
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "http://192.168.2.83:3000",
        "http://192.168.2.83:8000",
        # Wildcard fallback — set to ["*"] in dev if needed
    ]
    ALLOWED_HOSTS: list[str] = ["localhost", "127.0.0.1", "192.168.2.83"]

    # --- PostgreSQL ---
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinel"
    POSTGRES_PASSWORD: str = "sentinel_dev_password"
    POSTGRES_DB: str = "sentinelai"

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # --- Redis ---
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = "sentinel_dev_password"
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # --- Elasticsearch ---
    ELASTICSEARCH_HOST: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX_PREFIX: str = "sentinelai"

    # --- JWT Authentication ---
    JWT_SECRET_KEY: str = "CHANGE-ME-jwt-secret-key-use-openssl-rand-hex-64"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- LLM Configuration ---
    LLM_PROVIDER: str = "ollama"  # openai | anthropic | ollama
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "bjoernb/claude-opus-4-5"

    # --- NVD / Vulnerability Database ---
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CACHE_TTL_HOURS: int = 24

    # --- Agent Configuration ---
    AGENT_HEARTBEAT_INTERVAL_SECONDS: int = 30
    AGENT_TELEMETRY_BATCH_SIZE: int = 100
    AGENT_MAX_OFFLINE_MINUTES: int = 5

    # --- SMTP / Email ---
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@sentinelai.local"
    SMTP_USE_TLS: bool = True

    # --- 2FA / TOTP ---
    TOTP_ISSUER: str = "SentinelAI"

    # --- Command Signing (HMAC-SHA256) ---
    REMEDIATION_HMAC_KEY: str = "CHANGE-ME-hmac-key-use-openssl-rand-hex-64"
    COMMAND_SIGNING_REQUIRED: bool = True

    # --- Approval Workflow ---
    APPROVAL_EXPIRY_HOURS: int = 24
    AUTO_APPROVE_FOR_ADMIN: bool = True

    # --- First-run admin seed ---
    ADMIN_DEFAULT_EMAIL: str = "admin@sentinelai.local"
    ADMIN_DEFAULT_PASSWORD: str = "SentinelAdmin2026!"


settings = Settings()
