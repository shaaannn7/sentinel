"""Configuration settings for SENTINEL API using pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly typed application configuration."""

    DATABASE_URL: str = "sqlite:///./sentinel.db"
    REDIS_URL: str = "redis://redis:6379/0"

    LLM_PROVIDER: str = "mock"
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_API_KEY: str = ""
    LLM_API_URL: str = "https://api.openai.com/v1"
    LLM_TIMEOUT_SECONDS: float = 30.0
    LLM_MOCK_ENABLED: bool = False

    THREAT_INTEL_PROVIDER: str = "mock"
    THREAT_INTEL_API_KEY: str = ""
    GEOLOCATION_PROVIDER: str = "mock"
    GEOLOCATION_API_KEY: str = ""

    STORE_RAW_EMAIL: bool = True
    MAX_UPLOAD_SIZE: int = 10_485_760
    DEMO_MODE: bool = True
    UPLOAD_DIR: str = "/tmp/sentinel/uploads"
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    API_AUTH_KEY: str = ""
    ADMIN_API_KEY: str = ""
    ANALYST_API_KEY: str = ""
    VIEWER_API_KEY: str = ""
    AUTH_ENFORCE: bool = False

    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "120/minute"
    RATE_LIMIT_UPLOAD: str = "15/minute"
    RATE_LIMIT_EXPENSIVE: str = "6/minute"

    MAX_ATTACHMENTS: int = 50
    MAX_URLS: int = 200
    MAX_INDICATORS: int = 500
    MAX_MIME_DEPTH: int = 10
    MAX_HEADER_COUNT: int = 100
    MAX_AI_BODY_CHARS: int = 4000
    SCORE_VERSION: str = "2026.10"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
