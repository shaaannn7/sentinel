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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
