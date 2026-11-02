from pathlib import Path
from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "RAJAWALI"
    ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production"
    DATABASE_URL: str = "sqlite+aiosqlite:///./rajawali.db"
    REDIS_URL: Optional[str] = "memory://"
    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_CHANNEL_ID: Optional[str] = None
    ABUSE_CH_API_KEY: Optional[str] = None
    NEXT_PUBLIC_API_URL: str = "http://localhost:8000"
    CORS_ORIGINS: str = "http://localhost:3000"
    HONEYPOT_TOKEN: Optional[str] = None
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD_HASH: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[3] / ".env",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.ENV.lower() == "production" and (
            self.SECRET_KEY == "change-me-in-production" or len(self.SECRET_KEY) < 32
        ):
            raise ValueError("SECRET_KEY must be a random value of at least 32 characters in production")
        if self.ENV.lower() == "production" and (
            not self.HONEYPOT_TOKEN or not self.ADMIN_PASSWORD_HASH
        ):
            raise ValueError("HONEYPOT_TOKEN and ADMIN_PASSWORD_HASH must be configured in production")
        return self

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()
