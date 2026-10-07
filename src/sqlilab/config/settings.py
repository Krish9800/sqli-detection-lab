"""Runtime configuration settings for sqlilab."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable override support."""

    app_name: str = "SQL Injection Detection Lab"
    version: str = "0.1.0"
    environment: str = "development"
    debug: bool = False

    # Detection Thresholds
    anomaly_threshold: float = 0.65
    entropy_threshold: float = 4.2
    tautology_strict_mode: bool = True

    # Lab Server Config
    lab_host: str = "127.0.0.1"
    lab_port: int = 8080

    model_config = SettingsConfigDict(
        env_prefix="SQLILAB_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return singleton configuration settings."""
    return Settings()
