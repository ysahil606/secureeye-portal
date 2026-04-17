from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # App
    APP_NAME: str = "SecureEye Cybersecurity Advisory Portal"
    SECRET_KEY: str = "change-this-to-a-very-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "sqlite:///./secureeye.db"
    ALLOWED_ORIGINS: str = ""

    # Email (SMTP)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "ysahil251101@gmail.com"
    SMTP_PASSWORD: str = ""
    ALERT_FROM_EMAIL: str = "ysahil251101@gmail.com"

    # Slack
    SLACK_WEBHOOK_URL: str = ""

    # MS Teams
    TEAMS_WEBHOOK_URL: str = ""

    # AI Summarization (optional)
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Web Search
    WEB_SEARCH_PROVIDER: str = "brave"
    WEB_SEARCH_RESULTS_LIMIT: int = 10
    GOOGLE_SEARCH_API_KEY: str = ""
    GOOGLE_SEARCH_ENGINE_ID: str = ""

    # Feed polling interval in minutes
    FEED_POLL_INTERVAL_MINUTES: int = 30

    # CVSS threshold for critical alerts
    CRITICAL_CVSS_THRESHOLD: float = 8.5

    class Config:
        env_file = ".env"

settings = Settings()
