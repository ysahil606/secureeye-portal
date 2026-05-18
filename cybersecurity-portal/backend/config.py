from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # App
    APP_NAME: str = "Secure Cybersecurity Advisory Portal"
    SECRET_KEY: str = "change-this-to-a-very-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "sqlite:////tmp/secure.db"
    
    @property
    def sqlalchemy_database_url(self) -> str:
        """Handle SQLAlchemy's requirement for postgresql:// instead of postgres://"""
        if self.DATABASE_URL.startswith("postgres://"):
            return self.DATABASE_URL.replace("postgres://", "postgresql://", 1)
        return self.DATABASE_URL

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

    # NTFY
    NTFY_TOPIC: str = ""

    # AI Summarization (optional)
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    GROQ_API_KEY: str = ""

    # Web Search
    WEB_SEARCH_PROVIDER: str = "brave"
    WEB_SEARCH_RESULTS_LIMIT: int = 10
    GOOGLE_SEARCH_API_KEY: str = ""
    GOOGLE_SEARCH_ENGINE_ID: str = ""
    BRAVE_API_KEY: str = ""
    NVD_API_KEY: str = ""
    THREATFOX_AUTH_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""
    HYBRID_ANALYSIS_API_KEY: str = ""

    # Feed polling interval in minutes
    FEED_POLL_INTERVAL_MINUTES: int = 30
    WARM_START_FEEDS_ENABLED: bool = False
    KEEP_ALIVE_INTERVAL_SECONDS: int = 240
    PUBLIC_BACKEND_URL: str = ""

    # CVSS threshold for critical alerts
    CRITICAL_CVSS_THRESHOLD: float = 8.5

    class Config:
        env_file = ".env"

settings = Settings()
