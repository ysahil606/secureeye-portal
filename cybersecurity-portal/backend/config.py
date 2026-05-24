from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # App
    APP_NAME: str = "Secure Cybersecurity Advisory Portal"
    SECRET_KEY: str = "change-this-to-a-very-secret-key-in-production"
    FORCE_ADMIN_RESET: bool = False
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
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_FROM_EMAIL: str = ""

    # Slack
    SLACK_WEBHOOK_URL: str = ""

    # MS Teams
    TEAMS_WEBHOOK_URL: str = ""

    # NTFY
    NTFY_TOPIC: str = ""

    # AI Summarization - Add multiple free keys for auto-rotation (effectively unlimited)
    # Each Groq model has its OWN rate limit bucket - different models = more combined quota!
    OPENAI_API_KEY: str = ""

    # Gemini Keys (get free keys at aistudio.google.com)
    GEMINI_API_KEY: str = ""           # Free: 1,500 req/day
    GEMINI_MODEL_1: str = "gemini-2.0-flash"    # Fast, high quality
    GEMINI_API_KEY_2: str = ""         # Optional 2nd Gemini key/account
    GEMINI_MODEL_2: str = "gemini-1.5-flash"    # Different model = separate quota pool

    # Groq Keys (get free keys at console.groq.com)
    # Each model has its own separate daily limit - mix models for max combined free quota!
    GROQ_API_KEY: str = ""             # Free: ~14,400 req/day
    GROQ_MODEL_1: str = "llama-3.3-70b-versatile"   # Best quality model
    GROQ_API_KEY_2: str = ""           # Optional 2nd Groq key
    GROQ_MODEL_2: str = "llama-3.3-70b-versatile"   # Same model, different account
    GROQ_API_KEY_3: str = ""           # Optional 3rd Groq key
    GROQ_MODEL_3: str = "llama-3.3-70b-versatile"   # Same model, different account
    GROQ_API_KEY_4: str = ""           # Optional 4th Groq key
    GROQ_MODEL_4: str = "llama-3.3-70b-versatile"   # Same model, different account

    CEREBRAS_API_KEY: str = ""         # Free: cloud.cerebras.ai (1,000 req/day)
    OPENROUTER_API_KEY: str = ""       # Free models: openrouter.ai
    HUGGINGFACE_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

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
    BREACH_DIRECTORY_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    LEAK_LOOKUP_API_KEY: str = ""
    GREYNOISE_API_KEY: str = ""
    PULSEDIVE_API_KEY: str = ""

    # Feed polling interval in minutes
    FEED_POLL_INTERVAL_MINUTES: int = 30
    WARM_START_FEEDS_ENABLED: bool = False
    KEEP_ALIVE_INTERVAL_SECONDS: int = 240
    PUBLIC_BACKEND_URL: str = ""

    # CVSS threshold for critical alerts
    CRITICAL_CVSS_THRESHOLD: float = 8.5

    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }

settings = Settings()
