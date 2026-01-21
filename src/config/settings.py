from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Database
    DATABASE_URL: str = "postgresql://mac:1201@localhost:5432/ztp_db"
    MONGODB_URL: str = "mongodb://localhost:27017/ztp_engine"
    
    # JWT
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # ML Configuration
    MODEL_PATH: str = "./ml_models/ztp_policy_model.pkl"
    DEVICE_HEALTH_THRESHOLD: int = 70
    RISK_THRESHOLD_HIGH: int = 80
    RISK_THRESHOLD_MEDIUM: int = 50
    
    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    DEBUG: bool = True
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/ztp_engine.log"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()