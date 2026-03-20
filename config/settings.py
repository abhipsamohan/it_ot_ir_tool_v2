"""
config/settings.py - Configuration Management
Environment-based configuration for Development/Production/Testing modes.
All secrets loaded from environment variables - no hardcoded values.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    DEBUG = False
    TESTING = False

    # Database
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///data/incidents.db")

    # Alert ingestion directory
    ALERTS_DIR = os.environ.get("ALERTS_DIR", "data/alerts")

    # OT asset context file
    ASSETS_FILE = os.environ.get("ASSETS_FILE", "data/ot_context/ot_assets.json")

    # Rules and dependency config
    RULES_FILE = os.environ.get("RULES_FILE", "config/rules.json")
    DEPENDENCIES_FILE = os.environ.get("DEPENDENCIES_FILE", "config/dependencies.json")

    # Alert history cap (for correlation engine)
    ALERT_HISTORY_LIMIT = int(os.environ.get("ALERT_HISTORY_LIMIT", "1000"))

    # Brute force detection thresholds
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
    BRUTE_FORCE_WINDOW_MINUTES = int(os.environ.get("BRUTE_FORCE_WINDOW_MINUTES", "5"))

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get("LOG_FILE", "data/app.log")

    # CORS origins
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

    # Device monitoring (optional)
    MONITORED_DEVICES = os.environ.get("MONITORED_DEVICES", "").split(",") if os.environ.get("MONITORED_DEVICES") else []


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class ProductionConfig(BaseConfig):
    DEBUG = False
    LOG_LEVEL = "WARNING"


class TestingConfig(BaseConfig):
    TESTING = True
    DATABASE_URL = "sqlite:///:memory:"
    ALERTS_DIR = "/tmp/test_alerts"
    LOG_LEVEL = "DEBUG"


# Map environment name to config class
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    """Return the appropriate config class based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
