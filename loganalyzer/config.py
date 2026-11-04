"""Application configuration and directory management."""

from pathlib import Path
from datetime import datetime, timezone
import os

def utc_now() -> datetime:
    """Return naive UTC datetime (for SQLite string ISO compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = BASE_DIR / "loganalyzer.db"
RULES_CONFIG_PATH = BASE_DIR / "loganalyzer" / "detection" / "rules_config.yaml"
MITRE_DATA_PATH = BASE_DIR / "loganalyzer" / "intel" / "mitre_data.json"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Application settings
APP_NAME = "LogAnalyzer Pro"
APP_SUBTITLE = "Intelligent Security Log Analysis & Incident Investigation Platform"
APP_VERSION = "1.0.0"

# Risk Scoring Weights
RISK_WEIGHTS = {
    "severity_critical": 40,
    "severity_high": 30,
    "severity_medium": 15,
    "severity_low": 5,
    "multiple_accounts": 20,
    "high_frequency_failures": 15,
    "suspicious_success_after_failure": 25,
    "public_ip_source": 10,
    "multi_technique_correlation": 15
}
