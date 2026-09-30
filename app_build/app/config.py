"""Central configuration. Runtime output goes to ../production_artifacts."""
from __future__ import annotations
import os
from pathlib import Path

APP_NAME = "SecureMailScope"
APP_VERSION = "1.0.0"

APP_DIR = Path(__file__).resolve().parent
BUILD_DIR = APP_DIR.parent
PROJECT_ROOT = BUILD_DIR.parent

ARTIFACTS_DIR = Path(os.getenv("SMS_ARTIFACTS_DIR", PROJECT_ROOT / "production_artifacts")).resolve()
UPLOAD_DIR = ARTIFACTS_DIR / "uploads"
ANALYSES_DIR = ARTIFACTS_DIR / "analyses"
BASELINES_DIR = ARTIFACTS_DIR / "baselines"
MODELS_DIR = ARTIFACTS_DIR / "models"
REPORTS_DIR = ARTIFACTS_DIR / "reports"
TRUST_STORE_DIR = ARTIFACTS_DIR / "trust_store"   # drop enterprise/private CA certs (.pem/.crt) here
SAMPLES_DIR = ARTIFACTS_DIR / "samples"
LOGS_DIR = ARTIFACTS_DIR / "logs"

MAX_UPLOAD_MB = int(os.getenv("SMS_MAX_UPLOAD_MB", "512"))
API_KEY = os.getenv("SMS_API_KEY", "")
CORS_ORIGINS = [o.strip() for o in os.getenv("SMS_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]

# Well-known mail ports -> (protocol, usual transport mode)
MAIL_PORTS = {
    25: ("SMTP", "starttls"), 587: ("SMTP", "starttls"), 2525: ("SMTP", "starttls"), 465: ("SMTP", "implicit_tls"),
    143: ("IMAP", "starttls"), 993: ("IMAP", "implicit_tls"),
    110: ("POP3", "starttls"), 995: ("POP3", "implicit_tls"),
}
IMPLICIT_TLS_PORTS = {465, 993, 995}

# Thresholds
CERT_EXPIRY_WARN_DAYS = 30
CERT_EXPIRY_CRIT_DAYS = 7
CERT_MAX_VALIDITY_DAYS = 825
ML_MIN_SESSIONS = 20
ML_ANOMALY_THRESHOLD = 0.5      # calibrated 0-1 score at/above which a session is anomalous
PROTOCOL_MIN_CONFIDENCE = 0.5


def ensure_dirs() -> None:
    for d in (UPLOAD_DIR, ANALYSES_DIR, BASELINES_DIR, MODELS_DIR, REPORTS_DIR, TRUST_STORE_DIR, SAMPLES_DIR, LOGS_DIR):
        d.mkdir(parents=True, exist_ok=True)
