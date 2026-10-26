import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-change-this-key-before-deployment"
    DATABASE = os.environ.get("DATABASE_PATH", str(BASE_DIR / "arinex_jamb_prep.db"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("APP_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 30
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    PREMIUM_PRICE = int(os.environ.get("PREMIUM_PRICE", "2000"))
    PAYMENT_BANK = "Kuda Bank"
    PAYMENT_ACCOUNT_NUMBER = os.environ.get("PAYMENT_ACCOUNT_NUMBER", "2085846984")
    PAYMENT_ACCOUNT_NAME = os.environ.get("PAYMENT_ACCOUNT_NAME", "Arilesere Nihmatalah Omolewa")
    MOCK_QUESTION_COUNT = 180
    MOCK_DURATION_MINUTES = 120
    ENGLISH_QUESTION_COUNT = 60
    OTHER_SUBJECT_QUESTION_COUNT = 40
    FREE_PRACTICE_ATTEMPTS = 2
    DEFAULT_PRACTICE_QUESTIONS = 20
    DEFAULT_PRACTICE_MINUTES = 30
    MAX_PRACTICE_QUESTIONS = 60
