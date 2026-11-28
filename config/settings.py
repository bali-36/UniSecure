"""Application configuration for UniSecure (Phase 1 Vulnerable Skeleton)."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base configuration loaded from environment with local dev defaults."""

    BASE_DIR = BASE_DIR
    SECRET_KEY = os.getenv("SECRET_KEY", "unisecure-dev-secret-change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", "unisecure-jwt-dev-secret")
    DATABASE_PATH = os.getenv(
        "DATABASE_PATH", str(BASE_DIR / "instance" / "unisecure.db")
    )
    UPLOAD_FOLDER = os.getenv(
        "UPLOAD_FOLDER", str(BASE_DIR / "instance" / "uploads")
    )
    CORS_ALLOW_ORIGIN = os.getenv("CORS_ALLOW_ORIGIN", "*")
    TESTING = False
