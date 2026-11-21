import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import redis
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger("phishing_detector")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./local_phishing.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine_kwargs: dict[str, Any] = {
    "connect_args": connect_args,
    "pool_pre_ping": True,
}
if not DATABASE_URL.startswith("sqlite"):
    engine_kwargs["pool_size"] = 5

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db_engine_label() -> str:
    if DATABASE_URL.startswith("sqlite"):
        return "Local SQLite"
    return "Amazon RDS PostgreSQL"


class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    filename = Column(String(255), nullable=False)
    content_hash = Column(String(64), index=True)
    sender = Column(String(255))
    subject = Column(String(500))
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    is_phishing = Column(Boolean, nullable=False)
    verdict = Column(String(128), nullable=False)
    indicator_count = Column(Integer, nullable=False)
    details_json = Column(Text, nullable=False)
    investigation_json = Column(Text, nullable=True)
    processing_ms = Column(Float, default=0.0)
    action_type = Column(String(64), default="SCAN")
    served_by = Column(String(128))


def init_db() -> None:
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
    except IntegrityError:
        logger.info("Database schema already initialized by another worker.")

    try:
        inspector = inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("scan_history")}
        with engine.begin() as conn:
            if "investigation_json" not in cols:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN investigation_json TEXT"))
            if "processing_ms" not in cols:
                conn.execute(text("ALTER TABLE scan_history ADD COLUMN processing_ms FLOAT DEFAULT 0"))
    except Exception as exc:
        logger.warning("Schema migration check skipped: %s", exc)


def check_db_health() -> bool:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        return False


class CacheClient:
    def __init__(self) -> None:
        self.host = os.getenv("REDIS_HOST", "").strip()
        self.port = int(os.getenv("REDIS_PORT", "6379"))
        self.ttl = int(os.getenv("CACHE_TTL_SECONDS", "600"))
        self._client: Optional[redis.Redis] = None
        if self.host:
            self._client = redis.Redis(
                host=self.host,
                port=self.port,
                decode_responses=True,
                socket_connect_timeout=1.5,
                socket_timeout=1.5,
            )

    def is_healthy(self) -> str:
        if not self._client:
            return "disabled"
        try:
            return "ok" if self._client.ping() else "error"
        except Exception as exc:
            logger.warning("Redis ping failed: %s", exc)
            return "unavailable"

    def get_json(self, key: str) -> Optional[Any]:
        if not self._client:
            return None
        try:
            val = self._client.get(key)
            return json.loads(val) if val else None
        except Exception as exc:
            logger.warning("Redis GET failed (%s): %s", key, exc)
            return None

    def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        if not self._client:
            return
        try:
            self._client.setex(key, ttl or self.ttl, json.dumps(value, default=str))
        except Exception as exc:
            logger.warning("Redis SET failed (%s): %s", key, exc)

    def delete(self, key: str) -> None:
        if not self._client:
            return
        try:
            self._client.delete(key)
        except Exception as exc:
            logger.warning("Redis DELETE failed (%s): %s", key, exc)


cache = CacheClient()
