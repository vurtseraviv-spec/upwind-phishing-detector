import hashlib
import json
import logging
import math
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai_engine import chat_with_analyst, get_ai_engine_status, investigate_scan
from app.db import ScanRecord, SessionLocal, cache, check_db_health, get_db_engine_label, init_db
from app.detector import analyze_email


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "host": socket.gethostname(),
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_data"):
            payload.update(record.extra_data)
        return json.dumps(payload)


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("phishing_detector")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    formatter = JsonFormatter()

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    log_file = os.getenv("LOG_FILE", "")
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


logger = setup_logging()
INSTANCE_HOST = socket.gethostname()
_cpu_stress_lock = threading.Lock()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    logger.info(
        "Application started",
        extra={
            "extra_data": {
                "event": "startup",
                "database_engine": get_db_engine_label(),
                "redis": cache.is_healthy(),
                "ai_engine": get_ai_engine_status(),
            }
        },
    )
    yield


app = FastAPI(title="Upwind Email Phishing Detector & AI SOC", version="2.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class TextScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "pasted_email.txt"


class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[int] = None


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    if request.url.path not in ("/health", "/favicon.ico"):
        logger.info(
            "HTTP request handled",
            extra={
                "extra_data": {
                    "event": "http_request",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                }
            },
        )
    return response


@app.get("/")
def serve_ui():
    static_file = Path(__file__).parent / "static" / "index.html"
    return FileResponse(static_file)


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health_check():
    db_ok = check_db_health()
    redis_status = cache.is_healthy()
    status_code = 200 if db_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if db_ok else "unhealthy",
            "database": "ok" if db_ok else "error",
            "database_engine": get_db_engine_label(),
            "redis_cache": redis_status,
            "ai_engine": get_ai_engine_status(),
            "served_by": INSTANCE_HOST,
        },
    )


def _compute_metrics(db: Session) -> Dict[str, Any]:
    rows = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(250).all()
    total = len(rows)
    phishing_count = sum(1 for r in rows if r.is_phishing)
    suspicious_count = sum(1 for r in rows if (not r.is_phishing and r.risk_level == "MEDIUM"))
    safe_count = total - phishing_count - suspicious_count
    cached_count = sum(1 for r in rows if r.action_type == "SCAN_CACHED")
    investigated_count = sum(1 for r in rows if r.investigation_json)

    avg_score = round(sum(r.risk_score for r in rows) / total, 1) if total else 0.0
    latencies = [float(r.processing_ms or 0.0) for r in rows if r.processing_ms is not None]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_dist = {
        "Spoofed Sender": 0,
        "Suspicious Link": 0,
        "Suspicious Wording": 0,
        "Attachment Analysis": 0,
    }
    host_dist: Dict[str, int] = {}

    for r in rows:
        if r.risk_level in severity_dist:
            severity_dist[r.risk_level] += 1
        host_key = r.served_by or "unknown"
        host_dist[host_key] = host_dist.get(host_key, 0) + 1
        try:
            details = json.loads(r.details_json)
            for ind in details.get("indicators", []):
                cat = ind.get("category")
                if cat in category_dist:
                    category_dist[cat] += 1
        except Exception:
            pass

    recent_timeline = [
        {
            "id": r.id,
            "time": r.created_at.strftime("%H:%M:%S") if r.created_at else "",
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "processing_ms": round(float(r.processing_ms or 0.0), 2),
            "cached": r.action_type == "SCAN_CACHED",
            "served_by": r.served_by or "",
        }
        for r in reversed(rows[:15])
    ]

    return {
        "total_scans": total,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "detection_rate_pct": round((phishing_count / total) * 100, 1) if total else 0.0,
        "avg_risk_score": avg_score,
        "avg_latency_ms": avg_latency,
        "cache_hit_rate_pct": round((cached_count / total) * 100, 1) if total else 0.0,
        "investigated_count": investigated_count,
        "severity_distribution": severity_dist,
        "category_distribution": category_dist,
        "host_distribution": host_dist,
        "recent_timeline": recent_timeline,
        "ai_engine": get_ai_engine_status(),
        "database_engine": get_db_engine_label(),
        "served_by": INSTANCE_HOST,
    }


def _execute_and_store_scan(raw_content: str, filename: str, db: Session):
    start = time.perf_counter()
    content_hash = hashlib.sha256(raw_content.encode("utf-8", errors="ignore")).hexdigest()
    cache_key = f"scan:v2:{content_hash}"

    cached_result = cache.get_json(cache_key)
    from_cache = cached_result is not None

    if from_cache:
        result = cached_result
    else:
        result = analyze_email(raw_content, filename=filename)
        cache.set_json(cache_key, result)

    duration_ms = round((time.perf_counter() - start) * 1000, 2)

    record = ScanRecord(
        filename=filename,
        content_hash=result["content_hash"],
        sender=result["sender"],
        subject=result["subject"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        is_phishing=result["is_phishing"],
        verdict=result["verdict"],
        indicator_count=result["indicator_count"],
        details_json=json.dumps(result),
        processing_ms=duration_ms,
        action_type="SCAN_CACHED" if from_cache else "SCAN_NEW",
        served_by=INSTANCE_HOST,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    cache.delete("history:latest")

    logger.info(
        "Email scan completed",
        extra={
            "extra_data": {
                "event": "email_scan",
                "scan_id": record.id,
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "is_phishing": result["is_phishing"],
                "cached": from_cache,
                "duration_ms": duration_ms,
            }
        },
    )

    return {
        **result,
        "id": record.id,
        "created_at": record.created_at.isoformat(),
        "cached": from_cache,
        "processing_ms": duration_ms,
        "served_by": INSTANCE_HOST,
        "investigation": None,
    }


@app.post("/api/scan")
async def scan_email_text(payload: TextScanRequest, db: Session = Depends(get_db)):
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")
    return _execute_and_store_scan(payload.content, payload.filename or "pasted_email.txt", db)


@app.post("/api/scan/file")
async def scan_email_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    raw_content = raw_bytes.decode("utf-8", errors="replace")
    return _execute_and_store_scan(raw_content, file.filename or "uploaded_email.txt", db)


@app.post("/api/investigate/{scan_id}")
def run_ai_investigation(scan_id: int, force: bool = False, db: Session = Depends(get_db)):
    row = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if row.investigation_json and not force:
        return {
            "scan_id": row.id,
            "cached": True,
            "investigation": json.loads(row.investigation_json),
            "served_by": INSTANCE_HOST,
        }

    start = time.perf_counter()
    details = json.loads(row.details_json)
    inv_cache_key = f"inv:v2:{row.content_hash}"
    cached_inv = None if force else cache.get_json(inv_cache_key)

    if cached_inv:
        investigation = cached_inv
    else:
        investigation = investigate_scan(details)
        cache.set_json(inv_cache_key, investigation, ttl=900)

    row.investigation_json = json.dumps(investigation)
    db.commit()
    cache.delete("history:latest")

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "AI threat investigation completed",
        extra={
            "extra_data": {
                "event": "ai_investigation",
                "scan_id": row.id,
                "attack_type": investigation.get("attack_type"),
                "engine": investigation.get("engine"),
                "duration_ms": duration_ms,
            }
        },
    )

    return {
        "scan_id": row.id,
        "cached": bool(cached_inv),
        "duration_ms": duration_ms,
        "investigation": investigation,
        "served_by": INSTANCE_HOST,
    }


@app.post("/api/chat")
def ai_security_chat(payload: ChatRequest, db: Session = Depends(get_db)):
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="Chat message cannot be empty.")

    active_scan = None
    if payload.scan_id is not None:
        row = db.query(ScanRecord).filter(ScanRecord.id == payload.scan_id).first()
        if row:
            active_scan = {**json.loads(row.details_json), "id": row.id}
    else:
        latest = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).first()
        if latest:
            active_scan = {**json.loads(latest.details_json), "id": latest.id}

    metrics = _compute_metrics(db)
    result = chat_with_analyst(payload.message.strip(), active_scan, metrics)

    logger.info(
        "AI security chat answered",
        extra={
            "extra_data": {
                "event": "ai_chat",
                "scan_id": active_scan["id"] if active_scan else None,
                "engine": result.get("engine"),
            }
        },
    )
    return {
        **result,
        "active_scan_id": active_scan["id"] if active_scan else None,
        "served_by": INSTANCE_HOST,
    }


@app.get("/api/metrics")
def get_live_metrics(db: Session = Depends(get_db)):
    return _compute_metrics(db)


@app.get("/api/history")
def get_history(limit: int = 25, db: Session = Depends(get_db)):
    cache_key = "history:latest"
    if limit == 25:
        cached = cache.get_json(cache_key)
        if cached is not None:
            return {
                "items": cached,
                "cached": True,
                "database_engine": get_db_engine_label(),
                "served_by": INSTANCE_HOST,
            }

    rows = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(min(limit, 100)).all()
    items = [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat(),
            "filename": r.filename,
            "sender": r.sender,
            "subject": r.subject,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "is_phishing": r.is_phishing,
            "verdict": r.verdict,
            "indicator_count": r.indicator_count,
            "has_investigation": bool(r.investigation_json),
            "processing_ms": round(float(r.processing_ms or 0.0), 2),
            "action_type": r.action_type,
            "served_by": r.served_by,
        }
        for r in rows
    ]
    if limit == 25:
        cache.set_json(cache_key, items, ttl=60)
    return {
        "items": items,
        "cached": False,
        "database_engine": get_db_engine_label(),
        "served_by": INSTANCE_HOST,
    }


@app.get("/api/history/{scan_id}")
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    row = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {
        **json.loads(row.details_json),
        "id": row.id,
        "created_at": row.created_at.isoformat(),
        "processing_ms": round(float(row.processing_ms or 0.0), 2),
        "action_type": row.action_type,
        "served_by": row.served_by,
        "investigation": json.loads(row.investigation_json) if row.investigation_json else None,
    }


@app.delete("/api/history/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    row = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    db.delete(row)
    db.commit()
    cache.delete("history:latest")
    logger.info("Scan record deleted", extra={"extra_data": {"event": "delete_scan", "scan_id": scan_id}})
    return {"deleted": True, "id": scan_id}


@app.post("/api/simulate/error")
def simulate_server_error():
    logger.error(
        "Simulated HTTP 500 fault triggered for CloudWatch observability demo",
        extra={"extra_data": {"event": "simulated_500_fault"}},
    )
    raise HTTPException(status_code=500, detail="Simulated 500 fault logged to CloudWatch for monitoring test.")


def _burn_cpu_briefly(duration_sec: int = 8) -> None:
    try:
        end_time = time.time() + duration_sec
        x = 1.0001
        while time.time() < end_time:
            x = math.sqrt(x * x + 1.234567) % 1000
    finally:
        _cpu_stress_lock.release()


@app.post("/api/simulate/cpu")
def simulate_cpu_spike():
    if not _cpu_stress_lock.acquire(blocking=False):
        return {"status": "already_running", "served_by": INSTANCE_HOST}
    threading.Thread(target=_burn_cpu_briefly, args=(8,), daemon=True).start()
    logger.warning(
        "Simulated 8s CPU spike started for CloudWatch metric validation",
        extra={"extra_data": {"event": "simulated_cpu_spike", "duration_sec": 8}},
    )
    return {"status": "started", "duration_sec": 8, "served_by": INSTANCE_HOST}
