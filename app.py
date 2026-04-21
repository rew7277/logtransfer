from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import smtplib
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from functools import lru_cache
from queue import Queue, Full
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None  # type: ignore
    HAS_PSYCOPG2 = False

try:
    import requests as _requests_lib
except Exception:
    _requests_lib = None

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except Exception:
    BackgroundScheduler = None

# ─────────────────────────── Logging ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("observex")

# ─────────────────────────── Paths ───────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
_vol_env = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "").strip()
_vol_candidates = [Path(_vol_env)] if _vol_env else []
_vol_candidates += [Path("/data")]

def _pick_data_dir() -> Path:
    for p in _vol_candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            if os.access(p, os.W_OK):
                return p
        except Exception:
            pass
    fallback = BASE_DIR / "data"
    fallback.mkdir(exist_ok=True)
    return fallback

DATA_DIR = _pick_data_dir()
DB_PATH  = DATA_DIR / "observex.db"

# ─────────────────────────── Flask app ───────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB file uploads

# SECURITY: Enforce a strong secret key — never fall back to a dev string.
_secret_key = os.environ.get("SECRET_KEY", "").strip()
if not _secret_key:
    logger.critical(
        "SECRET_KEY env var is not set. "
        "Sessions are insecure. Set a 32+ char random value in production."
    )
    # Generate a random one for this process start (sessions won't survive restarts)
    _secret_key = secrets.token_hex(32)
app.secret_key = _secret_key

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") != "development"

# ─────────────────────────── Rate Limiter ────────────────────────────────────
# Uses in-memory storage by default. For multi-instance deployments on Railway,
# set REDIS_URL env var and switch to storage_uri=os.environ.get("REDIS_URL").
limiter: Any = None
if HAS_LIMITER:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri=os.environ.get("REDIS_URL", "memory://"),
    )

def rate_limit(limit_string: str):
    """Decorator — apply only when flask-limiter is installed."""
    def decorator(f):
        if limiter is not None:
            return limiter.limit(limit_string)(f)
        return f
    return decorator

# ─────────────────────────── Constants ───────────────────────────────────────
LEVEL_PATTERNS = {
    "error":   [r"\berror\b", r"\bexception\b", r"\bfailed\b", r"\btraceback\b", r"\btimeout\b", r"\brefused\b"],
    "warn":    [r"\bwarn\b", r"\bwarning\b", r"\bdegraded\b", r"\bretry\b", r"\bslow\b"],
    "success": [r"\bsuccess\b", r"\bcompleted\b", r"\bok\b", r"\b200\b"],
    "info":    [r"\binfo\b", r"\bstarted\b", r"\bprocessing\b"],
    "debug":   [r"\bdebug\b", r"\bverbose\b"],
}

TS_KEYS      = ["timestamp", "time", "@timestamp", "date", "createdAt", "datetime", "TimestampIST"]
MESSAGE_KEYS = ["message", "msg", "log", "event", "description"]
SOURCE_KEYS  = ["source", "service", "app", "application", "logger", "component", "system", "ApplicationName"]
ID_KEYS      = ["eventId", "requestId", "traceId", "correlationId", "transactionId", "id"]
HEADER_RE    = re.compile(r"^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}")
ROTATION_SUFFIX_RE = re.compile(r"(\.\d{4}-\d{2}-\d{2})+$|(\.\d+)$")

MASK_PATTERNS = [
    (re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[A-Za-z0-9+/=._-]+"), r"\1\2 [REDACTED]"),
    (re.compile(r"(?i)(password\s*[:=]\s*)[^\s,\"']+"), r"\1[REDACTED]"),
    (re.compile(r"\bGLBCUST\d{8,}\b"), "GLBCUST[REDACTED]"),
    (re.compile(r"\bAPP-\d{4,}\b"), "APP-[REDACTED]"),
]

VALID_ROLES  = {"admin", "manager", "developer", "tester"}
VALID_THEMES = {"white"}
DEFAULT_THEME_COLORS = {"white": "#2563eb"}

# SSRF protection: block private/loopback ranges in test_api
_BLOCKED_HOSTS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"::1|0\.0\.0\.0|169\.254\.\d+\.\d+)$",
    re.I,
)

# ─────────────────────────── API Key Cache ───────────────────────────────────
# Maps sha256(raw_key) -> (key_info_dict, expiry_epoch)
# This avoids running bcrypt on every authenticated API request.
# SECURITY: Cache only validated (successful) lookups; never cache failures.
_KEY_CACHE: dict[str, tuple[dict, float]] = {}
_KEY_CACHE_LOCK = threading.Lock()
_KEY_CACHE_TTL = 300  # seconds — revoked keys propagate within this window

def _cache_key_id(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()

def _get_cached_key(raw_key: str) -> dict | None:
    cid = _cache_key_id(raw_key)
    with _KEY_CACHE_LOCK:
        entry = _KEY_CACHE.get(cid)
        if entry and entry[1] > time.time():
            return entry[0]
        if entry:
            del _KEY_CACHE[cid]
    return None

def _set_cached_key(raw_key: str, key_info: dict) -> None:
    cid = _cache_key_id(raw_key)
    with _KEY_CACHE_LOCK:
        _KEY_CACHE[cid] = (key_info, time.time() + _KEY_CACHE_TTL)

def _invalidate_cached_key(raw_key_prefix: str) -> None:
    """Called on revoke — sweep cache entries whose stored prefix matches."""
    with _KEY_CACHE_LOCK:
        to_del = [cid for cid, (info, _) in _KEY_CACHE.items() if info.get("prefix") == raw_key_prefix]
        for cid in to_del:
            del _KEY_CACHE[cid]

# ─────────────────────────── Scheduler / Worker ──────────────────────────────
scheduler: Any = None
INGESTION_QUEUE: Queue[int] = Queue(maxsize=500)  # bounded — apply back-pressure
_WORKER_POOL: ThreadPoolExecutor | None = None

# ─────────────────────────── Per-org ingest rate limiter ──────────────────────
# Maps org_id -> (count_this_minute, minute_bucket_epoch)
_ORG_RATE: dict[int, tuple[int, int]] = {}
_ORG_RATE_LOCK = threading.Lock()

def _check_org_rate(org_id: int, limit: int) -> bool:
    """Return True if org is within its per-minute ingest rate limit."""
    bucket = int(time.time()) // 60
    with _ORG_RATE_LOCK:
        count, stored_bucket = _ORG_RATE.get(org_id, (0, bucket))
        if stored_bucket != bucket:
            count = 0
        count += 1
        _ORG_RATE[org_id] = (count, bucket)
    return count <= limit

# ─────────────────────────── Security helpers ────────────────────────────────

def validate_password_strength(password: str) -> str | None:
    """Return an error message if password is too weak, else None."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    return None

def validate_url_for_ssrf(url: str) -> str | None:
    """Return an error message if URL targets a private/internal host."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if _BLOCKED_HOSTS.match(host):
            return f"URL host '{host}' is not allowed (private/loopback address)."
        if parsed.scheme not in ("http", "https"):
            return "Only http and https URLs are supported."
    except Exception:
        return "Invalid URL."
    return None

def sanitize_input(value: str, max_length: int = 255) -> str:
    """Strip leading/trailing whitespace and enforce maximum length."""
    return (value or "").strip()[:max_length]

# ─────────────────────────── Security headers ────────────────────────────────

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if os.environ.get("FLASK_ENV") != "development":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Basic CSP — tighten per your frontend's CDN list
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# ─────────────────────────── Request ID middleware ───────────────────────────

@app.before_request
def attach_request_id():
    g.request_id = secrets.token_hex(8)
    g.request_start = time.monotonic()
    # Session hardening — enforce absolute expiry and touch last_active
    token = session.get("session_token")
    if token:
        _touch_session(token)
    user_id = session.get("user_id")
    if user_id and not token:
        # Legacy session without token — still valid, just not tracked
        pass

@app.after_request
def log_request(response):
    duration_ms = round((time.monotonic() - g.request_start) * 1000)
    logger.info(
        "%s %s %s %dms rid=%s",
        request.method, request.path, response.status_code, duration_ms,
        getattr(g, "request_id", "-"),
    )
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    return response

# ─────────────────────────── DB helpers ──────────────────────────────────────

def _is_pg() -> bool:
    """Return True when a PostgreSQL DATABASE_URL is configured."""
    return bool(os.environ.get("DATABASE_URL", "").strip()) and HAS_PSYCOPG2


def _pg_connect():
    """Open a psycopg2 connection using DATABASE_URL."""
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    conn.autocommit = False
    psycopg2.extras.register_default_jsonb(conn)
    return conn


def get_db():
    if "db" not in g:
        if _is_pg():
            conn = _pg_connect()
            g.db = conn
        else:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA cache_size=-8192")
            conn.execute("PRAGMA temp_store=MEMORY")
            g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()

def _open_db():
    """Open a standalone DB connection for use outside a request context."""
    if _is_pg():
        return _pg_connect()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def ensure_column(db, table: str, column: str, ddl: str) -> None:
    if _is_pg():
        cur = db.cursor()
        cur.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
            (table, column),
        )
        if cur.fetchone() is None:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
            db.commit()
    else:
        cols = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", sanitize_input(value).lower()).strip("-")
    return cleaned or "workspace"

def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name or "upload.log")

def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None

def request_payload() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    if request.form:
        return request.form.to_dict()
    return {}

def send_email_message(subject: str, to_email: str, body_text: str) -> None:
    host     = os.environ.get("SMTP_HOST")
    port     = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender   = os.environ.get("SMTP_FROM", username or "noreply@observex.in")
    if not host:
        logger.warning("SMTP_HOST not configured — email not sent: %s", subject)
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = to_email
    msg.set_content(body_text)
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)

def public_base_url() -> str:
    return os.environ.get("PUBLIC_BASE_URL", "https://observex.in").rstrip("/")


def send_slack_message(webhook_url: str, text: str) -> None:
    """Post a plain-text message to a Slack Incoming Webhook."""
    if not webhook_url or not webhook_url.startswith("https://hooks.slack.com/"):
        logger.warning("Invalid or missing Slack webhook URL — message not sent.")
        return
    try:
        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                logger.warning("Slack webhook returned HTTP %s", resp.status)
    except Exception as exc:
        logger.error("Slack notification failed: %s", exc)


def _call_anthropic(prompt: str, *, max_tokens: int = 512, system: str | None = None) -> str:
    """Call the Anthropic Messages API and return the assistant text.

    Requires ANTHROPIC_API_KEY in the environment. Returns an empty string on
    failure rather than raising so callers degrade gracefully.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not configured — AI call skipped.")
        return ""
    body: dict[str, Any] = {
        "model": "claude-3-5-haiku-20241022",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result["content"][0]["text"].strip()
    except Exception as exc:
        logger.error("Anthropic API call failed: %s", exc)
        return ""

def org_public_url(slug: str) -> str:
    return f"https://{slug}.observex.in"

def create_verification_token(user_id: int) -> str:
    db = get_db()
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO verification_tokens (user_id, token, status, created_at, expires_at) VALUES (?, ?, 'pending', ?, ?)",
        (user_id, token, iso_now(), (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()),
    )
    db.commit()
    return token

def init_db() -> None:
    db = _open_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            theme_color TEXT NOT NULL DEFAULT '#5b8cff',
            theme_mode TEXT NOT NULL DEFAULT 'white',
            logo_text TEXT NOT NULL DEFAULT 'VX',
            admin_only INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS integrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            settings_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS ingestion_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            integration_id INTEGER,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            schedule TEXT NOT NULL,
            last_run_at TEXT,
            next_run_at TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(integration_id) REFERENCES integrations(id)
        );

        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            condition_text TEXT NOT NULL,
            status TEXT NOT NULL,
            channel TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            total_records INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            upload_id INTEGER,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            source TEXT NOT NULL,
            event_id TEXT,
            message TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status_code INTEGER,
            duration_ms REAL,
            req_user_id TEXT,
            request_id TEXT,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(upload_id) REFERENCES uploads(id)
        );

        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            org_id INTEGER NOT NULL,
            session_token TEXT NOT NULL UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            last_active_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            detail_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_by INTEGER,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS saved_dashboards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            prefix TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS demo_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            company TEXT,
            email TEXT NOT NULL,
            message TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ingestion_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            job_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            record_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(job_id) REFERENCES ingestion_jobs(id)
        );

        CREATE TABLE IF NOT EXISTS observability_fired (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            alert_rule_id INTEGER,
            trigger_key TEXT NOT NULL,
            fired_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            filters_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );

        CREATE TABLE IF NOT EXISTS log_annotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            log_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            tag TEXT NOT NULL DEFAULT 'note',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(log_id) REFERENCES log_events(id)
        );

        -- Indexes for common query patterns
        CREATE INDEX IF NOT EXISTS idx_logs_org_ts     ON log_events(org_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_org_level  ON log_events(org_id, level);
        CREATE INDEX IF NOT EXISTS idx_logs_org_source ON log_events(org_id, source);
        CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_org      ON alert_rules(org_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_org        ON ingestion_jobs(org_id);
        CREATE INDEX IF NOT EXISTS idx_audit_org       ON audit_events(org_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash   ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix, status);
        CREATE INDEX IF NOT EXISTS idx_obs_fired       ON observability_fired(org_id, trigger_key, fired_at);
        CREATE INDEX IF NOT EXISTS idx_vt_token        ON verification_tokens(token);
        CREATE INDEX IF NOT EXISTS idx_pr_token        ON password_resets(token);
        CREATE INDEX IF NOT EXISTS idx_inv_token       ON invitations(token);

        CREATE TABLE IF NOT EXISTS error_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            sample_message TEXT NOT NULL DEFAULT '',
            UNIQUE(org_id, fingerprint),
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );
        CREATE INDEX IF NOT EXISTS idx_fingerprints_org ON error_fingerprints(org_id, last_seen_at DESC);

        CREATE INDEX IF NOT EXISTS idx_sessions_user    ON user_sessions(user_id, revoked);
        CREATE INDEX IF NOT EXISTS idx_sessions_token   ON user_sessions(session_token);
        """
    )

    # FTS5 full-text search (SQLite only — skip on PostgreSQL)
    if not _is_pg():
        try:
            db.execute(
                """CREATE VIRTUAL TABLE IF NOT EXISTS log_fts
                   USING fts5(message, content='log_events', content_rowid='id')"""
            )
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS log_fts_ai
                   AFTER INSERT ON log_events BEGIN
                       INSERT INTO log_fts(rowid, message) VALUES (new.id, new.message);
                   END"""
            )
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS log_fts_ad
                   AFTER DELETE ON log_events BEGIN
                       INSERT INTO log_fts(log_fts, rowid, message) VALUES('delete', old.id, old.message);
                   END"""
            )
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS log_fts_au
                   AFTER UPDATE ON log_events BEGIN
                       INSERT INTO log_fts(log_fts, rowid, message) VALUES('delete', old.id, old.message);
                       INSERT INTO log_fts(rowid, message) VALUES (new.id, new.message);
                   END"""
            )
        except Exception as exc:
            logger.warning("FTS5 setup skipped: %s", exc)

    ensure_column(db, "organizations", "theme_mode",       "theme_mode TEXT NOT NULL DEFAULT 'white'")
    ensure_column(db, "organizations", "admin_only",        "admin_only INTEGER NOT NULL DEFAULT 0")
    ensure_column(db, "organizations", "retention_days",    "retention_days INTEGER NOT NULL DEFAULT 90")
    ensure_column(db, "ingestion_jobs", "integration_id",   "integration_id INTEGER")
    ensure_column(db, "users",          "email_verified",   "email_verified INTEGER NOT NULL DEFAULT 0")
    ensure_column(db, "alert_rules",    "notify_email",     "notify_email TEXT")
    ensure_column(db, "alert_rules",    "threshold",        "threshold INTEGER NOT NULL DEFAULT 10")
    ensure_column(db, "alert_rules",    "alert_type",       "alert_type TEXT NOT NULL DEFAULT 'error_rate'")
    ensure_column(db, "alert_rules",    "slack_webhook_url","slack_webhook_url TEXT")
    ensure_column(db, "uploads",        "source_type",      "source_type TEXT NOT NULL DEFAULT 'file'")
    ensure_column(db, "log_events",     "correlation_id",   "correlation_id TEXT")
    ensure_column(db, "log_events",     "status_code",      "status_code INTEGER")
    ensure_column(db, "log_events",     "duration_ms",      "duration_ms REAL")
    ensure_column(db, "log_events",     "req_user_id",      "req_user_id TEXT")
    ensure_column(db, "log_events",     "request_id",       "request_id TEXT")
    ensure_column(db, "api_keys",       "scopes",           "scopes TEXT NOT NULL DEFAULT 'ingest,read,admin'")
    ensure_column(db, "organizations",  "ingest_rate_limit","ingest_rate_limit INTEGER NOT NULL DEFAULT 10000")
    ensure_column(db, "alert_rules",    "latency_threshold_ms", "latency_threshold_ms INTEGER")
    ensure_column(db, "alert_rules",    "dead_source_minutes",  "dead_source_minutes INTEGER")

    # These indexes reference columns added via ensure_column above, so they must
    # come AFTER ensure_column — not inside the executescript block.
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_log_status_code ON log_events(org_id, status_code)",
        "CREATE INDEX IF NOT EXISTS idx_log_duration    ON log_events(org_id, duration_ms)",
        "CREATE INDEX IF NOT EXISTS idx_log_request_id  ON log_events(request_id)",
    ]:
        try:
            db.execute(idx_sql)
        except Exception as exc:
            logger.warning("Index creation skipped: %s — %s", idx_sql[:60], exc)

    # Seed demo workspace — slug/email configurable via env vars
    seed_slug  = os.environ.get("SEED_ORG_SLUG",   "vewit")
    seed_email = os.environ.get("SEED_ADMIN_EMAIL", "admin@vewit.local")
    row = db.execute("SELECT id FROM organizations WHERE slug = ?", (seed_slug,)).fetchone()
    if row is None:
        now = iso_now()
        admin_password = os.environ.get("SEED_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        db.execute(
            "INSERT INTO organizations (name, slug, theme_color, theme_mode, logo_text, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (seed_slug.capitalize(), seed_slug, DEFAULT_THEME_COLORS["white"], "white", seed_slug[:2].upper(), 0, now),
        )
        org_id = db.execute("SELECT id FROM organizations WHERE slug = ?", (seed_slug,)).fetchone()[0]
        db.execute(
            "INSERT INTO users (org_id, name, email, password_hash, role, created_at, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, "Platform Admin", seed_email, generate_password_hash(admin_password), "admin", now, 1),
        )
        admin_id = db.execute("SELECT id FROM users WHERE email = ?", (seed_email,)).fetchone()[0]
        db.execute(
            "INSERT INTO audit_events (org_id, user_id, action, target_type, target_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, admin_id, "seeded_demo_workspace", "workspace", str(org_id), json.dumps({"email": seed_email}), now),
        )
        logger.info("Seeded demo workspace (slug=%s). Admin password: %s", seed_slug, admin_password)
    db.commit()
    db.close()


# ─────────────────────────── Auth & audit ────────────────────────────────────

def require_auth() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    user_id = session.get("user_id")
    if not user_id:
        return None, (jsonify({"error": "Authentication required."}), 401)
    db = get_db()
    row = db.execute(
        """
        SELECT u.id, u.name, u.email, u.role, u.org_id,
               o.name AS org_name, o.slug, o.theme_color, o.theme_mode, o.logo_text, o.admin_only
        FROM users u
        JOIN organizations o ON o.id = u.org_id
        WHERE u.id = ?
        """,
        (user_id,),
    ).fetchone()
    if not row:
        session.clear()
        return None, (jsonify({"error": "Session expired."}), 401)
    return dict(row), None

def require_admin() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    user, error = require_auth()
    if error:
        return None, error
    if user["role"] != "admin":
        return None, (jsonify({"error": "Admin access required."}), 403)
    return user, None

# Role hierarchy: higher number = more privilege
ROLE_LEVELS: dict[str, int] = {
    "tester":    1,
    "developer": 2,
    "manager":   3,
    "admin":     4,
}

def require_role(min_role: str) -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    """Require the authenticated user to have at least `min_role` privilege.

    Role hierarchy (ascending): tester → developer → manager → admin.
    - tester:    read-only access
    - developer: read + create API keys + run jobs + saved searches
    - manager:   developer + manage integrations, alerts, jobs, invitations
    - admin:     full access including org settings, users, retention
    """
    user, error = require_auth()
    if error:
        return None, error
    user_level = ROLE_LEVELS.get(user["role"], 0)
    min_level  = ROLE_LEVELS.get(min_role, 99)
    if user_level < min_level:
        return None, (jsonify({"error": f"Insufficient permissions. '{min_role}' role or above required."}), 403)
    return user, None

def require_api_key(required_scope: str | None = None) -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    """Authenticate via Bearer token (API key). Uses an in-process cache to
    avoid running bcrypt on every single request — critical for high throughput.
    Optionally enforces a required scope ('ingest', 'read', 'admin').
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_key = auth_header[7:].strip()
    else:
        raw_key = request.headers.get("X-API-Key", "").strip()
    if not raw_key:
        return None, (jsonify({"error": "API key required. Pass Authorization: Bearer <key> or X-API-Key header."}), 401)

    # 1. Try cache first (O(1) lookup, no bcrypt)
    cached = _get_cached_key(raw_key)
    if cached is not None:
        _update_key_last_used_async(cached["id"])
        if required_scope:
            scopes = [s.strip() for s in (cached.get("scopes") or "ingest,read,admin").split(",")]
            if required_scope not in scopes:
                return None, (jsonify({"error": f"API key missing required scope: '{required_scope}'."}), 403)
        return cached, None

    # 2. Cache miss: look up by prefix, then verify hash
    db = get_db()
    prefix = raw_key[:8]
    rows = db.execute(
        """SELECT ak.*, u.role, u.name AS user_name, o.slug, o.ingest_rate_limit
           FROM api_keys ak
           JOIN users u ON u.id = ak.user_id
           JOIN organizations o ON o.id = ak.org_id
           WHERE ak.prefix = ? AND ak.status = 'active'""",
        (prefix,),
    ).fetchall()
    for row in rows:
        if check_password_hash(row["key_hash"], raw_key):
            key_info = dict(row)
            _set_cached_key(raw_key, key_info)
            db.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (iso_now(), row["id"]))
            db.commit()
            if required_scope:
                scopes = [s.strip() for s in (key_info.get("scopes") or "ingest,read,admin").split(",")]
                if required_scope not in scopes:
                    return None, (jsonify({"error": f"API key missing required scope: '{required_scope}'."}), 403)
            return key_info, None

    return None, (jsonify({"error": "Invalid or revoked API key."}), 401)

def _update_key_last_used_async(key_id: int) -> None:
    """Fire-and-forget last_used_at update so cache hits don't block."""
    def _update():
        try:
            conn = _open_db()
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (iso_now(), key_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
    t = threading.Thread(target=_update, daemon=True)
    t.start()

def audit(org_id: int, user_id: int | None, action: str, target_type: str, target_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO audit_events (org_id, user_id, action, target_type, target_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, user_id, action, target_type, target_id, json.dumps(detail or {}), iso_now()),
    )
    db.commit()


# ─────────────────────────── Structured field extractor ──────────────────────

_STATUS_KEYS   = {"status_code", "status", "statusCode", "http_status", "httpStatus", "code"}
_DURATION_KEYS = {"duration_ms", "duration", "elapsed_ms", "elapsed", "latency_ms", "latency", "responseTime", "response_time"}
_RUSER_KEYS    = {"user_id", "userId", "user", "account_id", "accountId", "customerId"}
_REQID_KEYS    = {"request_id", "requestId", "req_id", "trace_id", "traceId", "x-request-id"}

def extract_structured_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote well-known keys from payload into indexed top-level fields."""
    out: dict[str, Any] = {}
    flat = {}
    # Flatten one level deep
    for k, v in payload.items():
        flat[k] = v
        if isinstance(v, dict):
            for k2, v2 in v.items():
                flat[k2] = v2

    for k, v in flat.items():
        if k in _STATUS_KEYS and out.get("status_code") is None:
            try:
                sc = int(v)
                if 100 <= sc <= 599:
                    out["status_code"] = sc
            except (TypeError, ValueError):
                pass
        if k in _DURATION_KEYS and out.get("duration_ms") is None:
            try:
                out["duration_ms"] = float(v)
            except (TypeError, ValueError):
                pass
        if k in _RUSER_KEYS and out.get("req_user_id") is None:
            out["req_user_id"] = str(v)[:100]
        if k in _REQID_KEYS and out.get("request_id") is None:
            out["request_id"] = str(v)[:100]
    return out


# ─────────────────────────── Session helpers ──────────────────────────────────
SESSION_MAX_AGE_DAYS = int(os.environ.get("SESSION_MAX_AGE_DAYS", "7"))

def _create_user_session(db: Any, user_id: int, org_id: int) -> str:
    """Insert a user_sessions row and return the opaque token stored in Flask session."""
    token     = secrets.token_urlsafe(32)
    now       = iso_now()
    expires   = (datetime.now(timezone.utc) + timedelta(days=SESSION_MAX_AGE_DAYS)).isoformat()
    ip        = request.remote_addr or ""
    ua        = (request.headers.get("User-Agent") or "")[:200]
    db.execute(
        "INSERT INTO user_sessions (user_id, org_id, session_token, ip_address, user_agent, created_at, last_active_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (user_id, org_id, token, ip, ua, now, now, expires),
    )
    return token

def _touch_session(token: str) -> None:
    """Update last_active_at in a background thread — fire-and-forget."""
    def _do():
        try:
            conn = _open_db()
            conn.execute("UPDATE user_sessions SET last_active_at=? WHERE session_token=?", (iso_now(), token))
            conn.commit()
            conn.close()
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()

def _revoke_session(token: str) -> None:
    try:
        conn = _open_db()
        conn.execute("UPDATE user_sessions SET revoked=1 WHERE session_token=?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ─────────────────────────── Log parsing ─────────────────────────────────────

def redact_sensitive(text: str) -> str:
    redacted = text
    for pattern, replacement in MASK_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted

def parse_timestamp(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            factor = 1000 if float(value) > 1e11 else 1
            ts = datetime.fromtimestamp(float(value) / factor, tz=timezone.utc)
            return ts.isoformat()
        except Exception:
            return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    text = str(value).strip()
    for parser in (
        lambda x: datetime.fromisoformat(x.replace("Z", "+00:00")),
        lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
        lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S,%f"),
        lambda x: datetime.strptime(x, "%d-%m-%Y %H:%M:%S"),
    ):
        try:
            dt = parser(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass
    return None

def first_value(payload: dict[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return str(payload[key])
    return default

def detect_level(text: str, payload: dict[str, Any] | None = None) -> str:
    level_candidates = []
    if payload:
        for key in ["level", "severity", "logLevel", "status"]:
            value = payload.get(key)
            if value is not None:
                level_candidates.append(str(value).lower())
    level_candidates.append((text or "").lower())
    blob = " ".join(level_candidates)
    for level, patterns in LEVEL_PATTERNS.items():
        if any(re.search(pattern, blob, flags=re.I) for pattern in patterns):
            return level
    return "info"

def to_record(payload: dict[str, Any], fallback_message: str = "") -> dict[str, Any]:
    message  = first_value(payload, MESSAGE_KEYS, fallback_message)
    ts       = None
    for key in TS_KEYS:
        if key in payload:
            ts = parse_timestamp(payload[key])
            if ts:
                break
    source   = first_value(payload, SOURCE_KEYS, "system")
    ref_id   = first_value(payload, ID_KEYS, "")
    return {
        "timestamp": ts or iso_now(),
        "level":     detect_level(message, payload),
        "source":    source,
        "event_id":  ref_id,
        "message":   redact_sensitive(message or fallback_message or "Log event"),
        "payload":   payload,
    }

def split_multiline_events(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if HEADER_RE.match(line) and current:
            blocks.append("\n".join(current).rstrip())
            current = [line]
        else:
            if line or current:
                current.append(line)
    if current:
        blocks.append("\n".join(current).rstrip())
    return [b for b in blocks if b.strip()]

def parse_json_text(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    stripped = text.strip()
    if not stripped:
        return records
    try:
        obj = json.loads(stripped)
        if isinstance(obj, list):
            return [to_record(item) for item in obj if isinstance(item, dict)]
        if isinstance(obj, dict):
            if "logEvents" in obj and isinstance(obj["logEvents"], list):
                for event in obj["logEvents"]:
                    if isinstance(event, dict):
                        inner = {
                            "timestamp": event.get("timestamp"),
                            "message":   event.get("message"),
                            "source":    obj.get("logGroup", "aws-cloudwatch"),
                        }
                        records.append(to_record(inner, event.get("message", "")))
                return records
            return [to_record(obj)]
    except json.JSONDecodeError:
        pass
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(to_record(obj))
        except json.JSONDecodeError:
            continue
    return records

def parse_csv_text(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        cleaned = {k: v for k, v in row.items() if k is not None}
        records.append(to_record(cleaned))
    return records

def parse_mule_block(block: str) -> dict[str, Any]:
    lines  = block.splitlines()
    header = lines[0] if lines else block
    header_match = re.match(
        r"^(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+\[(?P<thread>.*?)\]\s+\[(?P<meta>.*?)\]\s+(?P<logger>[^:]+):\s?(?P<msg>.*)$",
        header,
    )
    if not header_match:
        return {
            "timestamp": iso_now(),
            "level":     detect_level(block),
            "source":    "system",
            "event_id":  "",
            "message":   redact_sensitive(block),
            "payload":   {"raw": redact_sensitive(block)},
        }
    data         = header_match.groupdict()
    source_match = re.search(r"\[([^\]]+)\]\.([^\.\s]+)", data["thread"])
    source       = source_match.group(1) if source_match else "system"
    event_id_m   = re.search(r"event:\s*([^\];]+)", data["meta"])
    event_id     = event_id_m.group(1).strip() if event_id_m else ""
    body_lines   = lines[1:]
    combined_msg = data["msg"]
    if body_lines:
        combined_msg += "\n" + "\n".join(body_lines)
    combined_msg = redact_sensitive(combined_msg.strip())
    payload: dict[str, Any] = {
        "timestamp":     data["ts"],
        "level":         data["level"],
        "source":        source,
        "logger":        data["logger"].strip(),
        "thread":        data["thread"],
        "correlationId": event_id,
        "message":       combined_msg,
        "raw":           redact_sensitive(block),
    }
    json_candidate = None
    msg_start = data["msg"].strip()
    if msg_start.startswith("{"):
        json_candidate = "\n".join([data["msg"]] + body_lines)
    elif body_lines and body_lines[0].strip().startswith("{"):
        json_candidate = "\n".join(body_lines)
    if json_candidate:
        try:
            parsed_json = json.loads(json_candidate)
            payload["parsed"] = parsed_json
            common = parsed_json.get("common") if isinstance(parsed_json, dict) else None
            if isinstance(common, dict):
                payload["source"]        = common.get("ApplicationName", source)
                payload["correlationId"] = common.get("correlationId", event_id)
                source   = payload["source"]
                event_id = payload["correlationId"]
        except Exception:
            pass
    return {
        "timestamp": parse_timestamp(data["ts"]) or iso_now(),
        "level":     data["level"].lower(),
        "source":    source,
        "event_id":  event_id,
        "message":   combined_msg,
        "payload":   payload,
    }

def parse_plain_text(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    blocks = split_multiline_events(text)
    if blocks and any(HEADER_RE.match(block.splitlines()[0]) for block in blocks):
        return [parse_mule_block(block) for block in blocks]
    for line in text.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        ts_match  = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+(.*)$", line)
        timestamp = iso_now()
        message   = line
        if ts_match:
            timestamp = parse_timestamp(ts_match.group(1)) or iso_now()
            message   = ts_match.group(2)
        eid_m  = re.search(r"\b(?:eventId|requestId|traceId|correlationId|transactionId)[=: ]+([A-Za-z0-9._:-]+)", line, re.I)
        src_m  = re.search(r"\[([^\]]+)\]", line)
        records.append({
            "timestamp": timestamp,
            "level":     detect_level(message),
            "source":    src_m.group(1) if src_m else "system",
            "event_id":  eid_m.group(1) if eid_m else "",
            "message":   redact_sensitive(message),
            "payload":   {"raw": redact_sensitive(line)},
        })
    return records

def parse_text_by_extension(filename: str, text: str) -> list[dict[str, Any]]:
    ext = Path(filename).suffix.lower()
    if ext in {".json", ".ndjson"}:
        records = parse_json_text(text)
        return records if records else parse_plain_text(text)
    if ext == ".csv":
        records = parse_csv_text(text)
        return records if records else parse_plain_text(text)
    records = parse_json_text(text)
    return records if records else parse_plain_text(text)

def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    total   = len(records)
    levels  = Counter(record["level"] for record in records)
    sources = Counter(record["source"] for record in records)
    terms: Counter[str] = Counter()
    for record in records:
        words = re.findall(r"[A-Za-z][A-Za-z0-9._-]{3,}", record["message"])
        terms.update(word.lower() for word in words[:8])
    sorted_records = sorted(records, key=lambda r: r["timestamp"], reverse=True)
    return {
        "total":      total,
        "levels":     dict(levels),
        "sources":    sources.most_common(8),
        "top_terms":  terms.most_common(12),
        "recent":     sorted_records[:30],
    }

def dashboard_summary(org_id: int) -> dict[str, Any]:
    db = get_db()
    counts = db.execute(
        "SELECT level, COUNT(*) AS count FROM log_events WHERE org_id = ? GROUP BY level",
        (org_id,),
    ).fetchall()
    level_counts = {row["level"]: row["count"] for row in counts}
    total_logs   = sum(level_counts.values())
    integrations = db.execute("SELECT COUNT(*) FROM integrations WHERE org_id = ?", (org_id,)).fetchone()[0]
    jobs         = db.execute("SELECT COUNT(*) FROM ingestion_jobs WHERE org_id = ?", (org_id,)).fetchone()[0]
    alerts       = db.execute("SELECT COUNT(*) FROM alert_rules WHERE org_id = ?", (org_id,)).fetchone()[0]
    users        = db.execute("SELECT COUNT(*) FROM users WHERE org_id = ?", (org_id,)).fetchone()[0]
    uploads      = db.execute("SELECT COUNT(*) FROM uploads WHERE org_id = ?", (org_id,)).fetchone()[0]
    error_rate   = round((level_counts.get("error", 0) / total_logs) * 100, 2) if total_logs else 0
    recent_sources = [dict(row) for row in db.execute(
        "SELECT source, COUNT(*) AS count FROM log_events WHERE org_id = ? GROUP BY source ORDER BY count DESC LIMIT 6",
        (org_id,),
    ).fetchall()]
    latest_log = db.execute("SELECT MAX(timestamp) FROM log_events WHERE org_id = ?", (org_id,)).fetchone()[0]
    uploads_week = db.execute(
        "SELECT COUNT(*) FROM uploads WHERE org_id = ? AND created_at >= ?",
        (org_id, (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()),
    ).fetchone()[0]
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    ts_rows = db.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS hour, level, COUNT(*) AS count "
        "FROM log_events WHERE org_id = ? AND timestamp >= ? GROUP BY hour, level ORDER BY hour",
        (org_id, since_24h),
    ).fetchall()
    time_series: dict[str, dict[str, int]] = {}
    for row in ts_rows:
        hour = row["hour"] or ""
        if hour not in time_series:
            time_series[hour] = {}
        time_series[hour][row["level"]] = row["count"]
    since_30d = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    daily_rows = db.execute(
        "SELECT strftime('%Y-%m-%d', timestamp) AS day, COUNT(*) AS count "
        "FROM log_events WHERE org_id = ? AND timestamp >= ? GROUP BY day ORDER BY day",
        (org_id, since_30d),
    ).fetchall()
    daily_series = [{"day": row["day"], "count": row["count"]} for row in daily_rows]
    return {
        "totals":          {"logs": total_logs, "integrations": integrations, "jobs": jobs, "alerts": alerts, "users": users, "uploads": uploads},
        "levels":          level_counts,
        "error_rate":      error_rate,
        "source_breakdown": recent_sources,
        "latest_log":      latest_log,
        "uploads_week":    uploads_week,
        "time_series":     time_series,
        "daily_series":    daily_series,
    }


# ─────────────────────────── Ingestion helpers ───────────────────────────────

def parse_cron_next_run(expr: str) -> str | None:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    try:
        minute, hour, *_ = expr.split()
        for i in range(1, 24 * 60 + 1):
            candidate  = now + timedelta(minutes=i)
            minute_ok  = minute == "*" or minute == f"{candidate.minute}" or (minute.startswith("*/") and candidate.minute % int(minute[2:]) == 0)
            hour_ok    = hour == "*" or hour == f"{candidate.hour}" or (hour.startswith("*/") and candidate.hour % int(hour[2:]) == 0)
            if minute_ok and hour_ok:
                return candidate.isoformat()
    except Exception:
        return None
    return None

def fetch_latest_integration(org_id: int, source_type: str) -> dict[str, Any] | None:
    db = get_db()
    row = db.execute(
        "SELECT * FROM integrations WHERE org_id = ? AND kind = ? ORDER BY updated_at DESC LIMIT 1",
        (org_id, source_type),
    ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["settings"] = json.loads(item["settings_json"])
    return item

def run_ingestion_job_internal(user: dict[str, Any], job_id: int) -> tuple[bool, str, int]:
    db = get_db()
    row = db.execute("SELECT * FROM ingestion_jobs WHERE id = ? AND org_id = ?", (job_id, user["org_id"])).fetchone()
    if not row:
        return False, "Job not found.", 0
    job         = dict(row)
    details     = json.loads(job["details_json"] or "{}")
    integration = fetch_latest_integration(user["org_id"], job["source_type"])
    now         = iso_now()
    records: list[dict[str, Any]] = []

    if job["source_type"] == "api":
        if _requests_lib is None:
            return False, "requests is not installed.", 0
        if not integration:
            return False, "No API integration configured.", 0
        settings = integration["settings"]
        headers  = settings.get("headers") or {}
        token    = settings.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp    = _requests_lib.get(settings.get("url"), headers=headers, timeout=15)
        records = parse_text_by_extension("remote_api.json", resp.text)
        if not records:
            records = [to_record({"timestamp": now, "source": settings.get("name", "remote-api"), "message": resp.text[:4000]})]
    elif job["source_type"] == "s3":
        if boto3 is None:
            return False, "boto3 is not installed.", 0
        if not integration:
            return False, "No S3 integration configured.", 0
        settings    = integration["settings"]
        session_aws = boto3.session.Session(
            aws_access_key_id=settings.get("access_key"),
            aws_secret_access_key=settings.get("secret_key"),
            region_name=settings.get("region"),
        )
        client = session_aws.client("s3")
        resp   = client.list_objects_v2(Bucket=settings.get("bucket"), Prefix=settings.get("prefix", ""), MaxKeys=int(details.get("max_keys", 3)))
        for item in resp.get("Contents", []):
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue
            obj     = client.get_object(Bucket=settings.get("bucket"), Key=key)
            content = obj["Body"].read(2 * 1024 * 1024).decode("utf-8", errors="ignore")
            records.extend(parse_text_by_extension(key, content))
    else:
        return False, "Unsupported job source.", 0

    if not records:
        return False, "No records were ingested.", 0

    upload_cur = db.execute(
        "INSERT INTO uploads (org_id, user_id, filename, total_records, created_at) VALUES (?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], f"job-{job_id}-{job['source_type']}", len(records), now),
    )
    upload_id = upload_cur.lastrowid
    db.executemany(
        "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(user["org_id"], upload_id, rec["timestamp"], rec["level"], rec["source"], rec.get("event_id") or "", rec["message"], json.dumps(rec.get("payload", {})), now) for rec in records],
    )
    db.execute(
        "UPDATE ingestion_jobs SET last_run_at = ?, next_run_at = ? WHERE id = ?",
        (now, parse_cron_next_run(job["schedule"] or "*/15 * * * *"), job_id),
    )
    db.commit()
    audit(user["org_id"], user["id"], "ran_ingestion_job", "job", str(job_id), {"records": len(records), "source_type": job["source_type"]})
    return True, f"Job ran successfully and ingested {len(records)} records.", len(records)

def _run_job_in_worker(job_id: int) -> None:
    """Executed inside the ThreadPoolExecutor — has its own DB connection."""
    conn = _open_db()
    run_id = None
    try:
        job      = conn.execute("SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        if not job:
            return
        user_row = conn.execute(
            "SELECT u.id, u.org_id, u.role, o.slug, o.name AS org_name, o.theme_color, o.theme_mode, o.logo_text, o.admin_only, u.email, u.name "
            "FROM users u JOIN organizations o ON o.id = u.org_id "
            "WHERE u.org_id = ? ORDER BY CASE WHEN u.role='admin' THEN 0 ELSE 1 END, u.id LIMIT 1",
            (job["org_id"],),
        ).fetchone()
        run_id = conn.execute(
            "INSERT INTO ingestion_runs (org_id, job_id, status, message, record_count, created_at) VALUES (?, ?, 'running', ?, 0, ?)",
            (job["org_id"], job_id, "Background ingestion started.", iso_now()),
        ).lastrowid
        conn.commit()

        if not user_row:
            conn.execute("UPDATE ingestion_runs SET status='failed', message=?, completed_at=? WHERE id=?",
                         ("No admin user found.", iso_now(), run_id))
            conn.commit()
            return

        with app.app_context():
            # Use a fresh g.db for this app context
            g.db = _open_db()
            try:
                success, message, count = run_ingestion_job_internal(dict(user_row), job_id)
                conn.execute(
                    "UPDATE ingestion_runs SET status=?, message=?, record_count=?, completed_at=? WHERE id=?",
                    ("completed" if success else "failed", message, count, iso_now(), run_id),
                )
                conn.commit()
            except Exception as exc:
                logger.exception("Ingestion job %d failed", job_id)
                conn.execute(
                    "UPDATE ingestion_runs SET status='failed', message=?, completed_at=? WHERE id=?",
                    (str(exc)[:500], iso_now(), run_id),
                )
                conn.commit()
            finally:
                g.db.close()
    finally:
        conn.close()

def ingestion_queue_consumer() -> None:
    """Single consumer thread that dispatches jobs into the thread pool."""
    while True:
        job_id = INGESTION_QUEUE.get()
        try:
            if _WORKER_POOL is not None:
                _WORKER_POOL.submit(_run_job_in_worker, job_id)
        except Exception:
            logger.exception("Failed to submit job %d to pool", job_id)
        finally:
            INGESTION_QUEUE.task_done()

def start_worker() -> None:
    global _WORKER_POOL
    if _WORKER_POOL is not None:
        return
    # Thread pool — scale workers via env var (default 4)
    pool_size   = int(os.environ.get("INGESTION_WORKERS", "4"))
    _WORKER_POOL = ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="observex-ingest")
    consumer    = threading.Thread(target=ingestion_queue_consumer, daemon=True, name="observex-queue-consumer")
    consumer.start()
    logger.info("Ingestion worker pool started with %d threads", pool_size)

def _fire_alert(conn: Any, org_id: int, rule: Any, subject: str, body: str, now_str: str, tk: str) -> None:
    """Fire email + Slack for a rule and record in observability_fired."""
    email_to   = (rule["notify_email"]     or "").strip() if "notify_email"     in rule.keys() else ""
    slack_hook = (rule["slack_webhook_url"] or "").strip() if "slack_webhook_url" in rule.keys() else ""
    if email_to:
        try:
            send_email_message(subject, email_to, body)
        except Exception as exc:
            logger.error("Alert email failed org=%d: %s", org_id, exc)
    if slack_hook:
        try:
            send_slack_message(slack_hook, f":rotating_light: *{subject}*\n{body}")
        except Exception as exc:
            logger.error("Alert Slack failed org=%d: %s", org_id, exc)
    conn.execute(
        "INSERT INTO observability_fired (org_id, alert_rule_id, trigger_key, fired_at) VALUES (?,?,?,?)",
        (org_id, rule["id"] if hasattr(rule, "keys") and "id" in rule.keys() else None, tk, now_str),
    )


def scheduler_tick() -> None:
    conn = _open_db()
    try:
        now_str = iso_now()
        now_dt  = datetime.now(timezone.utc)

        # ── 1. Dispatch scheduled ingestion jobs ──────────────────────────────
        due = conn.execute(
            "SELECT * FROM ingestion_jobs WHERE status = 'scheduled' AND next_run_at IS NOT NULL AND next_run_at <= ?",
            (now_str,),
        ).fetchall()
        for job in due:
            try:
                INGESTION_QUEUE.put_nowait(job["id"])
            except Full:
                logger.warning("Ingestion queue full — skipping scheduled job %d", job["id"])

        orgs        = conn.execute("SELECT id, retention_days FROM organizations").fetchall()
        window_1h   = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        window_7d   = (now_dt - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        cooldown_4h = (now_dt - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%S")
        cooldown_1h = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")

        for org_row in orgs:
            org_id = org_row["id"]
            try:
                active_rules = conn.execute(
                    "SELECT * FROM alert_rules WHERE org_id=? AND status='active'", (org_id,)
                ).fetchall()

                # ── 2. Error spike anomaly detection ─────────────────────────
                hour_errors = conn.execute(
                    "SELECT COUNT(*) FROM log_events WHERE org_id=? AND level='error' AND timestamp>=?",
                    (org_id, window_1h),
                ).fetchone()[0]
                total_7d = conn.execute(
                    "SELECT COUNT(*) FROM log_events WHERE org_id=? AND level='error' AND timestamp>=?",
                    (org_id, window_7d),
                ).fetchone()[0]
                baseline_per_hour = total_7d / (7 * 24) if total_7d else 0

                if hour_errors > max(10, baseline_per_hour * 3):
                    tk = f"anomaly:spike:org:{org_id}"
                    if not conn.execute(
                        "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=? AND fired_at>=?",
                        (org_id, tk, cooldown_4h),
                    ).fetchone():
                        sample_rows = conn.execute(
                            "SELECT message FROM log_events WHERE org_id=? AND level='error' AND timestamp>=? LIMIT 10",
                            (org_id, window_1h),
                        ).fetchall()
                        samples     = "\n".join(r["message"][:200] for r in sample_rows)
                        ai_summary  = _call_anthropic(
                            f"Summarise these error log messages in 2-3 sentences for an ops team alert:\n{samples}",
                            max_tokens=200,
                        ) if samples else ""
                        subject = f"[ObserveX] Error spike — {hour_errors} errors in last hour"
                        body    = (
                            f"Org: {org_id} | Errors/hour: {hour_errors} | Baseline: {baseline_per_hour:.1f} | "
                            f"Ratio: {hour_errors / max(baseline_per_hour, 1):.1f}×"
                            + (f"\n\nAI summary:\n{ai_summary}" if ai_summary else "")
                        )
                        for rule in active_rules:
                            _fire_alert(conn, org_id, rule, subject, body, now_str, tk)

                # ── 3. Latency alerting ───────────────────────────────────────
                latency_rules = [r for r in active_rules
                                 if r["alert_type"] == "latency"
                                 and r["latency_threshold_ms"] is not None]
                for rule in latency_rules:
                    threshold_ms = rule["latency_threshold_ms"]
                    p95_row = conn.execute(
                        """SELECT duration_ms FROM log_events
                           WHERE org_id=? AND duration_ms IS NOT NULL AND timestamp>=?
                           ORDER BY duration_ms DESC
                           LIMIT 1 OFFSET CAST((
                               SELECT COUNT(*) FROM log_events
                               WHERE org_id=? AND duration_ms IS NOT NULL AND timestamp>=?
                           ) * 0.05 AS INTEGER)""",
                        (org_id, window_1h, org_id, window_1h),
                    ).fetchone()
                    if p95_row and p95_row["duration_ms"] is not None:
                        p95 = p95_row["duration_ms"]
                        if p95 > threshold_ms:
                            tk = f"latency:rule:{rule['id']}:org:{org_id}"
                            if not conn.execute(
                                "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=? AND fired_at>=?",
                                (org_id, tk, cooldown_1h),
                            ).fetchone():
                                subject = f"[ObserveX] High latency — p95={p95:.0f}ms (threshold {threshold_ms}ms)"
                                body    = (f"Alert: {rule['name']}\nOrg: {org_id}\n"
                                           f"p95 latency last hour: {p95:.0f}ms\nThreshold: {threshold_ms}ms")
                                _fire_alert(conn, org_id, rule, subject, body, now_str, tk)

                # ── 4. Dead source detection ──────────────────────────────────
                dead_rules = [r for r in active_rules
                              if r["alert_type"] == "dead_source"
                              and r["dead_source_minutes"] is not None]
                if dead_rules:
                    active_sources = conn.execute(
                        "SELECT DISTINCT source FROM log_events WHERE org_id=? AND timestamp>=? AND source != ''",
                        (org_id, (now_dt - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")),
                    ).fetchall()
                    for src_row in active_sources:
                        source = src_row["source"]
                        last   = conn.execute(
                            "SELECT MAX(timestamp) AS last_ts FROM log_events WHERE org_id=? AND source=?",
                            (org_id, source),
                        ).fetchone()
                        if not last or not last["last_ts"]:
                            continue
                        try:
                            last_dt = datetime.fromisoformat(last["last_ts"].replace("Z", "+00:00"))
                            if last_dt.tzinfo is None:
                                last_dt = last_dt.replace(tzinfo=timezone.utc)
                            silent_minutes = (now_dt - last_dt).total_seconds() / 60
                        except Exception:
                            continue
                        for rule in dead_rules:
                            if silent_minutes >= rule["dead_source_minutes"]:
                                tk = f"dead_source:{source}:rule:{rule['id']}"
                                if not conn.execute(
                                    "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=? AND fired_at>=?",
                                    (org_id, tk, cooldown_4h),
                                ).fetchone():
                                    subject = f"[ObserveX] Dead source — '{source}' silent for {silent_minutes:.0f}m"
                                    body    = (f"Alert: {rule['name']}\nSource '{source}' has not sent logs for "
                                               f"{silent_minutes:.0f} minutes (threshold: {rule['dead_source_minutes']} min).\n"
                                               f"Last seen: {last['last_ts']}")
                                    _fire_alert(conn, org_id, rule, subject, body, now_str, tk)

                # ── 5. Generic custom alert rule evaluator ────────────────────
                #    Supports simple expressions in condition_text:
                #    "level=error count>N window=Xm"
                #    "status_code=5xx count>N window=Xm"
                custom_rules = [r for r in active_rules if r["alert_type"] == "custom"]
                _COND_RE = re.compile(
                    r"(?:level\s*=\s*(\w+))?"
                    r".*?(?:status_code\s*=\s*(5xx|4xx|\d+))?"
                    r".*?count\s*>\s*(\d+)"
                    r".*?window\s*=\s*(\d+)m?",
                    re.I,
                )
                for rule in custom_rules:
                    m = _COND_RE.search(rule["condition_text"] or "")
                    if not m:
                        continue
                    lvl_filter, sc_filter, count_str, window_str = m.groups()
                    try:
                        threshold_count = int(count_str)
                        window_mins     = max(1, min(int(window_str), 1440))
                    except (TypeError, ValueError):
                        continue
                    since_w = (now_dt - timedelta(minutes=window_mins)).strftime("%Y-%m-%dT%H:%M:%S")
                    q   = "SELECT COUNT(*) FROM log_events WHERE org_id=? AND timestamp>=?"
                    qp: list[Any] = [org_id, since_w]
                    if lvl_filter:
                        q  += " AND level=?"; qp.append(lvl_filter.lower())
                    if sc_filter:
                        if sc_filter == "5xx":
                            q  += " AND status_code>=500 AND status_code<600"
                        elif sc_filter == "4xx":
                            q  += " AND status_code>=400 AND status_code<500"
                        else:
                            q  += " AND status_code=?"; qp.append(int(sc_filter))
                    actual_count = conn.execute(q, qp).fetchone()[0]
                    if actual_count > threshold_count:
                        tk = f"custom:rule:{rule['id']}:bucket:{int(now_dt.timestamp())//3600}"
                        if not conn.execute(
                            "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=? AND fired_at>=?",
                            (org_id, tk, cooldown_1h),
                        ).fetchone():
                            subject = f"[ObserveX] Alert: {rule['name']} triggered"
                            body    = (f"Rule: {rule['name']}\nCondition: {rule['condition_text']}\n"
                                       f"Actual count in last {window_mins}m: {actual_count} (threshold: {threshold_count})")
                            _fire_alert(conn, org_id, rule, subject, body, now_str, tk)

                # ── 6. First-seen error fingerprint detection ─────────────────
                recent_errors = conn.execute(
                    "SELECT message FROM log_events WHERE org_id=? AND level='error' AND timestamp>=? LIMIT 200",
                    (org_id, window_1h),
                ).fetchall()
                for err_row in recent_errors:
                    raw        = err_row["message"] or ""
                    normalised = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<uuid>", raw, flags=re.I)
                    normalised = re.sub(r"\b\d+\b", "<N>", normalised)
                    fp         = hashlib.md5(normalised[:300].encode()).hexdigest()
                    existing   = conn.execute(
                        "SELECT id FROM error_fingerprints WHERE org_id=? AND fingerprint=?",
                        (org_id, fp),
                    ).fetchone()
                    if existing is None:
                        conn.execute(
                            "INSERT INTO error_fingerprints (org_id, fingerprint, first_seen_at, last_seen_at, count, sample_message) VALUES (?,?,?,?,1,?)",
                            (org_id, fp, now_str, now_str, raw[:500]),
                        )
                        subject = "[ObserveX] New error pattern detected"
                        body    = f"First occurrence of a new error pattern:\n\n{raw[:400]}"
                        for rule in active_rules:
                            _fire_alert(conn, org_id, rule, subject, body, now_str,
                                        f"fingerprint:{fp}:org:{org_id}")
                    else:
                        conn.execute(
                            "UPDATE error_fingerprints SET count=count+1, last_seen_at=? WHERE id=?",
                            (now_str, existing["id"]),
                        )

            except Exception as exc:
                logger.error("Scheduler checks failed for org %d: %s", org_id, exc)

        # ── 7. Weekly digest email — every Sunday at 08:00 UTC ────────────────
        if now_dt.weekday() == 6 and now_dt.hour == 8:
            for org_row in orgs:
                org_id = org_row["id"]
                tk     = f"weekly_digest:org:{org_id}:week:{now_dt.isocalendar()[1]}"
                if conn.execute(
                    "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=?",
                    (org_id, tk),
                ).fetchone():
                    continue
                try:
                    since_7d = window_7d
                    stats    = conn.execute(
                        """SELECT
                             COUNT(*) AS total,
                             SUM(CASE WHEN level='error' THEN 1 ELSE 0 END) AS errors,
                             SUM(CASE WHEN level='warn'  THEN 1 ELSE 0 END) AS warnings,
                             COUNT(DISTINCT source) AS sources
                           FROM log_events WHERE org_id=? AND timestamp>=?""",
                        (org_id, since_7d),
                    ).fetchone()
                    top_fp = conn.execute(
                        "SELECT sample_message, count FROM error_fingerprints WHERE org_id=? ORDER BY count DESC LIMIT 5",
                        (org_id,),
                    ).fetchall()
                    admin_emails = conn.execute(
                        "SELECT email FROM users WHERE org_id=? AND role='admin'", (org_id,)
                    ).fetchall()
                    fp_summary = "\n".join(f"  • ({r['count']}×) {r['sample_message'][:120]}" for r in top_fp)
                    ai_insights = ""
                    if os.environ.get("ANTHROPIC_API_KEY") and fp_summary:
                        ai_insights = _call_anthropic(
                            f"Weekly log digest for an engineering team. Stats: {dict(stats)}.\n"
                            f"Top error patterns:\n{fp_summary}\n"
                            f"Write 3-4 actionable bullet points for the engineering team.",
                            max_tokens=300,
                        )
                    subject = f"[ObserveX] Weekly Digest — {now_dt.strftime('%b %d, %Y')}"
                    body    = (
                        f"Weekly log summary for your workspace\n"
                        f"{'─'*50}\n"
                        f"Period:   Last 7 days\n"
                        f"Total events:  {stats['total'] or 0:,}\n"
                        f"Errors:        {stats['errors'] or 0:,}\n"
                        f"Warnings:      {stats['warnings'] or 0:,}\n"
                        f"Active sources:{stats['sources'] or 0}\n\n"
                        f"Top recurring error patterns:\n{fp_summary or '  None'}\n"
                        + (f"\nAI insights:\n{ai_insights}" if ai_insights else "")
                    )
                    for admin in admin_emails:
                        try:
                            send_email_message(subject, admin["email"], body)
                        except Exception as exc:
                            logger.error("Weekly digest email failed org=%d: %s", org_id, exc)
                    conn.execute(
                        "INSERT INTO observability_fired (org_id, alert_rule_id, trigger_key, fired_at) VALUES (?,?,?,?)",
                        (org_id, None, tk, now_str),
                    )
                except Exception as exc:
                    logger.error("Weekly digest failed for org %d: %s", org_id, exc)

        # ── 8. Nightly log retention — 02:00 UTC ─────────────────────────────
        if now_dt.hour == 2:
            for org_row in orgs:
                retention_days = org_row["retention_days"] or 90
                cutoff = (now_dt - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%S")
                try:
                    deleted = conn.execute(
                        "DELETE FROM log_events WHERE org_id=? AND timestamp<?",
                        (org_row["id"], cutoff),
                    ).rowcount
                    if deleted:
                        logger.info("Retention: deleted %d log events for org %d (>%d days)",
                                    deleted, org_row["id"], retention_days)
                except Exception as exc:
                    logger.error("Retention deletion failed for org %d: %s", org_row["id"], exc)

        conn.commit()
    finally:
        conn.close()

def start_scheduler() -> None:
    global scheduler
    if BackgroundScheduler is None or scheduler is not None:
        return
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(scheduler_tick, "interval", minutes=1, id="observex_scheduler_tick", replace_existing=True)
    scheduler.start()


# ─────────────────────────── Web routes ──────────────────────────────────────

@app.get("/")
def root():
    if session.get("user_id"):
        return redirect("/workspace")
    return render_template("landing.html")

@app.get("/login-page")
def login_page_redirect():
    return redirect("/login")

@app.get("/create-account")
def create_account_page():
    if session.get("user_id"):
        return redirect("/workspace")
    return render_template("create_account.html")

@app.get("/login")
def login_page():
    if session.get("user_id"):
        return redirect("/workspace")
    return render_template("login.html")

@app.get("/workspace")
def workspace():
    user, error = require_auth()
    if error:
        return redirect("/login")
    db   = get_db()
    org  = db.execute("SELECT slug FROM organizations WHERE id = ?", (user["org_id"],)).fetchone()
    slug = org["slug"] if org else "workspace"
    return redirect(f"/workspace/{slug}")

@app.get("/workspace/<slug>")
def workspace_slug(slug: str):
    user, error = require_auth()
    if error:
        return redirect("/login")
    db  = get_db()
    org = db.execute("SELECT id FROM organizations WHERE slug = ? AND id = ?", (slug, user["org_id"])).fetchone()
    if not org:
        return redirect("/workspace")
    return render_template("index.html", user=user, active_section="overview", org_slug=slug)

@app.get("/workspace/<slug>/<section>")
def workspace_section(slug: str, section: str):
    user, error = require_auth()
    if error:
        return redirect("/login")
    db  = get_db()
    org = db.execute("SELECT id FROM organizations WHERE slug = ? AND id = ?", (slug, user["org_id"])).fetchone()
    if not org:
        return redirect("/workspace")
    valid_sections = {"overview", "explorer", "ingest", "integrations", "jobs", "alerts", "users",
                      "dashboards", "invites", "organization", "audit", "observability"}
    safe_section = section if section in valid_sections else "overview"
    return render_template("index.html", user=user, active_section=safe_section, org_slug=slug)


# ─────────────────────────── Auth API ────────────────────────────────────────

@app.post("/login")
@rate_limit("10 per minute; 50 per hour")
def login():
    payload  = request_payload()
    email    = sanitize_input(payload.get("email") or "").lower()
    password = payload.get("password") or ""
    db       = get_db()
    user     = db.execute(
        """SELECT u.id, u.name, u.email, u.role, u.org_id, u.password_hash, u.email_verified, o.admin_only
           FROM users u JOIN organizations o ON o.id = u.org_id WHERE lower(u.email) = ?""",
        (email,),
    ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401
    if user["admin_only"] and user["role"] != "admin":
        return jsonify({"error": "This workspace is in admin-only mode."}), 403
    session.clear()
    session["user_id"]      = user["id"]
    session["csrf"]         = secrets.token_hex(16)
    session["session_token"] = _create_user_session(db, user["id"], user["org_id"])
    db.commit()
    audit(user["org_id"], user["id"], "logged_in", "session", str(user["id"]), {"email": user["email"]})
    return jsonify({"message": "Login successful."})

@app.post("/register")
@rate_limit("5 per minute; 20 per hour")
def register_org_and_admin():
    payload    = request_payload()
    org_name   = sanitize_input(payload.get("organization_name") or "")
    admin_name = sanitize_input(payload.get("name") or "")
    email      = sanitize_input(payload.get("email") or "").lower()
    password   = payload.get("password") or ""
    role       = sanitize_input(payload.get("role") or "admin").lower()
    theme_mode = sanitize_input(payload.get("theme_mode") or "white").lower()
    slug       = slugify(payload.get("organization_slug") or org_name)

    if not org_name or not admin_name or not email or not password:
        return jsonify({"error": "Organization name, your name, email, and password are required."}), 400
    if role != "admin":
        return jsonify({"error": "Workspace creator must be an admin."}), 400
    if theme_mode not in VALID_THEMES:
        theme_mode = "white"

    # Validate password strength
    pw_error = validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    # Basic email format check
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Invalid email address."}), 400

    db = get_db()
    if db.execute("SELECT id FROM organizations WHERE slug = ?", (slug,)).fetchone():
        return jsonify({"error": "That organization slug already exists. Try another organization name."}), 400
    if db.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone():
        return jsonify({"error": "A user with that email already exists."}), 400

    now       = iso_now()
    logo_text = "".join([part[0] for part in org_name.split()[:2]]).upper() or "OX"
    cur       = db.execute(
        "INSERT INTO organizations (name, slug, theme_color, theme_mode, logo_text, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_name, slug, DEFAULT_THEME_COLORS[theme_mode], theme_mode, logo_text[:3], 0, now),
    )
    org_id   = cur.lastrowid
    user_cur = db.execute(
        "INSERT INTO users (org_id, name, email, password_hash, role, created_at, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, admin_name, email, generate_password_hash(password), "admin", now, 1),
    )
    db.commit()
    user_id = user_cur.lastrowid
    session.clear()
    session["user_id"]       = user_id
    session["csrf"]          = secrets.token_hex(16)
    session["session_token"] = _create_user_session(db, user_id, org_id)
    db.commit()
    audit(org_id, user_id, "created_workspace", "organization", str(org_id), {"slug": slug, "email": email})
    return jsonify({
        "message": "Workspace created successfully. Welcome to ObserveX!",
        "slug":    slug,
        "workspace_url": org_public_url(slug),
    })

@app.post("/logout")
def logout():
    user_id = session.get("user_id")
    token   = session.get("session_token")
    user, _ = require_auth() if user_id else (None, None)
    if token:
        _revoke_session(token)
    session.clear()
    if user:
        audit(user["org_id"], user["id"], "logged_out", "session", str(user["id"]), {})
    return jsonify({"message": "Logged out."})


# ─────────────────────────── API ─────────────────────────────────────────────

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "ObserveX Enterprise", "time": iso_now()})

def _get_onboarding_state(db: Any, org_id: int) -> dict[str, Any]:
    """Return a checklist of first-run milestones so the UI can render
    a guided onboarding panel until all steps are complete."""
    has_integration = db.execute(
        "SELECT 1 FROM integrations WHERE org_id = ? LIMIT 1", (org_id,)
    ).fetchone() is not None
    has_logs = db.execute(
        "SELECT 1 FROM log_events WHERE org_id = ? LIMIT 1", (org_id,)
    ).fetchone() is not None
    has_alert = db.execute(
        "SELECT 1 FROM alert_rules WHERE org_id = ? LIMIT 1", (org_id,)
    ).fetchone() is not None
    has_team_member = db.execute(
        "SELECT 1 FROM users WHERE org_id = ? AND id != (SELECT MIN(id) FROM users WHERE org_id = ?) LIMIT 1",
        (org_id, org_id),
    ).fetchone() is not None
    has_api_key = db.execute(
        "SELECT 1 FROM api_keys WHERE org_id = ? AND status = 'active' LIMIT 1", (org_id,)
    ).fetchone() is not None
    steps = [
        {"id": "connect_source",  "label": "Connect a log source",    "done": has_integration},
        {"id": "ingest_logs",     "label": "Ingest your first logs",   "done": has_logs},
        {"id": "create_alert",    "label": "Set up an alert",          "done": has_alert},
        {"id": "create_api_key",  "label": "Generate an API key",      "done": has_api_key},
        {"id": "invite_teammate", "label": "Invite a team member",     "done": has_team_member},
    ]
    return {
        "steps":    steps,
        "complete": all(s["done"] for s in steps),
        "percent":  round(sum(1 for s in steps if s["done"]) / len(steps) * 100),
    }


@app.get("/api/bootstrap")
def bootstrap():
    user, error = require_auth()
    if error:
        return error
    db          = get_db()
    integrations = [dict(row) for row in db.execute(
        "SELECT * FROM integrations WHERE org_id = ? ORDER BY updated_at DESC", (user["org_id"],)
    ).fetchall()]
    jobs        = [dict(row) for row in db.execute(
        "SELECT * FROM ingestion_jobs WHERE org_id = ? ORDER BY id DESC", (user["org_id"],)
    ).fetchall()]
    alerts      = [dict(row) for row in db.execute(
        "SELECT * FROM alert_rules WHERE org_id = ? ORDER BY id DESC", (user["org_id"],)
    ).fetchall()]
    users       = [dict(row) for row in db.execute(
        "SELECT id, name, email, role, created_at FROM users WHERE org_id = ? ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'manager' THEN 2 WHEN 'developer' THEN 3 ELSE 4 END, created_at ASC",
        (user["org_id"],),
    ).fetchall()]
    audit_events = [dict(row) for row in db.execute(
        "SELECT created_at, action, target_type, target_id, detail_json FROM audit_events WHERE org_id = ? ORDER BY id DESC LIMIT 20",
        (user["org_id"],),
    ).fetchall()]
    for item in integrations:
        item["settings"] = json.loads(item.pop("settings_json"))
    for item in jobs:
        item["details"] = json.loads(item.pop("details_json"))
    for item in audit_events:
        item["detail"] = json.loads(item.pop("detail_json"))
    invitations = [dict(row) for row in db.execute(
        "SELECT id, email, role, token, status, created_at, expires_at FROM invitations WHERE org_id = ? ORDER BY id DESC LIMIT 20",
        (user["org_id"],),
    ).fetchall()]
    dashboards  = [dict(row) for row in db.execute(
        "SELECT id, name, config_json, created_at FROM saved_dashboards WHERE org_id = ? ORDER BY id DESC",
        (user["org_id"],),
    ).fetchall()]
    runs        = [dict(row) for row in db.execute(
        "SELECT id, job_id, status, message, record_count, created_at, completed_at FROM ingestion_runs WHERE org_id = ? ORDER BY id DESC LIMIT 20",
        (user["org_id"],),
    ).fetchall()]
    for item in dashboards:
        item["config"] = json.loads(item.pop("config_json"))
    api_keys_list = [dict(r) for r in db.execute(
        "SELECT ak.id, ak.name, ak.prefix, ak.status, ak.created_at, ak.last_used_at, u.name AS created_by "
        "FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.org_id = ? ORDER BY ak.id DESC LIMIT 20",
        (user["org_id"],),
    ).fetchall()]
    return jsonify({
        "user":         user,
        "organization": {
            "id":            user["org_id"],
            "name":          user["org_name"],
            "slug":          user["slug"],
            "theme_color":   user["theme_color"],
            "theme_mode":    user["theme_mode"],
            "logo_text":     user["logo_text"],
            "admin_only":    bool(user["admin_only"]),
            "workspace_url": org_public_url(user["slug"]),
        },
        "summary":          dashboard_summary(user["org_id"]),
        "integrations":     integrations,
        "jobs":             jobs,
        "alerts":           alerts,
        "users":            users,
        "audit":            audit_events,
        "invitations":      invitations,
        "saved_dashboards": dashboards,
        "ingestion_runs":   runs,
        "role_options":     sorted(VALID_ROLES),
        "theme_options":    sorted(VALID_THEMES),
        "api_keys":         api_keys_list,
        "saved_searches":   [{"id": r["id"], "name": r["name"], "filters": json.loads(r["filters_json"]), "created_at": r["created_at"]} for r in db.execute("SELECT id, name, filters_json, created_at FROM saved_searches WHERE org_id = ? ORDER BY id DESC LIMIT 50", (user["org_id"],)).fetchall()],
        "onboarding": _get_onboarding_state(db, user["org_id"]),
        "permission_matrix": {
            "can_manage_org":          user["role"] == "admin",
            "can_manage_users":        user["role"] == "admin",
            "can_manage_integrations": user["role"] in ("admin", "manager"),
            "can_manage_alerts":       user["role"] in ("admin", "manager"),
            "can_manage_jobs":         user["role"] in ("admin", "manager"),
            "can_invite_users":        user["role"] in ("admin", "manager"),
            "can_run_jobs":            user["role"] in ("admin", "manager", "developer"),
            "can_create_api_keys":     user["role"] in ("admin", "manager", "developer"),
            "can_view_audit":          user["role"] in ("admin", "manager"),
        },
    })

@app.get("/api/logs")
def get_logs():
    user, error = require_auth()
    if error:
        return error
    db    = get_db()
    q     = sanitize_input(request.args.get("q") or "", 200)
    level = sanitize_input(request.args.get("level") or "all", 20).lower()
    minutes = request.args.get("minutes", "0")
    params: list[Any] = [user["org_id"]]
    sql = "SELECT id, timestamp, level, source, event_id, message FROM log_events WHERE org_id = ?"
    if level != "all":
        sql += " AND level = ?"
        params.append(level)
    if q:
        # Use FTS5 when available (SQLite only) for much faster full-text search
        use_fts = False
        if not _is_pg():
            try:
                fts_ids = [r[0] for r in get_db().execute(
                    "SELECT rowid FROM log_fts WHERE log_fts MATCH ? AND rowid IN (SELECT id FROM log_events WHERE org_id=?) LIMIT 2000",
                    (q, user["org_id"]),
                ).fetchall()]
                if fts_ids:
                    placeholders = ",".join("?" * len(fts_ids))
                    sql = f"SELECT id, timestamp, level, source, event_id, message FROM log_events WHERE org_id = ? AND id IN ({placeholders})"
                    params = [user["org_id"]] + fts_ids
                    use_fts = True
            except Exception:
                pass
        if not use_fts:
            sql += " AND (lower(message) LIKE ? OR lower(source) LIKE ? OR lower(coalesce(event_id,'')) LIKE ?)"
            pattern = f"%{q.lower()}%"
            params.extend([pattern, pattern, pattern])
    try:
        mins = int(minutes)
        if mins > 0:
            sql += " AND timestamp >= datetime('now', ? || ' minutes')"
            params.append(f"-{mins}")
    except (ValueError, TypeError):
        pass
    from_ts = sanitize_input(request.args.get("from_ts") or "", 50)
    to_ts   = sanitize_input(request.args.get("to_ts") or "", 50)
    if from_ts:
        sql += " AND timestamp >= ?"
        params.append(from_ts)
    if to_ts:
        sql += " AND timestamp <= ?"
        params.append(to_ts)
    source_filter = sanitize_input(request.args.get("source") or "", 100)
    if source_filter:
        sql += " AND source = ?"
        params.append(source_filter)
    ALLOWED_SORT_COLS = {"timestamp", "level", "source", "message", "event_id"}
    sort_col = sanitize_input(request.args.get("sort", "timestamp"), 20).lower()
    sort_dir = sanitize_input(request.args.get("dir", "desc"), 5).lower()
    if sort_col not in ALLOWED_SORT_COLS:
        sort_col = "timestamp"
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"
    try:
        per_page = max(10, min(500, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        per_page = 50
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    count_sql = sql.replace(
        "SELECT id, timestamp, level, source, event_id, message FROM log_events",
        "SELECT COUNT(*) FROM log_events",
    )
    total = db.execute(count_sql, params).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page  = min(page, pages)
    sql  += f" ORDER BY {sort_col} {sort_dir.upper()} LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    rows = [dict(row) for row in db.execute(sql, params).fetchall()]
    return jsonify({"records": rows, "total": total, "page": page, "pages": pages, "per_page": per_page})

@app.get("/api/logs/sources")
def get_log_sources():
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    rows = db.execute(
        "SELECT DISTINCT source FROM log_events WHERE org_id = ? AND source IS NOT NULL AND source != '' ORDER BY source LIMIT 200",
        (user["org_id"],)
    ).fetchall()
    return jsonify({"sources": [r["source"] for r in rows]})

@app.get("/api/logs/errors/grouped")
def get_grouped_errors():
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    # Group errors by truncated message pattern (first 120 chars) with counts
    rows = db.execute(
        """SELECT substr(message,1,120) AS pattern,
                  COUNT(*) AS count,
                  MIN(timestamp) AS first_seen,
                  MAX(timestamp) AS last_seen,
                  GROUP_CONCAT(DISTINCT source) AS sources,
                  level
           FROM log_events
           WHERE org_id = ? AND level IN ('error','warn')
           GROUP BY substr(message,1,120), level
           ORDER BY count DESC LIMIT 20""",
        (user["org_id"],)
    ).fetchall()
    result = []
    for r in rows:
        result.append({
            "pattern":    r["pattern"],
            "count":      r["count"],
            "first_seen": r["first_seen"],
            "last_seen":  r["last_seen"],
            "sources":    r["sources"].split(",")[:4] if r["sources"] else [],
            "level":      r["level"],
        })
    return jsonify({"groups": result})

@app.post("/api/logs/<int:log_id>/explain")
def explain_log(log_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute(
        "SELECT id, timestamp, level, source, event_id, message, payload_json FROM log_events WHERE id = ? AND org_id = ?",
        (log_id, user["org_id"])
    ).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    log = dict(row)
    try:
        payload = json.loads(log.get("payload_json") or "{}")
    except Exception:
        payload = {}

    # Fetch context: 5 events before and after on same source (or correlation_id if set)
    corr_id = log.get("correlation_id") or ""
    if corr_id:
        ctx_rows = db.execute(
            "SELECT timestamp, level, source, message FROM log_events WHERE org_id=? AND correlation_id=? AND id!=? ORDER BY timestamp ASC LIMIT 10",
            (user["org_id"], corr_id, log_id),
        ).fetchall()
    else:
        ctx_rows = db.execute(
            """SELECT timestamp, level, source, message FROM log_events
               WHERE org_id=? AND source=? AND id!=?
               ORDER BY ABS(CAST(strftime('%s', timestamp) AS INTEGER) - CAST(strftime('%s', ?) AS INTEGER))
               LIMIT 10""",
            (user["org_id"], log["source"], log_id, log["timestamp"]),
        ).fetchall()
    context_block = ""
    if ctx_rows:
        context_block = "\n\nSurrounding events (same source / correlation chain):\n" + "\n".join(
            f"  [{r['timestamp']}] [{r['level'].upper()}] {r['source']}: {r['message'][:200]}" for r in ctx_rows
        )

    prompt = (
        f"You are a senior SRE analysing a log event in context. "
        f"Be concise and practical. Respond in 4 short sections:\n"
        f"1. **What happened** (1-2 sentences)\n"
        f"2. **Root cause** — use the surrounding events if they reveal a chain (1-3 sentences)\n"
        f"3. **Fix / next steps** (2-3 bullet points)\n"
        f"4. **Prevention** (1 bullet)\n\n"
        f"Focal log entry:\n"
        f"- Level: {log['level']}\n"
        f"- Source: {log['source']}\n"
        f"- Timestamp: {log['timestamp']}\n"
        f"- Message: {log['message']}\n"
        f"- Payload: {json.dumps(payload, indent=2)[:800]}"
        f"{context_block}"
    )
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured on server. Add it to your Railway environment variables."}), 503
    explanation = _call_anthropic(prompt, max_tokens=700)
    if not explanation:
        return jsonify({"error": "AI explain failed — check server logs for details."}), 500
    return jsonify({"explanation": explanation, "context_events": len(ctx_rows)})

@app.get("/api/searches")
def get_searches():
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    rows = db.execute(
        "SELECT id, name, filters_json, created_at FROM saved_searches WHERE org_id = ? ORDER BY id DESC LIMIT 50",
        (user["org_id"],)
    ).fetchall()
    items = []
    for r in rows:
        items.append({"id": r["id"], "name": r["name"], "filters": json.loads(r["filters_json"]), "created_at": r["created_at"]})
    return jsonify({"searches": items})

@app.post("/api/searches")
def save_search():
    user, error = require_auth()
    if error:
        return error
    payload = request.get_json(silent=True) or {}
    name = sanitize_input(payload.get("name") or "Untitled search", 80)
    filters = payload.get("filters") or {}
    db = get_db()
    cur = db.execute(
        "INSERT INTO saved_searches (org_id, user_id, name, filters_json, created_at) VALUES (?,?,?,?,?)",
        (user["org_id"], user["id"], name, json.dumps(filters), iso_now())
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "filters": filters}), 201

@app.delete("/api/searches/<int:search_id>")
def delete_search(search_id: int):
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    db.execute("DELETE FROM saved_searches WHERE id = ? AND org_id = ?", (search_id, user["org_id"]))
    db.commit()
    return jsonify({"ok": True})

@app.get("/api/uploads")
def get_uploads():
    user, error = require_auth()
    if error:
        return error
    db = get_db()

    try:
        cols = {row[1] for row in db.execute("PRAGMA table_info(uploads)").fetchall()}
    except Exception:
        cols = set()

    record_expr = "record_count" if "record_count" in cols else ("total_records AS record_count" if "total_records" in cols else "0 AS record_count")
    source_expr = "source_type" if "source_type" in cols else "'file' AS source_type"

    rows = db.execute(
        f"SELECT id, filename, {record_expr}, {source_expr}, created_at FROM uploads WHERE org_id = ? ORDER BY id DESC LIMIT 100",
        (user["org_id"],)
    ).fetchall()
    return jsonify({"uploads": [dict(r) for r in rows]})

@app.get("/api/logs/<int:log_id>")
def get_log_detail(log_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute(
        "SELECT id, timestamp, level, source, event_id, message, payload_json, upload_id, created_at FROM log_events WHERE id = ? AND org_id = ?",
        (log_id, user["org_id"]),
    ).fetchone()
    if not row:
        return jsonify({"error": "Log not found."}), 404
    item = dict(row)
    item["payload"] = json.loads(item.pop("payload_json"))
    return jsonify(item)

@app.post("/api/upload")
@rate_limit("30 per minute")
def upload_logs():
    user, error = require_auth()
    if error:
        return error
    files = request.files.getlist("files") or request.files.getlist("file")
    if not files:
        return jsonify({"error": "No file uploaded."}), 400

    ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv", ".ndjson", ".jsonl", ".xml", ".tsv", ""}
    BINARY_SIGNATURES  = [
        (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP archive"),
        (b"%PDF",        "PDF file"),    (b"\x89PNG",     "PNG image"),
        (b"\xff\xd8\xff","JPEG image"),  (b"GIF8",        "GIF image"),
        (b"\x1f\x8b",    "GZIP archive"),(b"BZh",         "BZIP2 archive"),
        (b"\x7fELF",     "ELF binary"),  (b"Rar!",        "RAR archive"),
    ]

    all_records: list[dict[str, Any]] = []
    filenames: list[str] = []
    skipped: list[str]   = []
    db  = get_db()
    now = iso_now()

    for file in files:
        if not file or not (file.filename or "").strip():
            continue
        filename   = safe_filename(file.filename or "upload.log")
        clean_name = ROTATION_SUFFIX_RE.sub("", filename)
        ext        = Path(clean_name).suffix.lower()

        if ext and ext not in ALLOWED_EXTENSIONS:
            skipped.append(f"{filename} (unsupported type '{ext}')")
            continue

        raw = file.read()
        rejected_label = next((label for magic, label in BINARY_SIGNATURES if raw[:len(magic)] == magic), None)
        if rejected_label:
            skipped.append(f"{filename} (binary: {rejected_label})")
            continue

        sample = raw[:512]
        if sample and sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127) / len(sample) > 0.30:
            skipped.append(f"{filename} (binary content detected)")
            continue

        filenames.append(filename)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="ignore")

        records = parse_text_by_extension(filename, text)
        if not records:
            skipped.append(f"{filename} (no parseable log records)")
            continue

        cur       = db.execute(
            "INSERT INTO uploads (org_id, user_id, filename, total_records, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["org_id"], user["id"], filename, len(records), now),
        )
        upload_id = cur.lastrowid
        db.executemany(
            "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(user["org_id"], upload_id, r["timestamp"], r["level"], r["source"], r.get("event_id") or "", r["message"], json.dumps(r.get("payload", {})), now) for r in records],
        )
        audit(user["org_id"], user["id"], "uploaded_logs", "upload", str(upload_id), {"filename": filename, "records": len(records)})
        all_records.extend(records)

    db.commit()
    if not all_records:
        detail = (" Rejected: " + "; ".join(skipped)) if skipped else ""
        return jsonify({"error": f"No log records could be parsed.{detail}"}), 400
    return jsonify({
        "filename":       ", ".join(filenames),
        "files_uploaded": len(filenames),
        "skipped":        skipped,
        "summary":        summarize(all_records),
        "dashboard":      dashboard_summary(user["org_id"]),
    })

@app.post("/api/users")
def create_user():
    user, error = require_admin()
    if error:
        return error
    payload  = request_payload()
    email    = sanitize_input(payload.get("email") or "").lower()
    name     = sanitize_input(payload.get("name") or "")
    password = payload.get("password") or ""
    role     = sanitize_input(payload.get("role") or "developer").lower()
    if not email or not name or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": f"Unsupported role. Use one of: {', '.join(sorted(VALID_ROLES))}."}), 400
    pw_error = validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone():
        return jsonify({"error": "A user with that email already exists."}), 400
    cur = db.execute(
        "INSERT INTO users (org_id, name, email, password_hash, role, created_at, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], name, email, generate_password_hash(password), role, iso_now(), 1),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_user", "user", str(cur.lastrowid), {"email": email, "role": role})
    return jsonify({"message": "User created.", "id": cur.lastrowid})

@app.post("/api/integrations")
def add_integration():
    user, error = require_role("manager")
    if error:
        return error
    payload = request_payload()
    kind    = payload.get("kind")
    if kind not in {"s3", "api"}:
        return jsonify({"error": "Unsupported integration kind."}), 400
    now = iso_now()
    db  = get_db()
    cur = db.execute(
        "INSERT INTO integrations (org_id, kind, name, status, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], kind, sanitize_input(payload.get("name") or f"{kind.upper()} integration"), payload.get("status") or "configured", json.dumps(payload.get("settings") or {}), now, now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "saved_integration", "integration", str(cur.lastrowid), {"kind": kind})
    return jsonify({"message": "Integration saved.", "id": cur.lastrowid})

@app.post("/api/alerts")
def add_alert():
    user, error = require_role("manager")
    if error:
        return error
    payload = request_payload()
    now     = iso_now()
    db      = get_db()
    cur     = db.execute(
        "INSERT INTO alert_rules (org_id, name, severity, condition_text, status, channel, notify_email, threshold, alert_type, slack_webhook_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], sanitize_input(payload.get("name") or "New alert"), payload.get("severity") or "sev3",
         sanitize_input(payload.get("condition_text") or "condition pending", 500), payload.get("status") or "draft",
         payload.get("channel") or "Email", sanitize_input(payload.get("notify_email") or ""),
         int(payload.get("threshold") or 10), payload.get("alert_type") or "error_rate",
         sanitize_input(payload.get("slack_webhook_url") or ""), now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_alert", "alert", str(cur.lastrowid), {"name": payload.get("name")})
    return jsonify({"message": "Alert rule created.", "id": cur.lastrowid})

@app.post("/api/jobs")
def add_job():
    user, error = require_role("manager")
    if error:
        return error
    payload     = request_payload()
    now         = iso_now()
    db          = get_db()
    source_type = payload.get("source_type") or "api"
    integration = fetch_latest_integration(user["org_id"], source_type)
    cur         = db.execute(
        "INSERT INTO ingestion_jobs (org_id, integration_id, name, source_type, status, schedule, last_run_at, next_run_at, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], integration["id"] if integration else None, sanitize_input(payload.get("name") or "New ingestion job"), source_type, payload.get("status") or "scheduled", payload.get("schedule") or "0 * * * *", payload.get("last_run_at"), parse_cron_next_run(payload.get("schedule") or "0 * * * *"), json.dumps(payload.get("details") or {}), now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_job", "job", str(cur.lastrowid), {"name": payload.get("name"), "source_type": source_type})
    return jsonify({"message": "Job created.", "id": cur.lastrowid})

@app.post("/api/jobs/<int:job_id>/run")
def run_job(job_id: int):
    user, error = require_role("developer")
    if error:
        return error
    try:
        INGESTION_QUEUE.put_nowait(job_id)
    except Full:
        return jsonify({"error": "Ingestion queue is full. Try again shortly."}), 503
    audit(user["org_id"], user["id"], "queued_ingestion_job", "job", str(job_id), {})
    return jsonify({"message": "Job queued. Background worker will ingest records shortly.", "queued": True, "success": True})

@app.post("/api/org")
def update_org():
    user, error = require_admin()
    if error:
        return error
    payload    = request_payload()
    slug       = slugify(payload.get("slug") or user["slug"])
    theme_mode = sanitize_input(payload.get("theme_mode") or user["theme_mode"] or "white", 20).lower()
    if theme_mode not in VALID_THEMES:
        theme_mode = "white"
    theme_color = payload.get("theme_color") or DEFAULT_THEME_COLORS[theme_mode]
    db = get_db()
    if db.execute("SELECT id FROM organizations WHERE slug = ? AND id != ?", (slug, user["org_id"])).fetchone():
        return jsonify({"error": "That organization slug is already in use."}), 400
    db.execute(
        "UPDATE organizations SET name = ?, slug = ?, theme_color = ?, theme_mode = ?, logo_text = ?, admin_only = ? WHERE id = ?",
        (sanitize_input(payload.get("name") or user["org_name"]), slug, theme_color, theme_mode, sanitize_input(payload.get("logo_text") or user["logo_text"], 3).upper(), 1 if payload.get("admin_only") else 0, user["org_id"]),
    )
    db.commit()
    audit(user["org_id"], user["id"], "updated_org_settings", "organization", str(user["org_id"]), {"slug": slug})
    return jsonify({"message": "Organization settings updated."})

@app.post("/api/integrations/s3/test")
def test_s3():
    _, error = require_auth()
    if error:
        return error
    payload = request_payload()
    if boto3 is None:
        return jsonify({"success": False, "message": "boto3 is not installed in this environment."}), 500
    try:
        session_aws = boto3.session.Session(
            aws_access_key_id=payload.get("access_key"),
            aws_secret_access_key=payload.get("secret_key"),
            region_name=payload.get("region"),
        )
        client = session_aws.client("s3")
        resp   = client.list_objects_v2(Bucket=payload.get("bucket"), Prefix=payload.get("prefix", ""), MaxKeys=8)
        return jsonify({
            "success": True,
            "message": "S3 connection successful.",
            "objects": [
                {"key": item.get("Key"), "size": item.get("Size"), "last_modified": item.get("LastModified").isoformat() if item.get("LastModified") else None}
                for item in resp.get("Contents", [])
            ],
        })
    except (BotoCoreError, ClientError, Exception) as exc:
        return jsonify({"success": False, "message": f"S3 connection failed: {exc}"}), 400

@app.post("/api/integrations/api/test")
def test_api():
    _, error = require_auth()
    if error:
        return error
    payload = request_payload()
    if _requests_lib is None:
        return jsonify({"success": False, "message": "requests is not installed in this environment."}), 500
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"success": False, "message": "API URL is required."}), 400

    # SECURITY: Block SSRF — reject internal/private URLs
    ssrf_error = validate_url_for_ssrf(url)
    if ssrf_error:
        return jsonify({"success": False, "message": ssrf_error}), 400

    headers    = payload.get("headers") or {}
    auth_token = payload.get("token")
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        response = _requests_lib.get(url, headers=headers, timeout=10, allow_redirects=False)
        return jsonify({"success": True, "message": "API connection successful.", "status_code": response.status_code, "preview": response.text[:1200]})
    except Exception as exc:
        return jsonify({"success": False, "message": f"API connection failed: {exc}"}), 400

@app.get("/pricing")
def pricing_page():
    return render_template("pricing.html")

@app.get("/documentation")
def documentation_page():
    return render_template("documentation.html")

@app.get("/forgot-password")
def forgot_password_page():
    if session.get("user_id"):
        return redirect("/workspace")
    return render_template("forgot_password.html")

@app.get("/reset-password/<token>")
def reset_password_page(token: str):
    if session.get("user_id"):
        return redirect("/workspace")
    return render_template("reset_password.html", token=token)

@app.get("/verify-email/<token>")
def verify_email_page(token: str):
    db  = get_db()
    row = db.execute(
        "SELECT vt.id, vt.user_id, vt.status, vt.expires_at, u.org_id FROM verification_tokens vt JOIN users u ON u.id = vt.user_id WHERE vt.token = ?",
        (token,),
    ).fetchone()
    if not row or row["status"] != "pending" or row["expires_at"] < iso_now():
        return render_template("status_page.html", title="Verification link invalid", message="This verification link is invalid or expired.", action_label="Back to login", action_href="/login")
    db.execute("UPDATE verification_tokens SET status = 'used' WHERE id = ?", (row["id"],))
    db.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],))
    db.commit()
    audit(row["org_id"], row["user_id"], "verified_email", "user", str(row["user_id"]), {})
    return render_template("status_page.html", title="Email verified", message="Your email has been verified. You can sign in now.", action_label="Sign in", action_href="/login")

@app.get("/accept-invite/<token>")
def accept_invite_page(token: str):
    if session.get("user_id"):
        return redirect("/workspace")
    db     = get_db()
    invite = db.execute(
        "SELECT i.*, o.name AS org_name FROM invitations i JOIN organizations o ON o.id = i.org_id WHERE i.token = ?",
        (token,),
    ).fetchone()
    if not invite:
        return render_template("status_page.html", title="Invite not found", message="This invite is invalid or expired.", action_label="Back to website", action_href="/")
    return render_template("accept_invite.html", invite=dict(invite))

@app.post("/api/invitations")
def create_invitation():
    user, error = require_role("manager")
    if error:
        return error
    payload = request_payload()
    email   = sanitize_input(payload.get("email") or "").lower()
    role    = sanitize_input(payload.get("role") or "developer").lower()
    if not email:
        return jsonify({"error": "Email is required."}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": "Invalid role."}), 400
    token      = secrets.token_urlsafe(32)
    now        = iso_now()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    db         = get_db()
    cur        = db.execute(
        "INSERT INTO invitations (org_id, email, role, token, status, created_at, expires_at, created_by) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
        (user["org_id"], email, role, token, now, expires_at, user["id"]),
    )
    db.commit()
    invite_url      = f"{public_base_url()}/accept-invite/{token}"
    smtp_configured = bool(os.environ.get("SMTP_HOST"))
    email_sent      = False
    email_error     = None
    if smtp_configured:
        try:
            send_email_message(
                "You have been invited to ObserveX",
                email,
                f"Hi,\n\nYou've been invited to join an ObserveX workspace as {role}.\n\nAccept your invite here:\n{invite_url}\n\nThis link expires in 7 days.",
            )
            email_sent = True
        except Exception as exc:
            email_error = str(exc)
    audit(user["org_id"], user["id"], "created_invitation", "invitation", str(cur.lastrowid), {"email": email, "role": role, "email_sent": email_sent})
    return jsonify({
        "message":         "Invitation created.",
        "invite_url":      invite_url,
        "email_sent":      email_sent,
        "smtp_configured": smtp_configured,
        "email_error":     email_error,
    })

@app.post("/api/invitations/accept")
def accept_invitation():
    payload = request_payload()
    token   = payload.get("token") or ""
    name    = sanitize_input(payload.get("name") or "")
    password = payload.get("password") or ""
    pw_error = validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    db     = get_db()
    invite = db.execute("SELECT * FROM invitations WHERE token = ?", (token,)).fetchone()
    if not invite or invite["status"] != "pending" or invite["expires_at"] < iso_now():
        return jsonify({"error": "Invite is invalid or expired."}), 400
    if db.execute("SELECT id FROM users WHERE lower(email) = ?", ((invite["email"] or "").lower(),)).fetchone():
        return jsonify({"error": "A user with this email already exists."}), 400
    cur = db.execute(
        "INSERT INTO users (org_id, name, email, password_hash, role, created_at, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (invite["org_id"], name or invite["email"].split("@")[0], invite["email"], generate_password_hash(password), invite["role"], iso_now(), 1),
    )
    db.execute("UPDATE invitations SET status = 'accepted' WHERE id = ?", (invite["id"],))
    db.commit()
    session.clear()
    session["user_id"] = cur.lastrowid
    session["csrf"]    = secrets.token_hex(16)
    audit(invite["org_id"], cur.lastrowid, "accepted_invitation", "invitation", str(invite["id"]), {"email": invite["email"]})
    return jsonify({"message": "Welcome to your workspace."})

@app.post("/api/password/forgot")
@rate_limit("5 per minute; 20 per hour")
def forgot_password():
    payload = request_payload()
    email   = sanitize_input(payload.get("email") or "").lower()
    db      = get_db()
    user    = db.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
    # Always return the same message to prevent email enumeration
    if not user:
        return jsonify({"message": "If that email exists, a password reset link has been sent."})
    token = secrets.token_urlsafe(32)
    now   = iso_now()
    db.execute(
        "INSERT INTO password_resets (user_id, token, status, created_at, expires_at) VALUES (?, ?, 'pending', ?, ?)",
        (user["id"], token, now, (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()),
    )
    db.commit()
    reset_url = f"{public_base_url()}/reset-password/{token}"
    try:
        send_email_message("Reset your ObserveX password", email, f"Use this link to reset your password:\n{reset_url}\n\nThis link expires in 4 hours.")
    except Exception as exc:
        logger.warning("Password reset email failed: %s", exc)
    # SECURITY: Do NOT return the reset_url in the response — token must travel via email only.
    return jsonify({"message": "If that email exists, a password reset link has been sent."})

@app.post("/api/password/reset")
@rate_limit("10 per minute")
def reset_password():
    payload  = request_payload()
    token    = payload.get("token") or ""
    password = payload.get("password") or ""
    pw_error = validate_password_strength(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400
    db  = get_db()
    row = db.execute("SELECT * FROM password_resets WHERE token = ?", (token,)).fetchone()
    if not row or row["status"] != "pending" or row["expires_at"] < iso_now():
        return jsonify({"error": "Reset link is invalid or expired."}), 400
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(password), row["user_id"]))
    db.execute("UPDATE password_resets SET status = 'used' WHERE id = ?", (row["id"],))
    db.commit()
    return jsonify({"message": "Password reset successful."})

@app.post("/api/dashboards")
def save_dashboard():
    user, error = require_auth()
    if error:
        return error
    payload = request_payload()
    name    = sanitize_input(payload.get("name") or "")
    if not name:
        return jsonify({"error": "Dashboard name is required."}), 400
    db  = get_db()
    cur = db.execute(
        "INSERT INTO saved_dashboards (org_id, user_id, name, config_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], name, json.dumps(payload.get("config") or {}), iso_now()),
    )
    db.commit()
    audit(user["org_id"], user["id"], "saved_dashboard", "dashboard", str(cur.lastrowid), {"name": name})
    return jsonify({"message": "Dashboard saved."})


# ─────────────────────────── Ingest API ──────────────────────────────────────

@app.post("/ingest/json")
@rate_limit("1000 per minute")
def ingest_json():
    """
    Public REST endpoint to ingest JSON logs.
    Auth: Authorization: Bearer <api_key>  OR  X-API-Key: <api_key>
    """
    key_row, error = require_api_key(required_scope="ingest")
    if error:
        return error
    org_id  = key_row["org_id"]
    user_id = key_row["user_id"]

    # Per-org rate limit
    rate_limit_val = int(key_row.get("ingest_rate_limit") or 10000)
    if not _check_org_rate(org_id, rate_limit_val):
        return jsonify({"error": f"Ingest rate limit exceeded ({rate_limit_val} events/min). Retry shortly."}), 429

    # Enforce a per-request body size limit (separate from global 50MB)
    MAX_INGEST_BODY = 10 * 1024 * 1024  # 10 MB
    content_length  = request.content_length or 0
    if content_length > MAX_INGEST_BODY:
        return jsonify({"error": "Request body too large. Maximum 10 MB per ingest call."}), 413

    content_type = request.content_type or ""
    if "application/json" in content_type or "text/plain" in content_type or not content_type:
        raw = request.get_data(as_text=True)
    else:
        return jsonify({"error": "Content-Type must be application/json or text/plain."}), 415

    if not raw.strip():
        return jsonify({"error": "Request body is empty."}), 400

    records = parse_json_text(raw)
    if not records:
        records = parse_plain_text(raw)
    if not records:
        return jsonify({"error": "Could not parse any log records from the request body."}), 422

    db  = get_db()
    now = iso_now()
    cur = db.execute(
        "INSERT INTO uploads (org_id, user_id, filename, total_records, created_at) VALUES (?, ?, ?, ?, ?)",
        (org_id, user_id, "api-ingest.json", len(records), now),
    )
    upload_id = cur.lastrowid
    rows_to_insert = []
    for r in records:
        sf = extract_structured_fields(r.get("payload") or {})
        rows_to_insert.append((
            org_id, upload_id, r["timestamp"], r["level"], r["source"],
            r.get("event_id") or "", r["message"], json.dumps(r.get("payload", {})), now,
            sf.get("status_code"), sf.get("duration_ms"), sf.get("req_user_id"), sf.get("request_id"),
        ))
    db.executemany(
        "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at, status_code, duration_ms, req_user_id, request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows_to_insert,
    )
    db.commit()
    audit(org_id, user_id, "api_ingest_json", "upload", str(upload_id), {"records": len(records)})
    return jsonify({"ok": True, "ingested": len(records), "upload_id": upload_id, "summary": summarize(records)}), 201

@app.post("/ingest/file")
@rate_limit("100 per minute")
def ingest_file():
    """
    Public REST endpoint for file upload ingestion.
    Auth: Authorization: Bearer <api_key>  OR  X-API-Key: <api_key>
    """
    key_row, error = require_api_key(required_scope="ingest")
    if error:
        return error
    org_id  = key_row["org_id"]
    user_id = key_row["user_id"]

    rate_limit_val = int(key_row.get("ingest_rate_limit") or 10000)
    if not _check_org_rate(org_id, rate_limit_val):
        return jsonify({"error": f"Ingest rate limit exceeded ({rate_limit_val} events/min)."}), 429

    files = request.files.getlist("files") or request.files.getlist("file")
    if not files or not any(f.filename for f in files):
        return jsonify({"error": "No file(s) uploaded. Use multipart/form-data with field name 'file' or 'files'."}), 400

    db  = get_db()
    now = iso_now()
    all_records: list[dict[str, Any]] = []
    file_results: list[dict[str, Any]] = []

    for f in files:
        if not f or not (f.filename or "").strip():
            continue
        filename = safe_filename(f.filename or "upload.log")
        raw      = f.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="ignore")
        records = parse_text_by_extension(filename, text)
        if not records:
            file_results.append({"filename": filename, "ingested": 0, "error": "No records parsed"})
            continue
        cur       = db.execute(
            "INSERT INTO uploads (org_id, user_id, filename, total_records, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, user_id, filename, len(records), now),
        )
        upload_id = cur.lastrowid
        rows_to_insert = []
        for r in records:
            sf = extract_structured_fields(r.get("payload") or {})
            rows_to_insert.append((
                org_id, upload_id, r["timestamp"], r["level"], r["source"],
                r.get("event_id") or "", r["message"], json.dumps(r.get("payload", {})), now,
                sf.get("status_code"), sf.get("duration_ms"), sf.get("req_user_id"), sf.get("request_id"),
            ))
        db.executemany(
            "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at, status_code, duration_ms, req_user_id, request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows_to_insert,
        )
        audit(org_id, user_id, "api_ingest_file", "upload", str(upload_id), {"filename": filename, "records": len(records)})
        all_records.extend(records)
        file_results.append({"filename": filename, "ingested": len(records), "upload_id": upload_id})

    db.commit()
    if not all_records:
        return jsonify({"error": "No log records could be parsed from uploaded files.", "files": file_results}), 422
    return jsonify({"ok": True, "total_ingested": len(all_records), "files": file_results, "summary": summarize(all_records)}), 201


# ─────────────────────────── API Key management ───────────────────────────────

@app.post("/api/keys")
def create_api_key():
    user, error = require_auth()
    if error:
        return error
    payload = request_payload()
    name    = sanitize_input(payload.get("name") or "")
    if not name:
        return jsonify({"error": "Key name is required."}), 400
    # Validate scopes
    VALID_SCOPES = {"ingest", "read", "admin"}
    raw_scopes   = payload.get("scopes") or ["ingest", "read", "admin"]
    if isinstance(raw_scopes, str):
        raw_scopes = [s.strip() for s in raw_scopes.split(",")]
    scopes = [s for s in raw_scopes if s in VALID_SCOPES]
    if not scopes:
        return jsonify({"error": f"At least one valid scope required: {sorted(VALID_SCOPES)}"}), 400
    scopes_str = ",".join(sorted(set(scopes)))
    raw_key  = "oxk_" + secrets.token_urlsafe(32)
    prefix   = raw_key[:8]
    key_hash = generate_password_hash(raw_key)
    db       = get_db()
    cur      = db.execute(
        "INSERT INTO api_keys (org_id, user_id, name, key_hash, prefix, status, scopes, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
        (user["org_id"], user["id"], name, key_hash, prefix, scopes_str, iso_now()),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_api_key", "api_key", str(cur.lastrowid), {"name": name, "scopes": scopes_str})
    return jsonify({
        "message": "API key created. Copy it now — it will not be shown again.",
        "id":      cur.lastrowid,
        "name":    name,
        "key":     raw_key,
        "prefix":  prefix,
        "scopes":  scopes_str,
    }), 201

@app.get("/api/keys")
def list_api_keys():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute(
        "SELECT ak.id, ak.name, ak.prefix, ak.status, ak.scopes, ak.created_at, ak.last_used_at, u.name AS created_by "
        "FROM api_keys ak JOIN users u ON u.id = ak.user_id WHERE ak.org_id = ? ORDER BY ak.id DESC",
        (user["org_id"],),
    ).fetchall()
    return jsonify({"keys": [dict(r) for r in rows]})

@app.delete("/api/keys/<int:key_id>")
def revoke_api_key(key_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id, prefix FROM api_keys WHERE id = ? AND org_id = ?", (key_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Key not found."}), 404
    db.execute("UPDATE api_keys SET status = 'revoked' WHERE id = ?", (key_id,))
    db.commit()
    _invalidate_cached_key(row["prefix"])  # Purge from in-memory cache immediately
    audit(user["org_id"], user["id"], "revoked_api_key", "api_key", str(key_id), {})
    return jsonify({"message": "API key revoked."})

@app.get("/api/logs/timeseries")
def logs_timeseries():
    user, error = require_auth()
    if error:
        return error
    hours = min(int(request.args.get("hours", 24)), 168)
    db    = get_db()
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    rows  = db.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS hour, level, COUNT(*) AS count "
        "FROM log_events WHERE org_id = ? AND timestamp >= ? GROUP BY hour, level ORDER BY hour",
        (user["org_id"], since),
    ).fetchall()
    buckets: dict[str, dict[str, int]] = {}
    for row in rows:
        h = row["hour"] or ""
        if h not in buckets:
            buckets[h] = {}
        buckets[h][row["level"]] = row["count"]
    return jsonify({"hours": hours, "since": since, "buckets": buckets})

@app.post("/api/demo-request")
@rate_limit("5 per minute; 30 per hour")
def demo_request():
    payload = request_payload()
    name    = sanitize_input(payload.get("name") or "")
    email   = sanitize_input(payload.get("email") or "").lower()
    company = sanitize_input(payload.get("company") or "")
    message = sanitize_input(payload.get("message") or "", 2000)
    if not name or not email:
        return jsonify({"error": "Name and email are required."}), 400
    db = get_db()
    db.execute(
        "INSERT INTO demo_requests (name, company, email, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (name, company, email, message, iso_now()),
    )
    db.commit()
    return jsonify({"message": "Demo request submitted successfully."})

@app.get("/api/observability")
def get_observability():
    user, error = require_auth()
    if error:
        return error
    org_id         = user["org_id"]
    db             = get_db()
    window_minutes = max(1, min(int(request.args.get("minutes", 60)), 10080))
    since          = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%S")

    level_rows = db.execute(
        "SELECT level, COUNT(*) as cnt FROM log_events WHERE org_id=? AND timestamp>=? GROUP BY level",
        (org_id, since),
    ).fetchall()
    level_counts = {r["level"]: r["cnt"] for r in level_rows}
    total        = sum(level_counts.values())
    error_count  = level_counts.get("error", 0)
    warn_count   = level_counts.get("warn", 0)
    error_rate   = round((error_count / total * 100), 1) if total else 0.0

    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    hour_rows = db.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, level, COUNT(*) as cnt "
        "FROM log_events WHERE org_id=? AND timestamp>=? GROUP BY hour, level ORDER BY hour",
        (org_id, since_24h),
    ).fetchall()
    hourly: dict[str, dict[str, int]] = {}
    for r in hour_rows:
        h = r["hour"] or ""
        if h not in hourly:
            hourly[h] = {}
        hourly[h][r["level"]] = r["cnt"]

    ip_rx   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ip_rows = db.execute(
        "SELECT message, payload_json FROM log_events WHERE org_id=? AND timestamp>=? ORDER BY timestamp DESC LIMIT 5000",
        (org_id, since),
    ).fetchall()
    ip_hits: Counter = Counter()
    ip_errors: Counter = Counter()
    for row in ip_rows:
        text = (row["message"] or "") + " " + (row["payload_json"] or "")
        for ip in set(ip_rx.findall(text)):
            ip_hits[ip] += 1
            try:
                payload = json.loads(row["payload_json"] or "{}")
                lvl     = payload.get("level", "info").lower()
            except Exception:
                lvl = "info"
            if lvl == "error":
                ip_errors[ip] += 1

    rate_threshold = 50 * window_minutes
    suspicious: list[dict[str, Any]] = []
    for ip, hits in ip_hits.most_common(50):
        err     = ip_errors.get(ip, 0)
        err_pct = round(err / hits * 100, 1) if hits else 0
        is_sus  = hits > rate_threshold or (hits >= 10 and err_pct > 20)
        suspicious.append({"ip": ip, "hits": hits, "errors": err, "error_pct": err_pct, "suspicious": is_sus,
                           "hits_per_min": round(hits / max(window_minutes, 1), 2)})

    alerts_fired: list[str] = []
    alert_rules = db.execute(
        "SELECT * FROM alert_rules WHERE org_id=? AND status='active' AND alert_type='suspicious_ip'",
        (org_id,),
    ).fetchall()
    cooldown_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
    for entry in suspicious:
        if not entry["suspicious"]:
            continue
        for rule in alert_rules:
            notify_email = (rule["notify_email"] or "").strip()
            if not notify_email:
                continue
            trigger_key  = f"ip:{entry['ip']}:rule:{rule['id']}"
            already_fired = db.execute(
                "SELECT id FROM observability_fired WHERE org_id=? AND trigger_key=? AND fired_at>=?",
                (org_id, trigger_key, cooldown_cutoff),
            ).fetchone()
            if already_fired:
                continue
            subject = f"[ObserveX Alert] Suspicious IP detected: {entry['ip']}"
            body    = (f"Alert rule: {rule['name']}\nIP: {entry['ip']}\n"
                       f"Hits in last {window_minutes} min: {entry['hits']} ({entry['hits_per_min']}/min)\n"
                       f"Error rate: {entry['error_pct']}%\nThreshold: {rule['threshold']} hits/min or >20% errors\n")
            try:
                send_email_message(subject, notify_email, body)
                alerts_fired.append(f"Alerted {notify_email} for IP {entry['ip']}")
            except Exception as exc:
                alerts_fired.append(f"Email failed for {entry['ip']}: {exc}")
            slack_hook = (rule["slack_webhook_url"] or "").strip() if "slack_webhook_url" in rule.keys() else ""
            if slack_hook:
                try:
                    send_slack_message(slack_hook, f":warning: *ObserveX Alert* — {subject}\n{body}")
                    alerts_fired.append(f"Slack notified for IP {entry['ip']}")
                except Exception as exc:
                    alerts_fired.append(f"Slack failed for {entry['ip']}: {exc}")
            db.execute(
                "INSERT INTO observability_fired (org_id, alert_rule_id, trigger_key, fired_at) VALUES (?,?,?,?)",
                (org_id, rule["id"], trigger_key, iso_now()),
            )
    db.commit()
    return jsonify({
        "window_minutes": window_minutes,
        "total":          total,
        "error_count":    error_count,
        "warn_count":     warn_count,
        "error_rate":     error_rate,
        "level_counts":   level_counts,
        "hourly":         hourly,
        "top_ips":        suspicious,
        "alerts_fired":   alerts_fired,
    })

@app.get("/api/observability/alert-rules")
def get_obs_alert_rules():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute(
        "SELECT * FROM alert_rules WHERE org_id=? AND alert_type='suspicious_ip' ORDER BY created_at DESC",
        (user["org_id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ─────────────────────────── New endpoints (v2) ──────────────────────────────

# ── Webhook ingest (scope-gated + structured extraction) ─────────────────────

@app.post("/api/ingest/webhook")
def webhook_ingest():
    """HMAC-SHA256 validated webhook log ingest.
    Header: X-ObserveX-Signature: sha256=<hex>
    Body: JSON array of log objects or single log object.
    """
    key_info, error = require_api_key(required_scope="ingest")
    if error:
        return error
    org_id = key_info["org_id"]
    rate_limit_val = int(key_info.get("ingest_rate_limit") or 10000)
    if not _check_org_rate(org_id, rate_limit_val):
        return jsonify({"error": "Ingest rate limit exceeded."}), 429

    secret = os.environ.get("WEBHOOK_SECRET", "")
    if secret:
        sig_header = request.headers.get("X-ObserveX-Signature", "")
        expected   = "sha256=" + hmac.new(secret.encode(), request.data, "sha256").hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            return jsonify({"error": "Invalid signature."}), 401

    body = request.get_json(silent=True, force=True)
    if body is None:
        return jsonify({"error": "JSON body required."}), 400
    events = body if isinstance(body, list) else [body]
    if not events:
        return jsonify({"error": "Empty payload."}), 400

    db  = get_db()
    now = iso_now()
    inserted = 0
    for ev in events[:500]:
        msg      = sanitize_input(str(ev.get("message") or ""), 2000)
        level    = sanitize_input(str(ev.get("level") or "info").lower(), 20)
        source   = sanitize_input(str(ev.get("source") or "webhook"), 200)
        ts       = sanitize_input(str(ev.get("timestamp") or now), 50)
        event_id = sanitize_input(str(ev.get("event_id") or ""), 100)
        corr_id  = sanitize_input(str(ev.get("correlation_id") or ""), 100)
        payload  = {k: v for k, v in ev.items() if k not in ("message","level","source","timestamp","event_id","correlation_id")}
        sf       = extract_structured_fields(payload)
        db.execute(
            "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at, correlation_id, status_code, duration_ms, req_user_id, request_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (org_id, None, ts, level, source, event_id, msg, json.dumps(payload), now, corr_id,
             sf.get("status_code"), sf.get("duration_ms"), sf.get("req_user_id"), sf.get("request_id")),
        )
        inserted += 1
    db.commit()
    return jsonify({"inserted": inserted}), 201


# ── Correlation trace ─────────────────────────────────────────────────────────

@app.get("/api/logs/trace")
def get_log_trace():
    user, error = require_auth()
    if error:
        return error
    corr_id = sanitize_input(request.args.get("correlation_id") or "", 100)
    if not corr_id:
        return jsonify({"error": "correlation_id query param required."}), 400
    db   = get_db()
    rows = db.execute(
        "SELECT id, timestamp, level, source, event_id, message, payload_json, correlation_id FROM log_events WHERE org_id=? AND correlation_id=? ORDER BY timestamp ASC LIMIT 500",
        (user["org_id"], corr_id),
    ).fetchall()
    return jsonify({"correlation_id": corr_id, "events": [dict(r) for r in rows]})


# ── Log export (CSV + NDJSON streaming) ──────────────────────────────────────

@app.get("/api/logs/export")
def export_logs():
    """Streaming log export. Query params: format=csv|ndjson, level, source, from_ts, to_ts, q."""
    user, error = require_auth()
    if error:
        return error

    fmt      = sanitize_input(request.args.get("format") or "ndjson", 10).lower()
    if fmt not in ("csv", "ndjson"):
        return jsonify({"error": "format must be 'csv' or 'ndjson'."}), 400

    level    = sanitize_input(request.args.get("level") or "all", 20).lower()
    source   = sanitize_input(request.args.get("source") or "", 100)
    from_ts  = sanitize_input(request.args.get("from_ts") or "", 50)
    to_ts    = sanitize_input(request.args.get("to_ts") or "", 50)
    q        = sanitize_input(request.args.get("q") or "", 200)
    params: list[Any] = [user["org_id"]]
    sql = "SELECT id, timestamp, level, source, event_id, message, payload_json, correlation_id, status_code, duration_ms FROM log_events WHERE org_id=?"
    if level != "all":
        sql += " AND level=?";  params.append(level)
    if source:
        sql += " AND source=?"; params.append(source)
    if from_ts:
        sql += " AND timestamp>=?"; params.append(from_ts)
    if to_ts:
        sql += " AND timestamp<=?"; params.append(to_ts)
    if q:
        sql += " AND lower(message) LIKE ?"; params.append(f"%{q.lower()}%")
    sql += " ORDER BY timestamp DESC LIMIT 100000"

    from flask import Response, stream_with_context

    def generate_ndjson():
        conn = _open_db()
        try:
            for row in conn.execute(sql, params):
                yield json.dumps(dict(row)) + "\n"
        finally:
            conn.close()

    def generate_csv():
        conn = _open_db()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id","timestamp","level","source","event_id","message","correlation_id","status_code","duration_ms","payload_json"])
        yield output.getvalue(); output.seek(0); output.truncate(0)
        try:
            for row in conn.execute(sql, params):
                r = dict(row)
                writer.writerow([r.get("id"), r.get("timestamp"), r.get("level"), r.get("source"),
                                  r.get("event_id"), r.get("message"), r.get("correlation_id"),
                                  r.get("status_code"), r.get("duration_ms"), r.get("payload_json")])
                yield output.getvalue(); output.seek(0); output.truncate(0)
        finally:
            conn.close()

    if fmt == "csv":
        return Response(
            stream_with_context(generate_csv()),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=observex-logs.csv"},
        )
    return Response(
        stream_with_context(generate_ndjson()),
        mimetype="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=observex-logs.ndjson"},
    )


# ── Missing CRUD: alert_rules ─────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute("SELECT * FROM alert_rules WHERE org_id=? ORDER BY created_at DESC", (user["org_id"],)).fetchall()
    return jsonify({"alerts": [dict(r) for r in rows]})

@app.put("/api/alerts/<int:alert_id>")
def update_alert(alert_id: int):
    user, error = require_role("manager")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM alert_rules WHERE id=? AND org_id=?", (alert_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Alert not found."}), 404
    payload = request_payload()
    db.execute(
        """UPDATE alert_rules SET name=?, severity=?, condition_text=?, status=?, channel=?,
           notify_email=?, threshold=?, alert_type=?, slack_webhook_url=?,
           latency_threshold_ms=?, dead_source_minutes=?
           WHERE id=? AND org_id=?""",
        (sanitize_input(payload.get("name") or ""),
         payload.get("severity") or "sev3",
         sanitize_input(payload.get("condition_text") or "", 500),
         payload.get("status") or "draft",
         payload.get("channel") or "Email",
         sanitize_input(payload.get("notify_email") or ""),
         int(payload.get("threshold") or 10),
         payload.get("alert_type") or "error_rate",
         sanitize_input(payload.get("slack_webhook_url") or ""),
         payload.get("latency_threshold_ms"),
         payload.get("dead_source_minutes"),
         alert_id, user["org_id"]),
    )
    db.commit()
    audit(user["org_id"], user["id"], "updated_alert", "alert", str(alert_id), {"name": payload.get("name")})
    return jsonify({"message": "Alert updated."})

@app.delete("/api/alerts/<int:alert_id>")
def delete_alert(alert_id: int):
    user, error = require_role("manager")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM alert_rules WHERE id=? AND org_id=?", (alert_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Alert not found."}), 404
    db.execute("DELETE FROM alert_rules WHERE id=? AND org_id=?", (alert_id, user["org_id"]))
    db.commit()
    audit(user["org_id"], user["id"], "deleted_alert", "alert", str(alert_id), {})
    return jsonify({"message": "Alert deleted."})


# ── Missing CRUD: integrations ────────────────────────────────────────────────

@app.get("/api/integrations")
def list_integrations():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute("SELECT * FROM integrations WHERE org_id=? ORDER BY created_at DESC", (user["org_id"],)).fetchall()
    return jsonify({"integrations": [dict(r) for r in rows]})

@app.put("/api/integrations/<int:intg_id>")
def update_integration(intg_id: int):
    user, error = require_role("manager")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM integrations WHERE id=? AND org_id=?", (intg_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Integration not found."}), 404
    payload = request_payload()
    now     = iso_now()
    db.execute(
        "UPDATE integrations SET name=?, status=?, settings_json=?, updated_at=? WHERE id=? AND org_id=?",
        (sanitize_input(payload.get("name") or ""), payload.get("status") or "configured",
         json.dumps(payload.get("settings") or {}), now, intg_id, user["org_id"]),
    )
    db.commit()
    audit(user["org_id"], user["id"], "updated_integration", "integration", str(intg_id), {})
    return jsonify({"message": "Integration updated."})

@app.delete("/api/integrations/<int:intg_id>")
def delete_integration(intg_id: int):
    user, error = require_role("admin")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM integrations WHERE id=? AND org_id=?", (intg_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Integration not found."}), 404
    db.execute("DELETE FROM integrations WHERE id=? AND org_id=?", (intg_id, user["org_id"]))
    db.commit()
    audit(user["org_id"], user["id"], "deleted_integration", "integration", str(intg_id), {})
    return jsonify({"message": "Integration deleted."})


# ── Missing CRUD: ingestion jobs ──────────────────────────────────────────────

@app.put("/api/jobs/<int:job_id>")
def update_job(job_id: int):
    user, error = require_role("manager")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM ingestion_jobs WHERE id=? AND org_id=?", (job_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Job not found."}), 404
    payload = request_payload()
    db.execute(
        "UPDATE ingestion_jobs SET name=?, status=?, schedule=?, next_run_at=?, details_json=? WHERE id=? AND org_id=?",
        (sanitize_input(payload.get("name") or ""), payload.get("status") or "scheduled",
         payload.get("schedule") or "0 * * * *",
         parse_cron_next_run(payload.get("schedule") or "0 * * * *"),
         json.dumps(payload.get("details") or {}), job_id, user["org_id"]),
    )
    db.commit()
    audit(user["org_id"], user["id"], "updated_job", "job", str(job_id), {"name": payload.get("name")})
    return jsonify({"message": "Job updated."})

@app.delete("/api/jobs/<int:job_id>")
def delete_job(job_id: int):
    user, error = require_role("admin")
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM ingestion_jobs WHERE id=? AND org_id=?", (job_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Job not found."}), 404
    db.execute("DELETE FROM ingestion_jobs WHERE id=? AND org_id=?", (job_id, user["org_id"]))
    db.commit()
    audit(user["org_id"], user["id"], "deleted_job", "job", str(job_id), {})
    return jsonify({"message": "Job deleted."})

@app.get("/api/jobs/<int:job_id>/runs")
def get_job_runs(job_id: int):
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    row  = db.execute("SELECT id FROM ingestion_jobs WHERE id=? AND org_id=?", (job_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Job not found."}), 404
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = max(10, min(100, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        page, per_page = 1, 20
    total = db.execute("SELECT COUNT(*) FROM ingestion_runs WHERE job_id=? AND org_id=?", (job_id, user["org_id"])).fetchone()[0]
    rows  = db.execute(
        "SELECT id, status, message, record_count, created_at, completed_at FROM ingestion_runs WHERE job_id=? AND org_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
        (job_id, user["org_id"], per_page, (page-1)*per_page),
    ).fetchall()
    return jsonify({"runs": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page})


# ── Missing CRUD: log annotations ─────────────────────────────────────────────

@app.post("/api/logs/<int:log_id>/annotate")
def add_annotation(log_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    if not db.execute("SELECT id FROM log_events WHERE id=? AND org_id=?", (log_id, user["org_id"])).fetchone():
        return jsonify({"error": "Log event not found."}), 404
    payload = request_payload()
    tag  = sanitize_input(payload.get("tag") or "note", 50)
    note = sanitize_input(payload.get("note") or "", 2000)
    cur  = db.execute(
        "INSERT INTO log_annotations (org_id, log_id, user_id, tag, note, created_at) VALUES (?,?,?,?,?,?)",
        (user["org_id"], log_id, user["id"], tag, note, iso_now()),
    )
    db.commit()
    return jsonify({"message": "Annotation saved.", "id": cur.lastrowid}), 201

@app.get("/api/logs/<int:log_id>/annotations")
def get_annotations(log_id: int):
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute(
        "SELECT a.id, a.tag, a.note, a.created_at, u.name AS author FROM log_annotations a JOIN users u ON u.id=a.user_id WHERE a.log_id=? AND a.org_id=? ORDER BY a.created_at ASC",
        (log_id, user["org_id"]),
    ).fetchall()
    return jsonify({"annotations": [dict(r) for r in rows]})

@app.delete("/api/logs/annotations/<int:annotation_id>")
def delete_annotation(annotation_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM log_annotations WHERE id=? AND org_id=? AND user_id=?", (annotation_id, user["org_id"], user["id"])).fetchone()
    if not row:
        return jsonify({"error": "Annotation not found or not yours."}), 404
    db.execute("DELETE FROM log_annotations WHERE id=?", (annotation_id,))
    db.commit()
    return jsonify({"message": "Annotation deleted."})


# ── Missing CRUD: saved dashboards ────────────────────────────────────────────

@app.put("/api/dashboards/<int:dash_id>")
def update_dashboard(dash_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM saved_dashboards WHERE id=? AND org_id=?", (dash_id, user["org_id"])).fetchone()
    if not row:
        return jsonify({"error": "Dashboard not found."}), 404
    payload = request_payload()
    db.execute(
        "UPDATE saved_dashboards SET name=?, config_json=? WHERE id=? AND org_id=?",
        (sanitize_input(payload.get("name") or "Dashboard"), json.dumps(payload.get("config") or {}), dash_id, user["org_id"]),
    )
    db.commit()
    return jsonify({"message": "Dashboard updated."})

@app.delete("/api/dashboards/<int:dash_id>")
def delete_dashboard(dash_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT id FROM saved_dashboards WHERE id=? AND org_id=? AND user_id=?", (dash_id, user["org_id"], user["id"])).fetchone()
    if not row:
        return jsonify({"error": "Dashboard not found or not yours."}), 404
    db.execute("DELETE FROM saved_dashboards WHERE id=?", (dash_id,))
    db.commit()
    return jsonify({"message": "Dashboard deleted."})


# ── Session management ────────────────────────────────────────────────────────

@app.get("/api/sessions")
def list_sessions():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute(
        "SELECT id, ip_address, user_agent, created_at, last_active_at, expires_at, revoked FROM user_sessions WHERE user_id=? ORDER BY last_active_at DESC LIMIT 20",
        (user["id"],),
    ).fetchall()
    current_token = session.get("session_token", "")
    result = []
    for r in rows:
        d = dict(r)
        d["is_current"] = False  # token not exposed — mark by recency heuristic
        result.append(d)
    return jsonify({"sessions": result})

@app.delete("/api/sessions/<int:session_id>")
def revoke_session_endpoint(session_id: int):
    user, error = require_auth()
    if error:
        return error
    db  = get_db()
    row = db.execute("SELECT session_token FROM user_sessions WHERE id=? AND user_id=?", (session_id, user["id"])).fetchone()
    if not row:
        return jsonify({"error": "Session not found."}), 404
    db.execute("UPDATE user_sessions SET revoked=1 WHERE id=?", (session_id,))
    db.commit()
    return jsonify({"message": "Session revoked."})


# ── Audit log endpoint ────────────────────────────────────────────────────────

@app.get("/api/audit")
def get_audit_log():
    user, error = require_role("manager")
    if error:
        return error
    db = get_db()
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = max(10, min(200, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        page, per_page = 1, 50
    from_ts = sanitize_input(request.args.get("from_ts") or "", 50)
    to_ts   = sanitize_input(request.args.get("to_ts") or "", 50)
    action  = sanitize_input(request.args.get("action") or "", 100)
    uid     = request.args.get("user_id")

    params: list[Any] = [user["org_id"]]
    sql = "SELECT ae.*, u.name AS user_name, u.email AS user_email FROM audit_events ae LEFT JOIN users u ON u.id=ae.user_id WHERE ae.org_id=?"
    if from_ts:
        sql += " AND ae.created_at>=?"; params.append(from_ts)
    if to_ts:
        sql += " AND ae.created_at<=?"; params.append(to_ts)
    if action:
        sql += " AND ae.action=?"; params.append(action)
    if uid:
        try:
            sql += " AND ae.user_id=?"; params.append(int(uid))
        except (ValueError, TypeError):
            pass

    total = db.execute(sql.replace("SELECT ae.*, u.name AS user_name, u.email AS user_email", "SELECT COUNT(*)"), params).fetchone()[0]
    sql  += f" ORDER BY ae.created_at DESC LIMIT {per_page} OFFSET {(page-1)*per_page}"
    rows  = db.execute(sql, params).fetchall()
    events = []
    for r in rows:
        d = dict(r)
        try:
            d["detail"] = json.loads(d.get("detail_json") or "{}")
        except Exception:
            d["detail"] = {}
        events.append(d)
    return jsonify({"events": events, "total": total, "page": page, "per_page": per_page})


# ── AI endpoints ──────────────────────────────────────────────────────────────

@app.post("/api/ai/anomaly-summary")
def ai_anomaly_summary():
    user, error = require_auth()
    if error:
        return error
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured."}), 503
    db    = get_db()
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
    rows  = db.execute(
        "SELECT message, source FROM log_events WHERE org_id=? AND level='error' AND timestamp>=? ORDER BY timestamp DESC LIMIT 30",
        (user["org_id"], since),
    ).fetchall()
    if not rows:
        return jsonify({"summary": "No errors in the last hour.", "count": 0})
    samples = "\n".join(f"[{r['source']}] {r['message'][:200]}" for r in rows)
    summary = _call_anthropic(
        f"You are an SRE. Summarise the following error logs from the last hour in 3-4 sentences, "
        f"highlighting patterns and urgency:\n\n{samples}",
        max_tokens=300,
    )
    return jsonify({"summary": summary or "AI summary unavailable.", "count": len(rows)})


@app.post("/api/ai/suggest-search")
def ai_suggest_search():
    user, error = require_auth()
    if error:
        return error
    payload = request_payload()
    query   = sanitize_input(payload.get("query") or "", 500)
    if not query:
        return jsonify({"error": "query field required."}), 400
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured."}), 503
    result = _call_anthropic(
        f"Convert this natural-language log search query into a JSON object with these optional keys: "
        f"level (string), search (string keyword), from_ts (ISO8601), to_ts (ISO8601), source (string). "
        f"Return ONLY the JSON object, no explanation.\n\nQuery: {query}",
        max_tokens=200,
    )
    try:
        filters = json.loads(result)
    except Exception:
        filters = {"search": query}
    return jsonify({"filters": filters, "raw": result})


@app.post("/api/ai/build-alert")
def ai_build_alert():
    """Convert a natural-language alert description into a structured alert rule JSON."""
    user, error = require_auth()
    if error:
        return error
    payload = request_payload()
    desc    = sanitize_input(payload.get("description") or "", 500)
    if not desc:
        return jsonify({"error": "description field required."}), 400
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured."}), 503
    result = _call_anthropic(
        f"Convert this natural-language alert description into a JSON object for an alert rule with these keys:\n"
        f"  name (string), severity ('sev1'|'sev2'|'sev3'|'sev4'), condition_text (string, human-readable),\n"
        f"  alert_type ('error_rate'|'suspicious_ip'|'latency'|'dead_source'|'custom'),\n"
        f"  threshold (integer — count or ms depending on type), channel ('Email'|'Slack'|'Both'),\n"
        f"  latency_threshold_ms (integer, only for latency type), dead_source_minutes (integer, only for dead_source type).\n"
        f"Return ONLY the JSON object, no explanation or markdown.\n\nDescription: {desc}",
        max_tokens=300,
    )
    try:
        rule = json.loads(result)
    except Exception:
        rule = {"name": desc[:100], "condition_text": desc, "alert_type": "custom", "severity": "sev3", "threshold": 10}
    return jsonify({"rule": rule, "raw": result})


# ── Error fingerprints ────────────────────────────────────────────────────────

@app.get("/api/logs/fingerprints")
def get_fingerprints():
    user, error = require_auth()
    if error:
        return error
    db   = get_db()
    rows = db.execute(
        "SELECT fingerprint, first_seen_at, last_seen_at, count, sample_message FROM error_fingerprints WHERE org_id=? ORDER BY last_seen_at DESC LIMIT 100",
        (user["org_id"],),
    ).fetchall()
    return jsonify({"fingerprints": [dict(r) for r in rows]})


# ── Org: retention + ingest rate limit ───────────────────────────────────────

@app.post("/api/org/retention")
def set_retention():
    user, error = require_admin()
    if error:
        return error
    payload = request_payload()
    try:
        days = int(payload.get("retention_days") or 90)
        if days < 1 or days > 3650:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "retention_days must be an integer between 1 and 3650."}), 400
    db = get_db()
    db.execute("UPDATE organizations SET retention_days=? WHERE id=?", (days, user["org_id"]))
    db.commit()
    audit(user["org_id"], user["id"], "set_retention_policy", "organization", str(user["org_id"]), {"retention_days": days})
    return jsonify({"message": f"Retention policy set to {days} days.", "retention_days": days})

@app.post("/api/org/rate-limit")
def set_ingest_rate_limit():
    """Admin: set per-org ingest rate limit (events per minute)."""
    user, error = require_admin()
    if error:
        return error
    payload = request_payload()
    try:
        limit = int(payload.get("ingest_rate_limit") or 10000)
        if limit < 1 or limit > 1_000_000:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "ingest_rate_limit must be between 1 and 1,000,000."}), 400
    db = get_db()
    db.execute("UPDATE organizations SET ingest_rate_limit=? WHERE id=?", (limit, user["org_id"]))
    db.commit()
    audit(user["org_id"], user["id"], "set_ingest_rate_limit", "organization", str(user["org_id"]), {"limit": limit})
    return jsonify({"message": f"Ingest rate limit set to {limit} events/min.", "ingest_rate_limit": limit})


# ── OpenAPI specification ─────────────────────────────────────────────────────

@app.get("/api/openapi.json")
def openapi_spec():
    """Machine-readable OpenAPI 3.0 spec for all public endpoints."""
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "ObserveX API",
            "version": "2.0.0",
            "description": "Enterprise log observability platform. Authenticate with a Bearer API key for ingest/read endpoints, or use session cookies for browser-based endpoints.",
        },
        "servers": [{"url": os.environ.get("PUBLIC_BASE_URL", "https://observex.in")}],
        "components": {
            "securitySchemes": {
                "ApiKeyBearer": {"type": "http", "scheme": "bearer", "bearerFormat": "oxk_*"},
                "XApiKey":      {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        },
        "paths": {
            "/ingest/json":              {"post": {"summary": "Ingest JSON logs", "security": [{"ApiKeyBearer": []}], "tags": ["Ingest"]}},
            "/ingest/file":              {"post": {"summary": "Ingest log files (multipart)", "security": [{"ApiKeyBearer": []}], "tags": ["Ingest"]}},
            "/api/ingest/webhook":       {"post": {"summary": "Webhook ingest (HMAC-validated)", "security": [{"ApiKeyBearer": []}], "tags": ["Ingest"]}},
            "/api/logs":                 {"get":  {"summary": "Query log events (paginated)", "tags": ["Logs"]}},
            "/api/logs/export":          {"get":  {"summary": "Stream export (CSV or NDJSON)", "tags": ["Logs"], "parameters": [
                {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["csv", "ndjson"]}},
                {"name": "level",  "in": "query", "schema": {"type": "string"}},
                {"name": "source", "in": "query", "schema": {"type": "string"}},
                {"name": "from_ts","in": "query", "schema": {"type": "string", "format": "date-time"}},
                {"name": "to_ts",  "in": "query", "schema": {"type": "string", "format": "date-time"}},
                {"name": "q",      "in": "query", "schema": {"type": "string"}},
            ]}},
            "/api/logs/trace":           {"get":  {"summary": "Correlation trace by correlation_id", "tags": ["Logs"]}},
            "/api/logs/fingerprints":    {"get":  {"summary": "Error pattern fingerprints", "tags": ["Logs"]}},
            "/api/logs/errors/grouped":  {"get":  {"summary": "Grouped error patterns", "tags": ["Logs"]}},
            "/api/logs/{id}/explain":    {"post": {"summary": "AI root-cause explanation", "tags": ["AI", "Logs"]}},
            "/api/logs/{id}/annotate":   {"post": {"summary": "Add annotation to log event", "tags": ["Logs"]}},
            "/api/logs/{id}/annotations":{"get":  {"summary": "List annotations", "tags": ["Logs"]}},
            "/api/alerts":               {"get":  {"summary": "List alert rules", "tags": ["Alerts"]}, "post": {"summary": "Create alert rule", "tags": ["Alerts"]}},
            "/api/alerts/{id}":          {"put":  {"summary": "Update alert rule", "tags": ["Alerts"]}, "delete": {"summary": "Delete alert rule", "tags": ["Alerts"]}},
            "/api/integrations":         {"get":  {"summary": "List integrations", "tags": ["Integrations"]}, "post": {"summary": "Create integration", "tags": ["Integrations"]}},
            "/api/integrations/{id}":    {"put":  {"summary": "Update integration", "tags": ["Integrations"]}, "delete": {"summary": "Delete integration", "tags": ["Integrations"]}},
            "/api/jobs":                 {"post": {"summary": "Create ingestion job", "tags": ["Jobs"]}},
            "/api/jobs/{id}":            {"put":  {"summary": "Update job", "tags": ["Jobs"]}, "delete": {"summary": "Delete job", "tags": ["Jobs"]}},
            "/api/jobs/{id}/run":        {"post": {"summary": "Trigger job immediately", "tags": ["Jobs"]}},
            "/api/jobs/{id}/runs":       {"get":  {"summary": "Job run history (paginated)", "tags": ["Jobs"]}},
            "/api/dashboards":           {"post": {"summary": "Save dashboard", "tags": ["Dashboards"]}},
            "/api/dashboards/{id}":      {"put":  {"summary": "Update dashboard", "tags": ["Dashboards"]}, "delete": {"summary": "Delete dashboard", "tags": ["Dashboards"]}},
            "/api/keys":                 {"get":  {"summary": "List API keys", "tags": ["Keys"]}, "post": {"summary": "Create API key (with scopes)", "tags": ["Keys"]}},
            "/api/keys/{id}":            {"delete":{"summary": "Revoke API key", "tags": ["Keys"]}},
            "/api/sessions":             {"get":  {"summary": "List active sessions", "tags": ["Auth"]}},
            "/api/sessions/{id}":        {"delete":{"summary": "Revoke session", "tags": ["Auth"]}},
            "/api/audit":                {"get":  {"summary": "Audit log (paginated, admin)", "tags": ["Audit"]}},
            "/api/org/retention":        {"post": {"summary": "Set retention policy", "tags": ["Org"]}},
            "/api/org/rate-limit":       {"post": {"summary": "Set ingest rate limit", "tags": ["Org"]}},
            "/api/ai/anomaly-summary":   {"post": {"summary": "AI summary of last hour errors", "tags": ["AI"]}},
            "/api/ai/suggest-search":    {"post": {"summary": "NL → search filter JSON", "tags": ["AI"]}},
            "/api/ai/build-alert":       {"post": {"summary": "NL → alert rule JSON", "tags": ["AI"]}},
            "/api/observability":        {"get":  {"summary": "IP + error observability dashboard", "tags": ["Observability"]}},
            "/api/health":               {"get":  {"summary": "Health check", "tags": ["System"]}},
        },
    }
    return jsonify(spec)


# ─────────────────────────── Flow Analytics ──────────────────────────────────

@app.get("/api/traces")
def list_traces():
    """List distinct trace/correlation IDs with event counts and error flags."""
    user, err = require_auth()
    if err:
        return err
    org_id = user["org_id"]
    db = get_db()
    limit  = min(int(request.args.get("limit", 50)), 200)
    q      = sanitize_input(request.args.get("q", ""), 100)
    sql    = (
        "SELECT correlation_id, COUNT(*) AS event_count, "
        "  MAX(CASE WHEN level IN ('error','critical') THEN 1 ELSE 0 END) AS has_error, "
        "  MIN(timestamp) AS started_at, MAX(timestamp) AS ended_at "
        "FROM log_events "
        "WHERE org_id=? AND correlation_id IS NOT NULL AND correlation_id != '' "
    )
    params: list = [org_id]
    if q:
        sql += " AND correlation_id LIKE ? "
        params.append(f"%{q}%")
    sql += " GROUP BY correlation_id ORDER BY started_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(sql, params).fetchall()
    return jsonify({"traces": [dict(r) for r in rows]})


@app.get("/api/traces/<trace_id>")
def get_trace(trace_id: str):
    """Fetch all events for a trace_id and compute relative timing offsets (waterfall)."""
    user, err = require_auth()
    if err:
        return err
    org_id   = user["org_id"]
    trace_id = sanitize_input(trace_id, 100)
    db       = get_db()
    rows = db.execute(
        "SELECT id, timestamp, level, source, event_id, message, "
        "       payload_json, correlation_id, status_code, duration_ms "
        "FROM log_events "
        "WHERE org_id=? AND correlation_id=? "
        "ORDER BY timestamp ASC LIMIT 500",
        (org_id, trace_id),
    ).fetchall()
    if not rows:
        return jsonify({"error": "Trace not found or no events match."}), 404

    events = [dict(r) for r in rows]
    # Compute relative offsets from first event (ms)
    try:
        from datetime import datetime, timezone
        def _ms(ts: str) -> float:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(ts[:26], fmt).replace(tzinfo=timezone.utc).timestamp() * 1000
                except ValueError:
                    continue
            return 0.0
        base_ms = _ms(events[0]["timestamp"])
        for ev in events:
            ev["offset_ms"] = round(_ms(ev["timestamp"]) - base_ms, 1)
    except Exception:
        for ev in events:
            ev["offset_ms"] = 0
    has_error = any(e.get("level") in ("error", "critical") for e in events)
    total_span_ms = events[-1].get("offset_ms", 0) if events else 0
    return jsonify({
        "trace_id":     trace_id,
        "event_count":  len(events),
        "has_error":    has_error,
        "total_span_ms": total_span_ms,
        "events":       events,
    })


# ─────────────────────────── AI: RCA & Summarizer ────────────────────────────

@app.post("/api/ai/rca")
def ai_rca():
    """AI Root Cause Analysis — accepts trace_id or list of log_ids."""
    user, err = require_auth()
    if err:
        return err
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured on server."}), 503

    org_id  = user["org_id"]
    payload = request_payload()
    db      = get_db()

    trace_id = sanitize_input(str(payload.get("trace_id", "")), 100)
    log_ids  = payload.get("log_ids", [])

    if trace_id:
        rows = db.execute(
            "SELECT id, timestamp, level, source, message, payload_json, status_code, duration_ms "
            "FROM log_events WHERE org_id=? AND correlation_id=? ORDER BY timestamp ASC LIMIT 100",
            (org_id, trace_id),
        ).fetchall()
    elif log_ids:
        placeholders = ",".join("?" * len(log_ids[:50]))
        rows = db.execute(
            f"SELECT id, timestamp, level, source, message, payload_json, status_code, duration_ms "
            f"FROM log_events WHERE org_id=? AND id IN ({placeholders}) ORDER BY timestamp ASC",
            [org_id, *log_ids[:50]],
        ).fetchall()
    else:
        return jsonify({"error": "Provide trace_id or log_ids."}), 400

    if not rows:
        return jsonify({"error": "No events found for the given trace/logs."}), 404

    events = [dict(r) for r in rows]
    log_block = "\n".join(
        f"[{e['timestamp']}] [{e['level'].upper()}] [{e['source']}] {e['message']}"
        + (f" | status={e['status_code']}" if e.get("status_code") else "")
        + (f" | duration={e['duration_ms']}ms" if e.get("duration_ms") else "")
        for e in events
    )

    prompt = f"""You are an expert SRE / backend engineer. Analyse the following log trace and return ONLY valid JSON — no markdown, no backticks, no extra text.

Log events (chronological):
{log_block}

Return exactly this JSON structure:
{{
  "root_cause": "one concise sentence",
  "culprit_service": "service name or 'unknown'",
  "severity": "low|medium|high|critical",
  "timeline": [
    {{"time": "...", "event": "brief description"}}
  ],
  "fix_suggestion": "actionable fix in 1-2 sentences",
  "confidence": "low|medium|high"
}}"""

    raw = _call_anthropic(prompt, max_tokens=800, system="You are an expert SRE. Return only valid JSON.")
    # Strip markdown fences if model adds them
    clean = raw.strip()
    if clean.startswith("```"):
        clean = "\n".join(clean.split("\n")[1:])
    if clean.endswith("```"):
        clean = clean.rsplit("```", 1)[0]
    try:
        import json as _json
        result = _json.loads(clean.strip())
    except Exception:
        result = {"root_cause": raw, "culprit_service": "unknown", "severity": "unknown",
                  "timeline": [], "fix_suggestion": "Review logs manually.", "confidence": "low"}

    audit(org_id, user["id"], "ai_rca", "trace", trace_id or str(log_ids[:3]))
    return jsonify({"ok": True, "rca": result, "event_count": len(events)})


@app.post("/api/ai/summarize")
def ai_summarize():
    """AI log summarizer — condenses up to 500 log lines into bullet-point insights."""
    user, err = require_auth()
    if err:
        return err
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return jsonify({"error": "ANTHROPIC_API_KEY not configured on server."}), 503

    org_id  = user["org_id"]
    payload = request_payload()
    db      = get_db()

    from_ts = sanitize_input(str(payload.get("from_ts", "")), 30)
    to_ts   = sanitize_input(str(payload.get("to_ts", "")), 30)
    source  = sanitize_input(str(payload.get("source", "")), 100)
    level   = sanitize_input(str(payload.get("level", "")), 20)

    sql    = "SELECT timestamp, level, source, message FROM log_events WHERE org_id=?"
    params: list = [org_id]
    if from_ts:
        sql += " AND timestamp >= ?"; params.append(from_ts)
    if to_ts:
        sql += " AND timestamp <= ?"; params.append(to_ts)
    if source:
        sql += " AND source=?"; params.append(source)
    if level:
        sql += " AND level=?"; params.append(level)
    sql += " ORDER BY timestamp DESC LIMIT 500"

    rows   = db.execute(sql, params).fetchall()
    if not rows:
        return jsonify({"error": "No logs found for the specified filters."}), 404

    log_block = "\n".join(
        f"[{r['timestamp']}] [{r['level'].upper()}] [{r['source']}] {r['message']}"
        for r in rows
    )

    prompt = f"""You are an expert SRE. The following are log lines from an observability platform.
Summarise them into exactly 5 concise bullet points. Each bullet should highlight a key pattern,
anomaly, error trend, or insight. Return ONLY valid JSON — no markdown.

Logs:
{log_block[:12000]}

Return:
{{
  "summary": [
    "bullet 1",
    "bullet 2",
    "bullet 3",
    "bullet 4",
    "bullet 5"
  ],
  "top_error": "most frequent error message or 'none'",
  "top_source": "most active source or 'unknown'",
  "error_rate_pct": 0.0
}}"""

    raw = _call_anthropic(prompt, max_tokens=600, system="You are an expert SRE. Return only valid JSON.")
    clean = raw.strip()
    if clean.startswith("```"):
        clean = "\n".join(clean.split("\n")[1:])
    if clean.endswith("```"):
        clean = clean.rsplit("```", 1)[0]
    try:
        import json as _json
        result = _json.loads(clean.strip())
    except Exception:
        result = {"summary": [raw], "top_error": "unknown", "top_source": "unknown", "error_rate_pct": 0}

    return jsonify({"ok": True, "result": result, "log_count": len(rows)})


# ─────────────────────────── Startup ─────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    start_scheduler()
    start_worker()
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    init_db()
    start_scheduler()
    start_worker()
