from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import Flask, g, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:  # pragma: no cover
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except Exception:  # pragma: no cover
    BackgroundScheduler = None

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "observex.db"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

LEVEL_PATTERNS = {
    "error": [r"\berror\b", r"\bexception\b", r"\bfailed\b", r"\btraceback\b", r"\btimeout\b", r"\brefused\b"],
    "warn": [r"\bwarn\b", r"\bwarning\b", r"\bdegraded\b", r"\bretry\b", r"\bslow\b"],
    "success": [r"\bsuccess\b", r"\bcompleted\b", r"\bok\b", r"\b200\b"],
    "info": [r"\binfo\b", r"\bstarted\b", r"\bprocessing\b"],
    "debug": [r"\bdebug\b", r"\bverbose\b"],
}

TS_KEYS = ["timestamp", "time", "@timestamp", "date", "createdAt", "datetime", "TimestampIST"]
MESSAGE_KEYS = ["message", "msg", "log", "event", "description"]
SOURCE_KEYS = ["source", "service", "app", "application", "logger", "component", "system", "ApplicationName"]
ID_KEYS = ["eventId", "requestId", "traceId", "correlationId", "transactionId", "id"]
HEADER_RE = re.compile(r"^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}")
MASK_PATTERNS = [
    (re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[A-Za-z0-9+/=._-]+"), r"\1\2 [REDACTED]"),
    (re.compile(r"(?i)(password\s*[:=]\s*)[^\s,\"']+"), r"\1[REDACTED]"),
    (re.compile(r"\bGLBCUST\d{8,}\b"), "GLBCUST[REDACTED]"),
    (re.compile(r"\bAPP-\d{4,}\b"), "APP-[REDACTED]"),
]

VALID_ROLES = {"admin", "manager", "developer", "tester"}
VALID_THEMES = {"white"}
DEFAULT_THEME_COLORS = {
    "white": "#2563eb",
}

scheduler: BackgroundScheduler | None = None


# ----------------------------- DB helpers -----------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_column(db: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    cols = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return cleaned or "workspace"


def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name or "upload.log")


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
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
            FOREIGN KEY(org_id) REFERENCES organizations(id),
            FOREIGN KEY(upload_id) REFERENCES uploads(id)
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

        CREATE INDEX IF NOT EXISTS idx_logs_org_ts ON log_events(org_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_org_level ON log_events(org_id, level);
        CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_org ON alert_rules(org_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_org ON ingestion_jobs(org_id);
        CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_events(org_id, created_at DESC);
        """
    )

    ensure_column(db, "organizations", "theme_mode", "theme_mode TEXT NOT NULL DEFAULT 'white'")
    ensure_column(db, "organizations", "admin_only", "admin_only INTEGER NOT NULL DEFAULT 0")
    ensure_column(db, "ingestion_jobs", "integration_id", "integration_id INTEGER")

    row = db.execute("SELECT id FROM organizations WHERE slug = ?", ("vewit",)).fetchone()
    if row is None:
        now = iso_now()
        db.execute(
            "INSERT INTO organizations (name, slug, theme_color, theme_mode, logo_text, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("Vewit", "vewit", DEFAULT_THEME_COLORS["black"], "black", "VX", 0, now),
        )
        org_id = db.execute("SELECT id FROM organizations WHERE slug = ?", ("vewit",)).fetchone()[0]
        db.execute(
            "INSERT INTO users (org_id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, "Platform Admin", "admin@vewit.local", generate_password_hash("admin123"), "admin", now),
        )
        admin_id = db.execute("SELECT id FROM users WHERE email = ?", ("admin@vewit.local",)).fetchone()[0]
        seed_integrations = [
            (org_id, "s3", "Production Archive", "healthy", json.dumps({"bucket": "vewit-prod-logs", "region": "ap-south-1", "prefix": "apps/"}), now, now),
            (org_id, "api", "Partner Event API", "configured", json.dumps({"url": "https://api.example.com/logs", "method": "GET"}), now, now),
        ]
        db.executemany(
            "INSERT INTO integrations (org_id, kind, name, status, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            seed_integrations,
        )
        seed_jobs = [
            (org_id, None, "Nightly S3 Sync", "s3", "scheduled", "0 */6 * * *", None, None, json.dumps({"mode": "incremental", "retention": "90d"}), now),
            (org_id, None, "API Poller", "api", "paused", "*/15 * * * *", None, None, json.dumps({"batch_size": 500, "timeout_sec": 20}), now),
        ]
        db.executemany(
            "INSERT INTO ingestion_jobs (org_id, integration_id, name, source_type, status, schedule, last_run_at, next_run_at, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            seed_jobs,
        )
        seed_alerts = [
            (org_id, "High error rate", "sev2", "error rate > 5% over 5m", "active", "Slack", now),
            (org_id, "Ingestion stalled", "sev1", "no logs received for 5m", "active", "PagerDuty", now),
            (org_id, "SLA breach spike", "sev2", "slow requests > 50 in 10m", "draft", "Email", now),
        ]
        db.executemany(
            "INSERT INTO alert_rules (org_id, name, severity, condition_text, status, channel, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            seed_alerts,
        )
        db.execute(
            "INSERT INTO audit_events (org_id, user_id, action, target_type, target_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (org_id, admin_id, "seeded_demo_workspace", "workspace", str(org_id), json.dumps({"email": "admin@vewit.local"}), now),
        )
    db.commit()
    db.close()


# ----------------------------- auth and audit -----------------------------

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


def audit(org_id: int, user_id: int | None, action: str, target_type: str, target_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO audit_events (org_id, user_id, action, target_type, target_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_id, user_id, action, target_type, target_id, json.dumps(detail or {}), iso_now()),
    )
    db.commit()


# ----------------------------- parsing -----------------------------

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
    message = first_value(payload, MESSAGE_KEYS, fallback_message)
    ts = None
    for key in TS_KEYS:
        if key in payload:
            ts = parse_timestamp(payload[key])
            if ts:
                break
    source = first_value(payload, SOURCE_KEYS, "system")
    ref_id = first_value(payload, ID_KEYS, "")
    return {
        "timestamp": ts or iso_now(),
        "level": detect_level(message, payload),
        "source": source,
        "event_id": ref_id,
        "message": redact_sensitive(message or fallback_message or "Log event"),
        "payload": payload,
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
                            "message": event.get("message"),
                            "source": obj.get("logGroup", "aws-cloudwatch"),
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
    lines = block.splitlines()
    header = lines[0] if lines else block
    header_match = re.match(
        r"^(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+\[(?P<thread>.*?)\]\s+\[(?P<meta>.*?)\]\s+(?P<logger>[^:]+):\s?(?P<msg>.*)$",
        header,
    )
    if not header_match:
        return {
            "timestamp": iso_now(),
            "level": detect_level(block),
            "source": "system",
            "event_id": "",
            "message": redact_sensitive(block),
            "payload": {"raw": redact_sensitive(block)},
        }

    data = header_match.groupdict()
    source_match = re.search(r"\[([^\]]+)\]\.([^\.\s]+)", data["thread"])
    source = source_match.group(1) if source_match else "system"
    event_id_match = re.search(r"event:\s*([^\];]+)", data["meta"])
    event_id = event_id_match.group(1).strip() if event_id_match else ""

    body_lines = lines[1:]
    combined_message = data["msg"]
    if body_lines:
        combined_message += "\n" + "\n".join(body_lines)
    combined_message = redact_sensitive(combined_message.strip())

    payload: dict[str, Any] = {
        "timestamp": data["ts"],
        "level": data["level"],
        "source": source,
        "logger": data["logger"].strip(),
        "thread": data["thread"],
        "correlationId": event_id,
        "message": combined_message,
        "raw": redact_sensitive(block),
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
                payload["source"] = common.get("ApplicationName", source)
                payload["correlationId"] = common.get("correlationId", event_id)
                source = payload["source"]
                event_id = payload["correlationId"]
        except Exception:
            pass

    return {
        "timestamp": parse_timestamp(data["ts"]) or iso_now(),
        "level": data["level"].lower(),
        "source": source,
        "event_id": event_id,
        "message": combined_message,
        "payload": payload,
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
        ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d{3})?)\s+(.*)$", line)
        timestamp = iso_now()
        message = line
        if ts_match:
            timestamp = parse_timestamp(ts_match.group(1)) or iso_now()
            message = ts_match.group(2)
        event_id_match = re.search(r"\b(?:eventId|requestId|traceId|correlationId|transactionId)[=: ]+([A-Za-z0-9._:-]+)", line, re.I)
        source_match = re.search(r"\[([^\]]+)\]", line)
        records.append({
            "timestamp": timestamp,
            "level": detect_level(message),
            "source": source_match.group(1) if source_match else "system",
            "event_id": event_id_match.group(1) if event_id_match else "",
            "message": redact_sensitive(message),
            "payload": {"raw": redact_sensitive(line)},
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
    total = len(records)
    levels = Counter(record["level"] for record in records)
    sources = Counter(record["source"] for record in records)
    terms: Counter[str] = Counter()
    for record in records:
        words = re.findall(r"[A-Za-z][A-Za-z0-9._-]{3,}", record["message"])
        terms.update(word.lower() for word in words[:8])
    sorted_records = sorted(records, key=lambda r: r["timestamp"], reverse=True)
    return {
        "total": total,
        "levels": dict(levels),
        "sources": sources.most_common(8),
        "top_terms": terms.most_common(12),
        "recent": sorted_records[:30],
    }


def dashboard_summary(org_id: int) -> dict[str, Any]:
    db = get_db()
    counts = db.execute(
        "SELECT level, COUNT(*) AS count FROM log_events WHERE org_id = ? GROUP BY level",
        (org_id,),
    ).fetchall()
    level_counts = {row["level"]: row["count"] for row in counts}
    total_logs = sum(level_counts.values())
    integrations = db.execute("SELECT COUNT(*) FROM integrations WHERE org_id = ?", (org_id,)).fetchone()[0]
    jobs = db.execute("SELECT COUNT(*) FROM ingestion_jobs WHERE org_id = ?", (org_id,)).fetchone()[0]
    alerts = db.execute("SELECT COUNT(*) FROM alert_rules WHERE org_id = ?", (org_id,)).fetchone()[0]
    users = db.execute("SELECT COUNT(*) FROM users WHERE org_id = ?", (org_id,)).fetchone()[0]
    uploads = db.execute("SELECT COUNT(*) FROM uploads WHERE org_id = ?", (org_id,)).fetchone()[0]
    error_rate = round((level_counts.get("error", 0) / total_logs) * 100, 2) if total_logs else 0
    recent_sources = [dict(row) for row in db.execute(
        "SELECT source, COUNT(*) AS count FROM log_events WHERE org_id = ? GROUP BY source ORDER BY count DESC LIMIT 6",
        (org_id,),
    ).fetchall()]
    latest_log = db.execute("SELECT MAX(timestamp) FROM log_events WHERE org_id = ?", (org_id,)).fetchone()[0]
    uploads_week = db.execute(
        "SELECT COUNT(*) FROM uploads WHERE org_id = ? AND created_at >= ?",
        (org_id, (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()),
    ).fetchone()[0]
    return {
        "totals": {
            "logs": total_logs,
            "integrations": integrations,
            "jobs": jobs,
            "alerts": alerts,
            "users": users,
            "uploads": uploads,
        },
        "levels": level_counts,
        "error_rate": error_rate,
        "source_breakdown": recent_sources,
        "latest_log": latest_log,
        "uploads_week": uploads_week,
    }


# ----------------------------- ingestion -----------------------------

def parse_cron_next_run(expr: str) -> str | None:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    try:
        minute, hour, *_ = expr.split()
        for i in range(1, 24 * 60 + 1):
            candidate = now + timedelta(minutes=i)
            minute_ok = minute == "*" or minute == f"{candidate.minute}" or (minute.startswith("*/") and candidate.minute % int(minute[2:]) == 0)
            hour_ok = hour == "*" or hour == f"{candidate.hour}" or (hour.startswith("*/") and candidate.hour % int(hour[2:]) == 0)
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
    job = dict(row)
    details = json.loads(job["details_json"] or "{}")
    integration = fetch_latest_integration(user["org_id"], job["source_type"])
    now = iso_now()
    records: list[dict[str, Any]] = []

    if job["source_type"] == "api":
        if requests is None:
            return False, "requests is not installed.", 0
        if not integration:
            return False, "No API integration configured.", 0
        settings = integration["settings"]
        headers = settings.get("headers") or {}
        token = settings.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(settings.get("url"), headers=headers, timeout=15)
        body = resp.text
        records = parse_text_by_extension("remote_api.json", body)
        if not records:
            records = [to_record({"timestamp": now, "source": settings.get("name", "remote-api"), "message": body[:4000]})]
    elif job["source_type"] == "s3":
        if boto3 is None:
            return False, "boto3 is not installed.", 0
        if not integration:
            return False, "No S3 integration configured.", 0
        settings = integration["settings"]
        session_aws = boto3.session.Session(
            aws_access_key_id=settings.get("access_key"),
            aws_secret_access_key=settings.get("secret_key"),
            region_name=settings.get("region"),
        )
        client = session_aws.client("s3")
        resp = client.list_objects_v2(Bucket=settings.get("bucket"), Prefix=settings.get("prefix", ""), MaxKeys=int(details.get("max_keys", 3)))
        for item in resp.get("Contents", []):
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue
            obj = client.get_object(Bucket=settings.get("bucket"), Key=key)
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
        [(
            user["org_id"], upload_id, rec["timestamp"], rec["level"], rec["source"], rec.get("event_id") or "", rec["message"], json.dumps(rec.get("payload", {})), now
        ) for rec in records],
    )
    db.execute(
        "UPDATE ingestion_jobs SET last_run_at = ?, next_run_at = ? WHERE id = ?",
        (now, parse_cron_next_run(job["schedule"] or "*/15 * * * *"), job_id),
    )
    db.commit()
    audit(user["org_id"], user["id"], "ran_ingestion_job", "job", str(job_id), {"records": len(records), "source_type": job["source_type"]})
    return True, f"Job ran successfully and ingested {len(records)} records.", len(records)


def scheduler_tick() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    due = conn.execute(
        "SELECT * FROM ingestion_jobs WHERE status = 'scheduled' AND next_run_at IS NOT NULL AND next_run_at <= ?",
        (iso_now(),),
    ).fetchall()
    for job in due:
        user_row = conn.execute(
            "SELECT u.id, u.org_id, u.role, o.slug, o.name AS org_name, o.theme_color, o.theme_mode, o.logo_text, o.admin_only, u.email, u.name FROM users u JOIN organizations o ON o.id = u.org_id WHERE u.org_id = ? ORDER BY CASE WHEN u.role='admin' THEN 0 ELSE 1 END, u.id LIMIT 1",
            (job["org_id"],),
        ).fetchone()
        if user_row:
            with app.app_context():
                g.db = sqlite3.connect(DB_PATH)
                g.db.row_factory = sqlite3.Row
                try:
                    run_ingestion_job_internal(dict(user_row), job["id"])
                except Exception:
                    pass
                finally:
                    close_db(None)
    conn.close()


def start_scheduler() -> None:
    global scheduler
    if BackgroundScheduler is None or scheduler is not None:
        return
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(scheduler_tick, "interval", minutes=1, id="observex_scheduler_tick", replace_existing=True)
    scheduler.start()


# ----------------------------- web routes -----------------------------
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
        return redirect("/")
    return render_template("index.html", user=user)


@app.post("/login")
def login():
    payload = request.get_json(force=True)
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    db = get_db()
    user = db.execute(
        """
        SELECT u.id, u.name, u.email, u.role, u.org_id, u.password_hash, o.admin_only
        FROM users u
        JOIN organizations o ON o.id = u.org_id
        WHERE lower(u.email) = ?
        """,
        (email,),
    ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401
    if user["admin_only"] and user["role"] != "admin":
        return jsonify({"error": "This workspace is in admin-only mode."}), 403
    session["user_id"] = user["id"]
    session["csrf"] = secrets.token_hex(16)
    audit(user["org_id"], user["id"], "logged_in", "session", str(user["id"]), {"email": user["email"]})
    return jsonify({"message": "Login successful."})


@app.post("/register")
def register_org_and_admin():
    payload = request.get_json(force=True)
    org_name = (payload.get("organization_name") or "").strip()
    admin_name = (payload.get("name") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    role = (payload.get("role") or "admin").strip().lower()
    theme_mode = (payload.get("theme_mode") or "white").strip().lower()
    slug = slugify(payload.get("organization_slug") or org_name)
    if not org_name or not admin_name or not email or not password:
        return jsonify({"error": "Organization name, your name, email, and password are required."}), 400
    if role != "admin":
        return jsonify({"error": "Workspace creator must be an admin."}), 400
    if theme_mode not in VALID_THEMES:
        theme_mode = "white"

    db = get_db()
    existing_org = db.execute("SELECT id FROM organizations WHERE slug = ?", (slug,)).fetchone()
    if existing_org:
        return jsonify({"error": "That organization slug already exists. Try another organization name or slug."}), 400
    existing_email = db.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
    if existing_email:
        return jsonify({"error": "A user with that email already exists."}), 400

    now = iso_now()
    logo_text = "".join([part[0] for part in org_name.split()[:2]]).upper() or "OX"
    cur = db.execute(
        "INSERT INTO organizations (name, slug, theme_color, theme_mode, logo_text, admin_only, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (org_name, slug, DEFAULT_THEME_COLORS[theme_mode], theme_mode, logo_text[:3], 0, now),
    )
    org_id = cur.lastrowid
    user_cur = db.execute(
        "INSERT INTO users (org_id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (org_id, admin_name, email, generate_password_hash(password), "admin", now),
    )
    db.commit()
    session["user_id"] = user_cur.lastrowid
    session["csrf"] = secrets.token_hex(16)
    audit(org_id, user_cur.lastrowid, "created_workspace", "organization", str(org_id), {"slug": slug, "email": email, "theme_mode": theme_mode})
    return jsonify({"message": "Workspace created successfully.", "slug": slug})


@app.post("/logout")
def logout():
    user_id = session.get("user_id")
    user, _ = require_auth() if user_id else (None, None)
    session.clear()
    if user:
        audit(user["org_id"], user["id"], "logged_out", "session", str(user["id"]), {})
    return jsonify({"message": "Logged out."})


# ----------------------------- API routes -----------------------------
@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "ObserveX Enterprise", "time": iso_now()})


@app.get("/api/bootstrap")
def bootstrap():
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    integrations = [dict(row) for row in db.execute(
        "SELECT * FROM integrations WHERE org_id = ? ORDER BY updated_at DESC", (user["org_id"],)
    ).fetchall()]
    jobs = [dict(row) for row in db.execute(
        "SELECT * FROM ingestion_jobs WHERE org_id = ? ORDER BY id DESC", (user["org_id"],)
    ).fetchall()]
    alerts = [dict(row) for row in db.execute(
        "SELECT * FROM alert_rules WHERE org_id = ? ORDER BY id DESC", (user["org_id"],)
    ).fetchall()]
    users = [dict(row) for row in db.execute(
        "SELECT id, name, email, role, created_at FROM users WHERE org_id = ? ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'manager' THEN 2 WHEN 'developer' THEN 3 ELSE 4 END, created_at ASC", (user["org_id"],)
    ).fetchall()]
    audit_events = [dict(row) for row in db.execute(
        "SELECT created_at, action, target_type, target_id, detail_json FROM audit_events WHERE org_id = ? ORDER BY id DESC LIMIT 20", (user["org_id"],)
    ).fetchall()]
    for item in integrations:
        item["settings"] = json.loads(item.pop("settings_json"))
    for item in jobs:
        item["details"] = json.loads(item.pop("details_json"))
    for item in audit_events:
        item["detail"] = json.loads(item.pop("detail_json"))
    return jsonify({
        "user": user,
        "organization": {
            "id": user["org_id"],
            "name": user["org_name"],
            "slug": user["slug"],
            "theme_color": user["theme_color"],
            "theme_mode": user["theme_mode"],
            "logo_text": user["logo_text"],
            "admin_only": bool(user["admin_only"]),
            "subdomain_hint": f"{user['slug']}.vewit.com",
        },
        "summary": dashboard_summary(user["org_id"]),
        "integrations": integrations,
        "jobs": jobs,
        "alerts": alerts,
        "users": users,
        "audit": audit_events,
        "role_options": sorted(VALID_ROLES),
        "theme_options": sorted(VALID_THEMES),
    })


@app.get("/api/logs")
def get_logs():
    user, error = require_auth()
    if error:
        return error
    db = get_db()
    q = (request.args.get("q") or "").strip()
    level = (request.args.get("level") or "all").strip().lower()
    params: list[Any] = [user["org_id"]]
    sql = "SELECT id, timestamp, level, source, event_id, message FROM log_events WHERE org_id = ?"
    if level != "all":
        sql += " AND level = ?"
        params.append(level)
    if q:
        sql += " AND (lower(message) LIKE ? OR lower(source) LIKE ? OR lower(coalesce(event_id,'')) LIKE ?)"
        pattern = f"%{q.lower()}%"
        params.extend([pattern, pattern, pattern])
    sql += " ORDER BY timestamp DESC LIMIT 300"
    rows = [dict(row) for row in db.execute(sql, params).fetchall()]
    return jsonify({"records": rows})


@app.get("/api/logs/<int:log_id>")
def get_log_detail(log_id: int):
    user, error = require_auth()
    if error:
        return error
    db = get_db()
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
def upload_logs():
    user, error = require_auth()
    if error:
        return error
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    filename = safe_filename(file.filename or "upload.log")
    raw = file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="ignore")

    records = parse_text_by_extension(filename, text)
    if not records:
        return jsonify({"error": "No log records could be parsed from this file."}), 400

    db = get_db()
    now = iso_now()
    cur = db.execute(
        "INSERT INTO uploads (org_id, user_id, filename, total_records, created_at) VALUES (?, ?, ?, ?, ?)",
        (user["org_id"], user["id"], filename, len(records), now),
    )
    upload_id = cur.lastrowid
    db.executemany(
        "INSERT INTO log_events (org_id, upload_id, timestamp, level, source, event_id, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(
            user["org_id"], upload_id, record["timestamp"], record["level"], record["source"], record.get("event_id") or "", record["message"], json.dumps(record.get("payload", {})), now
        ) for record in records],
    )
    db.commit()
    audit(user["org_id"], user["id"], "uploaded_logs", "upload", str(upload_id), {"filename": filename, "records": len(records)})
    return jsonify({
        "filename": filename,
        "summary": summarize(records),
        "dashboard": dashboard_summary(user["org_id"]),
    })


@app.post("/api/users")
def create_user():
    user, error = require_admin()
    if error:
        return error
    payload = request.get_json(force=True)
    email = (payload.get("email") or "").strip().lower()
    name = (payload.get("name") or "").strip()
    password = payload.get("password") or ""
    role = (payload.get("role") or "developer").strip().lower()
    if not email or not name or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400
    if role not in VALID_ROLES:
        return jsonify({"error": f"Unsupported role. Use one of: {', '.join(sorted(VALID_ROLES))}."}), 400
    db = get_db()
    exists = db.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
    if exists:
        return jsonify({"error": "A user with that email already exists."}), 400
    cur = db.execute(
        "INSERT INTO users (org_id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user["org_id"], name, email, generate_password_hash(password), role, iso_now()),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_user", "user", str(cur.lastrowid), {"email": email, "role": role})
    return jsonify({"message": "User created.", "id": cur.lastrowid})


@app.post("/api/integrations")
def add_integration():
    user, error = require_admin()
    if error:
        return error
    payload = request.get_json(force=True)
    kind = payload.get("kind")
    if kind not in {"s3", "api"}:
        return jsonify({"error": "Unsupported integration kind."}), 400
    now = iso_now()
    db = get_db()
    cur = db.execute(
        "INSERT INTO integrations (org_id, kind, name, status, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], kind, payload.get("name") or f"{kind.upper()} integration", payload.get("status") or "configured", json.dumps(payload.get("settings") or {}), now, now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "saved_integration", "integration", str(cur.lastrowid), {"kind": kind, "name": payload.get("name")})
    return jsonify({"message": "Integration saved.", "id": cur.lastrowid})


@app.post("/api/alerts")
def add_alert():
    user, error = require_admin()
    if error:
        return error
    payload = request.get_json(force=True)
    now = iso_now()
    db = get_db()
    cur = db.execute(
        "INSERT INTO alert_rules (org_id, name, severity, condition_text, status, channel, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], payload.get("name") or "New alert", payload.get("severity") or "sev3", payload.get("condition_text") or "condition pending", payload.get("status") or "draft", payload.get("channel") or "Slack", now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_alert", "alert", str(cur.lastrowid), {"name": payload.get("name")})
    return jsonify({"message": "Alert rule created.", "id": cur.lastrowid})


@app.post("/api/jobs")
def add_job():
    user, error = require_admin()
    if error:
        return error
    payload = request.get_json(force=True)
    now = iso_now()
    db = get_db()
    source_type = payload.get("source_type") or "api"
    integration = fetch_latest_integration(user["org_id"], source_type)
    cur = db.execute(
        "INSERT INTO ingestion_jobs (org_id, integration_id, name, source_type, status, schedule, last_run_at, next_run_at, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user["org_id"], integration["id"] if integration else None, payload.get("name") or "New ingestion job", source_type, payload.get("status") or "scheduled", payload.get("schedule") or "0 * * * *", payload.get("last_run_at"), parse_cron_next_run(payload.get("schedule") or "0 * * * *"), json.dumps(payload.get("details") or {}), now),
    )
    db.commit()
    audit(user["org_id"], user["id"], "created_job", "job", str(cur.lastrowid), {"name": payload.get("name"), "source_type": source_type})
    return jsonify({"message": "Job created.", "id": cur.lastrowid})


@app.post("/api/jobs/<int:job_id>/run")
def run_job(job_id: int):
    user, error = require_admin()
    if error:
        return error
    success, message, count = run_ingestion_job_internal(user, job_id)
    status = 200 if success else 400
    return jsonify({"message": message, "count": count, "success": success}), status


@app.post("/api/org")
def update_org():
    user, error = require_admin()
    if error:
        return error
    payload = request.get_json(force=True)
    slug = slugify(payload.get("slug") or user["slug"])
    theme_mode = (payload.get("theme_mode") or user["theme_mode"] or "white").lower()
    if theme_mode not in VALID_THEMES:
        theme_mode = "white"
    theme_color = payload.get("theme_color") or DEFAULT_THEME_COLORS[theme_mode]
    db = get_db()
    existing = db.execute("SELECT id FROM organizations WHERE slug = ? AND id != ?", (slug, user["org_id"])).fetchone()
    if existing:
        return jsonify({"error": "That organization slug is already used by another workspace."}), 400
    db.execute(
        "UPDATE organizations SET name = ?, slug = ?, theme_color = ?, theme_mode = ?, logo_text = ?, admin_only = ? WHERE id = ?",
        (payload.get("name") or user["org_name"], slug, theme_color, theme_mode, (payload.get("logo_text") or user["logo_text"])[:3].upper(), 1 if payload.get("admin_only") else 0, user["org_id"]),
    )
    db.commit()
    audit(user["org_id"], user["id"], "updated_org_settings", "organization", str(user["org_id"]), payload)
    return jsonify({"message": "Organization settings updated."})


@app.post("/api/integrations/s3/test")
def test_s3():
    _, error = require_auth()
    if error:
        return error
    payload = request.get_json(force=True)
    if boto3 is None:
        return jsonify({"success": False, "message": "boto3 is not installed in this environment."}), 500
    try:
        session_aws = boto3.session.Session(
            aws_access_key_id=payload.get("access_key"),
            aws_secret_access_key=payload.get("secret_key"),
            region_name=payload.get("region"),
        )
        client = session_aws.client("s3")
        resp = client.list_objects_v2(Bucket=payload.get("bucket"), Prefix=payload.get("prefix", ""), MaxKeys=8)
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
    payload = request.get_json(force=True)
    if requests is None:
        return jsonify({"success": False, "message": "requests is not installed in this environment."}), 500
    url = payload.get("url")
    if not url:
        return jsonify({"success": False, "message": "API URL is required."}), 400
    headers = payload.get("headers") or {}
    auth_token = payload.get("token")
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return jsonify({"success": True, "message": "API connection successful.", "status_code": response.status_code, "preview": response.text[:1200]})
    except Exception as exc:
        return jsonify({"success": False, "message": f"API connection failed: {exc}"}), 400


if __name__ == "__main__":
    init_db()
    start_scheduler()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
else:
    init_db()
    start_scheduler()
