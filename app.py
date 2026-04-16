from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
from collections import Counter
from datetime import datetime, timezone
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

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "observex.db"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

LEVEL_PATTERNS = {
    "error": [r"\berror\b", r"\bexception\b", r"\bfailed\b", r"\btraceback\b", r"\btimeout\b"],
    "warn": [r"\bwarn\b", r"\bwarning\b", r"\bdegraded\b", r"\bretry\b"],
    "success": [r"\bsuccess\b", r"\bcompleted\b", r"\bok\b", r"\b200\b"],
    "info": [r"\binfo\b", r"\bstarted\b", r"\bprocessing\b"],
    "debug": [r"\bdebug\b", r"\bverbose\b"],
}

TS_KEYS = ["timestamp", "time", "@timestamp", "date", "createdAt", "datetime"]
MESSAGE_KEYS = ["message", "msg", "log", "event", "description"]
SOURCE_KEYS = ["source", "service", "app", "application", "logger", "component", "system"]
ID_KEYS = ["eventId", "requestId", "traceId", "correlationId", "transactionId", "id"]


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


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT NOT NULL UNIQUE,
            theme_color TEXT NOT NULL DEFAULT '#5b8cff',
            logo_text TEXT NOT NULL DEFAULT 'VX',
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
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL,
            schedule TEXT NOT NULL,
            last_run_at TEXT,
            next_run_at TEXT,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(org_id) REFERENCES organizations(id)
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

        CREATE INDEX IF NOT EXISTS idx_logs_org_ts ON log_events(org_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_logs_org_level ON log_events(org_id, level);
        CREATE INDEX IF NOT EXISTS idx_integrations_org ON integrations(org_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_org ON alert_rules(org_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_org ON ingestion_jobs(org_id);
        """
    )
    db.commit()

    row = db.execute("SELECT id FROM organizations WHERE slug = ?", ("vewit",)).fetchone()
    if row is None:
        now = iso_now()
        db.execute(
            "INSERT INTO organizations (name, slug, theme_color, logo_text, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Vewit", "vewit", "#5b8cff", "VX", now),
        )
        org_id = db.execute("SELECT id FROM organizations WHERE slug = ?", ("vewit",)).fetchone()[0]
        db.execute(
            "INSERT INTO users (org_id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, "Platform Admin", "admin@vewit.local", generate_password_hash("admin123"), "admin", now),
        )
        seed_integrations = [
            (org_id, "s3", "Production Archive", "healthy", json.dumps({"bucket": "vewit-prod-logs", "region": "ap-south-1", "prefix": "apps/"}), now, now),
            (org_id, "api", "Partner Event API", "configured", json.dumps({"url": "https://api.example.com/logs", "method": "GET"}), now, now),
        ]
        db.executemany(
            "INSERT INTO integrations (org_id, kind, name, status, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            seed_integrations,
        )
        seed_jobs = [
            (org_id, "Nightly S3 Sync", "s3", "scheduled", "0 */6 * * *", now, now, json.dumps({"mode": "incremental", "retention": "90d"}), now),
            (org_id, "API Poller", "api", "paused", "*/15 * * * *", None, None, json.dumps({"batch_size": 500, "timeout_sec": 20}), now),
        ]
        db.executemany(
            "INSERT INTO ingestion_jobs (org_id, name, source_type, status, schedule, last_run_at, next_run_at, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        db.commit()
    db.close()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def require_auth() -> tuple[dict[str, Any] | None, tuple[Any, int] | None]:
    user_id = session.get("user_id")
    if not user_id:
        return None, (jsonify({"error": "Authentication required."}), 401)
    db = get_db()
    row = db.execute(
        """
        SELECT u.id, u.name, u.email, u.role, u.org_id, o.name AS org_name, o.slug, o.theme_color, o.logo_text
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


# ----------------------------- Utility -----------------------------

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name or "upload")


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
        "message": message or fallback_message or "Log event",
        "payload": payload,
    }


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


def parse_plain_text(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
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
            "message": message,
            "payload": {"raw": line},
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
        "recent": sorted_records[:200],
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
    }


# ----------------------------- Web routes -----------------------------
@app.get("/")
def root():
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
        "SELECT id, name, email, role, org_id, password_hash FROM users WHERE lower(email) = ?",
        (email,),
    ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401
    session["user_id"] = user["id"]
    session["csrf"] = secrets.token_hex(16)
    return jsonify({"message": "Login successful."})


@app.post("/logout")
def logout():
    session.clear()
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
    for item in integrations:
        item["settings"] = json.loads(item.pop("settings_json"))
    for item in jobs:
        item["details"] = json.loads(item.pop("details_json"))
    summary = dashboard_summary(user["org_id"])
    return jsonify({
        "user": user,
        "organization": {
            "id": user["org_id"],
            "name": user["org_name"],
            "slug": user["slug"],
            "theme_color": user["theme_color"],
            "logo_text": user["logo_text"],
        },
        "summary": summary,
        "integrations": integrations,
        "jobs": jobs,
        "alerts": alerts,
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
    sql = "SELECT timestamp, level, source, event_id, message FROM log_events WHERE org_id = ?"
    if level != "all":
        sql += " AND level = ?"
        params.append(level)
    if q:
        sql += " AND (lower(message) LIKE ? OR lower(source) LIKE ? OR lower(coalesce(event_id,'')) LIKE ?)"
        pattern = f"%{q.lower()}%"
        params.extend([pattern, pattern, pattern])
    sql += " ORDER BY timestamp DESC LIMIT 200"
    rows = [dict(row) for row in db.execute(sql, params).fetchall()]
    return jsonify({"records": rows})


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
            user["org_id"],
            upload_id,
            record["timestamp"],
            record["level"],
            record["source"],
            record.get("event_id") or "",
            record["message"],
            json.dumps(record.get("payload", {})),
            now,
        ) for record in records],
    )
    db.commit()

    summary = summarize(records)
    return jsonify({
        "filename": filename,
        "summary": summary,
        "dashboard": dashboard_summary(user["org_id"]),
    })


@app.post("/api/integrations")
def add_integration():
    user, error = require_auth()
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
        (
            user["org_id"],
            kind,
            payload.get("name") or f"{kind.upper()} integration",
            payload.get("status") or "configured",
            json.dumps(payload.get("settings") or {}),
            now,
            now,
        ),
    )
    db.commit()
    return jsonify({"message": "Integration saved.", "id": cur.lastrowid})


@app.post("/api/alerts")
def add_alert():
    user, error = require_auth()
    if error:
        return error
    payload = request.get_json(force=True)
    now = iso_now()
    db = get_db()
    cur = db.execute(
        "INSERT INTO alert_rules (org_id, name, severity, condition_text, status, channel, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user["org_id"],
            payload.get("name") or "New alert",
            payload.get("severity") or "sev3",
            payload.get("condition_text") or "condition pending",
            payload.get("status") or "draft",
            payload.get("channel") or "Slack",
            now,
        ),
    )
    db.commit()
    return jsonify({"message": "Alert rule created.", "id": cur.lastrowid})


@app.post("/api/jobs")
def add_job():
    user, error = require_auth()
    if error:
        return error
    payload = request.get_json(force=True)
    now = iso_now()
    db = get_db()
    cur = db.execute(
        "INSERT INTO ingestion_jobs (org_id, name, source_type, status, schedule, last_run_at, next_run_at, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user["org_id"],
            payload.get("name") or "New ingestion job",
            payload.get("source_type") or "api",
            payload.get("status") or "scheduled",
            payload.get("schedule") or "0 * * * *",
            payload.get("last_run_at"),
            payload.get("next_run_at"),
            json.dumps(payload.get("details") or {}),
            now,
        ),
    )
    db.commit()
    return jsonify({"message": "Job created.", "id": cur.lastrowid})


@app.post("/api/org")
def update_org():
    user, error = require_auth()
    if error:
        return error
    payload = request.get_json(force=True)
    db = get_db()
    db.execute(
        "UPDATE organizations SET name = ?, theme_color = ?, logo_text = ? WHERE id = ?",
        (
            payload.get("name") or user["org_name"],
            payload.get("theme_color") or user["theme_color"],
            payload.get("logo_text") or user["logo_text"],
            user["org_id"],
        ),
    )
    db.commit()
    return jsonify({"message": "Organization settings updated."})


@app.post("/api/integrations/s3/test")
def test_s3():
    user, error = require_auth()
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
                {
                    "key": item.get("Key"),
                    "size": item.get("Size"),
                    "last_modified": item.get("LastModified").isoformat() if item.get("LastModified") else None,
                }
                for item in resp.get("Contents", [])
            ],
        })
    except (BotoCoreError, ClientError, Exception) as exc:
        return jsonify({"success": False, "message": f"S3 connection failed: {exc}"}), 400


@app.post("/api/integrations/api/test")
def test_api():
    user, error = require_auth()
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
        return jsonify({
            "success": True,
            "message": "API connection successful.",
            "status_code": response.status_code,
            "preview": response.text[:1200],
        })
    except Exception as exc:
        return jsonify({"success": False, "message": f"API connection failed: {exc}"}), 400


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
