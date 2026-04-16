from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

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
CONFIG_FILE = DATA_DIR / "integrations.json"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB

LEVEL_PATTERNS = {
    "error": [r"\berror\b", r"\bexception\b", r"\bfailed\b", r"\btraceback\b"],
    "warn": [r"\bwarn\b", r"\bwarning\b", r"\bdegraded\b"],
    "success": [r"\bsuccess\b", r"\bcompleted\b", r"\bok\b", r"\b200\b"],
    "info": [r"\binfo\b", r"\bstarted\b", r"\bprocessing\b"],
    "debug": [r"\bdebug\b", r"\bverbose\b"],
}

TS_KEYS = ["timestamp", "time", "@timestamp", "date", "createdAt", "datetime"]
MESSAGE_KEYS = ["message", "msg", "log", "event", "description"]
SOURCE_KEYS = ["source", "service", "app", "application", "logger", "component", "system"]
ID_KEYS = ["eventId", "requestId", "traceId", "correlationId", "transactionId", "id"]


def load_integrations() -> dict[str, list[dict[str, Any]]]:
    if not CONFIG_FILE.exists():
        return {"s3": [], "api": []}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"s3": [], "api": []}


def save_integrations(data: dict[str, list[dict[str, Any]]]) -> None:
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
            ts = datetime.fromtimestamp(float(value) / (1000 if float(value) > 1e11 else 1), tz=timezone.utc)
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
            for item in obj:
                if isinstance(item, dict):
                    records.append(to_record(item))
            return records
        if isinstance(obj, dict):
            if "logEvents" in obj and isinstance(obj["logEvents"], list):
                for event in obj["logEvents"]:
                    if isinstance(event, dict):
                        inner = {"timestamp": event.get("timestamp"), "message": event.get("message"), "source": obj.get("logGroup", "aws-cloudwatch")}
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
    top_terms: Counter[str] = Counter()
    for record in records:
        words = re.findall(r"[A-Za-z][A-Za-z0-9._-]{3,}", record["message"])
        top_terms.update(word.lower() for word in words[:8])

    sorted_records = sorted(records, key=lambda r: r["timestamp"], reverse=True)
    return {
        "total": total,
        "levels": levels,
        "sources": sources.most_common(6),
        "top_terms": top_terms.most_common(10),
        "recent": sorted_records[:200],
    }


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "ObserveX", "time": iso_now()})


@app.get("/api/integrations")
def get_integrations():
    return jsonify(load_integrations())


@app.post("/api/integrations")
def add_integration():
    payload = request.get_json(force=True)
    integrations = load_integrations()
    kind = payload.get("kind")
    if kind not in {"s3", "api"}:
        return jsonify({"error": "Unsupported integration kind."}), 400

    record = {
        "id": f"{kind}_{int(datetime.now().timestamp())}",
        "name": payload.get("name", f"{kind.upper()} integration"),
        "kind": kind,
        "created_at": iso_now(),
        "settings": payload.get("settings", {}),
    }
    integrations.setdefault(kind, []).append(record)
    save_integrations(integrations)
    return jsonify({"message": "Integration saved.", "integration": record})


@app.post("/api/upload")
def upload_logs():
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

    summary = summarize(records)
    return jsonify({
        "filename": filename,
        "summary": {
            "total": summary["total"],
            "levels": summary["levels"],
            "sources": summary["sources"],
            "top_terms": summary["top_terms"],
        },
        "records": summary["recent"],
    })


@app.post("/api/integrations/s3/test")
def test_s3():
    payload = request.get_json(force=True)
    if boto3 is None:
        return jsonify({"success": False, "message": "boto3 is not installed in this environment."}), 500

    try:
        session = boto3.session.Session(
            aws_access_key_id=payload.get("access_key"),
            aws_secret_access_key=payload.get("secret_key"),
            region_name=payload.get("region"),
        )
        client = session.client("s3")
        bucket = payload.get("bucket")
        prefix = payload.get("prefix", "")
        resp = client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        contents = resp.get("Contents", [])
        return jsonify({
            "success": True,
            "message": "S3 connection successful.",
            "objects": [
                {
                    "key": item.get("Key"),
                    "size": item.get("Size"),
                    "last_modified": item.get("LastModified").isoformat() if item.get("LastModified") else None,
                }
                for item in contents
            ],
        })
    except (BotoCoreError, ClientError, Exception) as exc:
        return jsonify({"success": False, "message": f"S3 connection failed: {exc}"}), 400


@app.post("/api/integrations/api/test")
def test_api():
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
        preview = response.text[:1200]
        return jsonify({
            "success": True,
            "status_code": response.status_code,
            "message": "API connection successful.",
            "preview": preview,
        })
    except Exception as exc:
        return jsonify({"success": False, "message": f"API connection failed: {exc}"}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
