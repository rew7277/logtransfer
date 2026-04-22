import os
import sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "observex.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "observex-v3-dev-secret")
app.config["DATABASE"] = DB_PATH


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        '''
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_name TEXT NOT NULL,
            workspace_slug TEXT UNIQUE NOT NULL,
            admin_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            primary_environment TEXT NOT NULL DEFAULT 'Production',
            theme_mode TEXT NOT NULL DEFAULT 'dark',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            environment TEXT NOT NULL,
            service TEXT NOT NULL,
            level TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            message TEXT NOT NULL,
            masking_state TEXT NOT NULL,
            latency_ms INTEGER NOT NULL,
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
        );
        '''
    )
    db.commit()

    # Seed one demo workspace only if none exists
    existing = cur.execute("SELECT COUNT(*) AS c FROM workspaces").fetchone()[0]
    if existing == 0:
        cur.execute(
            '''
            INSERT INTO workspaces (org_name, workspace_slug, admin_name, email, password_hash, primary_environment, theme_mode, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                "FiveStar Demo",
                "fivestar-demo",
                "Prasanna",
                "demo@observex.local",
                generate_password_hash("Demo@123"),
                "Production",
                "dark",
                datetime.utcnow().isoformat()
            )
        )
        workspace_id = cur.lastrowid

        seed_logs = [
            ("2026-04-22 11:20:42", "Production", "payment-engine", "ERROR", "TRC-98A21F", "EVT-101", "Beneficiary validation failed for account ********2198", "masked", 1821),
            ("2026-04-22 11:19:58", "Production", "auth-service", "WARN", "TRC-23D77B", "EVT-102", "Token refresh attempt from unusual IP range", "hidden", 214),
            ("2026-04-22 11:19:10", "UAT", "x-portal-loans", "INFO", "TRC-77P11K", "EVT-103", "Loan onboarding sync completed successfully", "clean", 98),
            ("2026-04-22 11:18:21", "Development", "dedupe-v3", "DEBUG", "TRC-66L42Q", "EVT-104", "Duplicate profile compare invoked with request hash d3f-****", "masked", 340),
            ("2026-04-22 11:17:35", "Production", "api-gateway", "ERROR", "TRC-54H10N", "EVT-105", "5xx threshold crossed for /internal/1.0/creditrisk", "masked", 924),
        ]
        for row in seed_logs:
            cur.execute(
                '''
                INSERT INTO log_events (workspace_id, timestamp, environment, service, level, trace_id, event_id, message, masking_state, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (workspace_id, *row)
            )

        seed_alerts = [
            ("PII masking gap in custom headers", "Critical", "Masking Engine", "Open", "2026-04-22 11:22:00"),
            ("Latency spike above threshold", "High", "Trace Monitor", "Open", "2026-04-22 11:17:00"),
            ("5xx error threshold crossed", "Medium", "API Gateway", "Investigating", "2026-04-22 11:12:00"),
            ("Suspicious login burst detected", "High", "Security Analytics", "Open", "2026-04-22 11:05:00"),
        ]
        for row in seed_alerts:
            cur.execute(
                '''
                INSERT INTO alerts (workspace_id, title, severity, source, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (workspace_id, *row)
            )
        db.commit()
    db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "workspace_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_workspace():
    if "workspace_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM workspaces WHERE id = ?", (session["workspace_id"],)).fetchone()


@app.context_processor
def inject_globals():
    return {"workspace": current_workspace()}


@app.route("/")
def landing():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM workspaces WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["workspace_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip()
        workspace_slug = request.form.get("workspace_slug", "").strip().lower()
        admin_name = request.form.get("admin_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        primary_environment = request.form.get("primary_environment", "Production")

        if not all([org_name, workspace_slug, admin_name, email, password]):
            flash("Please fill all required fields.", "error")
            return render_template("register.html")

        db = get_db()
        exists = db.execute(
            "SELECT id FROM workspaces WHERE email = ? OR workspace_slug = ?",
            (email, workspace_slug)
        ).fetchone()
        if exists:
            flash("Workspace slug or email already exists.", "error")
            return render_template("register.html")

        cur = db.execute(
            '''
            INSERT INTO workspaces (org_name, workspace_slug, admin_name, email, password_hash, primary_environment, theme_mode, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'dark', ?)
            ''',
            (org_name, workspace_slug, admin_name, email, generate_password_hash(password), primary_environment, datetime.utcnow().isoformat())
        )
        db.commit()
        workspace_id = cur.lastrowid

        # seed a few starter events so the dashboard doesn't feel empty
        starter_logs = [
            ("2026-04-22 12:00:01", primary_environment, "payment-engine", "INFO", "TRC-NEW101", "EVT-201", "Workspace created and telemetry pipeline initialized", "clean", 120),
            ("2026-04-22 12:02:44", primary_environment, "auth-service", "WARN", "TRC-NEW102", "EVT-202", "New admin session from registration flow", "hidden", 154),
        ]
        for row in starter_logs:
            db.execute(
                '''
                INSERT INTO log_events (workspace_id, timestamp, environment, service, level, trace_id, event_id, message, masking_state, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (workspace_id, *row)
            )
        db.execute(
            '''
            INSERT INTO alerts (workspace_id, title, severity, source, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (workspace_id, "Workspace health baseline created", "Low", "Bootstrap Engine", "Resolved", datetime.utcnow().isoformat())
        )
        db.commit()

        session["workspace_id"] = workspace_id
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    ws = current_workspace()
    logs = db.execute(
        "SELECT * FROM log_events WHERE workspace_id = ? ORDER BY id DESC LIMIT 5",
        (ws["id"],)
    ).fetchall()
    alerts = db.execute(
        "SELECT * FROM alerts WHERE workspace_id = ? ORDER BY id DESC LIMIT 4",
        (ws["id"],)
    ).fetchall()

    total_logs = db.execute("SELECT COUNT(*) AS c FROM log_events WHERE workspace_id = ?", (ws["id"],)).fetchone()["c"]
    open_alerts = db.execute("SELECT COUNT(*) AS c FROM alerts WHERE workspace_id = ? AND status != 'Resolved'", (ws["id"],)).fetchone()["c"]
    error_count = db.execute("SELECT COUNT(*) AS c FROM log_events WHERE workspace_id = ? AND level = 'ERROR'", (ws["id"],)).fetchone()["c"]
    avg_latency = db.execute("SELECT AVG(latency_ms) AS avg_lat FROM log_events WHERE workspace_id = ?", (ws["id"],)).fetchone()["avg_lat"] or 0

    return render_template(
        "dashboard.html",
        logs=logs,
        alerts=alerts,
        stats={
            "active_incidents": open_alerts,
            "logs_ingested": total_logs,
            "error_rate": f"{(error_count / total_logs * 100):.2f}%" if total_logs else "0.00%",
            "p95_latency": f"{int(avg_latency)} ms",
            "masking_score": "98.7%",
        }
    )


@app.route("/logs")
@login_required
def logs_page():
    db = get_db()
    ws = current_workspace()
    logs = db.execute(
        "SELECT * FROM log_events WHERE workspace_id = ? ORDER BY id DESC LIMIT 50",
        (ws["id"],)
    ).fetchall()
    return render_template("logs.html", logs=logs)


@app.route("/traces")
@login_required
def traces_page():
    db = get_db()
    ws = current_workspace()
    trace_rows = db.execute(
        "SELECT trace_id, service, environment, latency_ms, level, message FROM log_events WHERE workspace_id = ? ORDER BY id DESC LIMIT 12",
        (ws["id"],)
    ).fetchall()
    return render_template("traces.html", trace_rows=trace_rows)


@app.route("/alerts")
@login_required
def alerts_page():
    db = get_db()
    ws = current_workspace()
    alerts = db.execute(
        "SELECT * FROM alerts WHERE workspace_id = ? ORDER BY id DESC",
        (ws["id"],)
    ).fetchall()
    return render_template("alerts.html", alerts=alerts)


@app.route("/security")
@login_required
def security_page():
    return render_template("security.html")


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")


@app.route("/api/bootstrap")
@login_required
def bootstrap_api():
    db = get_db()
    ws = current_workspace()
    latest_logs = db.execute(
        "SELECT timestamp, service, level, trace_id, environment, message, masking_state, latency_ms FROM log_events WHERE workspace_id = ? ORDER BY id DESC LIMIT 8",
        (ws["id"],)
    ).fetchall()
    latest_alerts = db.execute(
        "SELECT title, severity, source, status, created_at FROM alerts WHERE workspace_id = ? ORDER BY id DESC LIMIT 6",
        (ws["id"],)
    ).fetchall()
    return jsonify({
        "workspace": {
            "org_name": ws["org_name"],
            "workspace_slug": ws["workspace_slug"],
            "primary_environment": ws["primary_environment"],
            "theme_mode": ws["theme_mode"],
        },
        "logs": [dict(r) for r in latest_logs],
        "alerts": [dict(r) for r in latest_alerts],
    })


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
