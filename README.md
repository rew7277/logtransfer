# ObserveX Enterprise v2

ObserveX Enterprise v2 is a polished Flask-based observability starter platform for **all systems**, not tied to MuleSoft or any single vendor.

## What is included

- secure login screen with seeded demo credentials
- organization-aware workspace and branding settings
- SQLite-backed persistence for uploads, logs, jobs, alerts, and integrations
- log upload and parsing for text, JSON, NDJSON, and CSV
- S3 connection testing and integration saving
- API connection testing and integration saving
- ingestion job management UI
- alert rule management UI
- searchable log explorer over persisted records

## Demo login

- **Email:** `admin@vewit.local`
- **Password:** `admin123`

Change these immediately before any real deployment.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8080`

## Deployment notes

This project is suitable as a strong starter for Railway, Render, or a VM/container deployment.

For production, the next recommended upgrades are:

- PostgreSQL instead of SQLite
- background workers for scheduled S3/API ingestion
- real RBAC and user invitations
- object storage for uploaded files
- charting and dashboard visualizations
- audit logs and secrets management
- queue-based ingestion pipeline

## Structure

- `app.py` — Flask app, auth, API routes, DB bootstrap, parsing
- `templates/login.html` — login experience
- `templates/index.html` — enterprise workspace UI
- `static/app.js` — client-side behavior
- `static/styles.css` — visual system
- `data/observex.db` — local demo database created on first run

