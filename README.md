# ObserveX

ObserveX is a system-agnostic log observability starter app built for any platform that emits logs.

It includes:
- professional web UI for upload, search, and operational review
- local file parsing for `.log`, `.txt`, `.json`, `.ndjson`, and `.csv`
- AWS S3 integration test and local config save flow
- API feed integration test and local config save flow
- generic branding and language suitable for all systems, not MuleSoft-specific

## Stack
- Flask backend
- Vanilla HTML, CSS, and JavaScript frontend
- boto3 for S3 connectivity
- requests for API connectivity tests

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:
```text
http://localhost:8080
```

## Main routes
- `/` — application UI
- `/api/health` — health endpoint
- `/api/upload` — upload and parse log files
- `/api/integrations` — list and save integrations
- `/api/integrations/s3/test` — test S3 connection
- `/api/integrations/api/test` — test API connection

## Notes
- integration records are stored locally in `data/integrations.json`
- uploaded files are parsed in memory and not persisted by default
- this is a strong starter implementation, not a full enterprise ingestion pipeline yet

## Suggested next upgrades
- background jobs for scheduled S3/API polling
- authentication and role-based access
- persistent storage for uploaded logs and parsed events
- charting and saved dashboards
- alert rules and notification channels
- multi-tenant organization support
