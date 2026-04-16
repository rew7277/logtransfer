# ObserveX Enterprise Workspace

A generic log observability starter platform for all systems.

## What's included
- Shared workspace login
- Admin-created user accounts
- Admin-only workspace mode toggle
- Organization branding and slug for future subdomain routing like `company.vewit.com`
- Multiline-safe log parsing for Mule-style and generic logs
- Full log detail viewer
- Upload logs into SQLite-backed storage
- AWS S3 connector test and save
- API connector test and save
- Ingestion jobs with manual **Run now** and optional APScheduler polling
- Alert rules
- Audit trail
- Simple charts and dashboard cards

## Demo login
- Email: `admin@vewit.local`
- Password: `admin123`

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

App default URL:
- `http://localhost:8080`

## Notes
- This is a strong starter, not a complete production SaaS yet.
- SQLite is included for easy local testing. Move to PostgreSQL for real deployment.
- APScheduler is included for simple scheduled job execution in a single-process environment.
- The parser redacts some obvious sensitive patterns, but production masking should be stronger and more configurable.

## Suggested next steps
- PostgreSQL
- Real background workers (Celery / RQ)
- Per-user permissions screens
- Alert delivery integrations
- Tenant subdomain routing and reverse proxy config
- Search indexing and richer analytics
