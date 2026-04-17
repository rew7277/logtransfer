# ObserveX Enterprise Workspace

A generic log observability starter for all systems.

## What is included
- shared workspace login
- self-service organization creation
- organization slug for future `company.vewit.com`
- roles: admin, manager, developer, tester
- admin-created user accounts inside an organization
- optional admin-only mode
- multiline-safe parser for Mule-style logs
- upload + searchable log explorer
- full log detail modal
- AWS S3 test/save
- API test/save
- ingestion jobs with run-now
- alert rules
- audit trail
- theme modes: black, white, green
- SQLite persistence
- APScheduler hook for basic scheduled polling

## Demo login
- Email: `admin@vewit.local`
- Password: `admin123`

## Run locally
```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8080`

## Notes
- This is a strong starter, not a full production platform yet.
- For production, move to PostgreSQL, background workers, stronger RBAC, and real subdomain routing.
