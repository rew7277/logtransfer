# ObserveX

Updated SaaS-style observability workspace with:
- separate landing, sign-in, and create-account pages
- multi-file log upload and multiline parsing
- S3 and API connectors
- background ingestion worker queue
- saved dashboards
- invites, email verification, reset password
- SMTP-ready email sending
- PostgreSQL package scaffold in requirements for next deployment step
- wildcard subdomain-ready org slug model

## Environment
- `SECRET_KEY`
- `PUBLIC_BASE_URL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`

## Notes
SQLite is still the default embedded database. `psycopg[binary]` is included as the next step toward PostgreSQL deployment.
