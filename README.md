# ObserveX v10 cleanup

Includes:
- cleaned landing page and pricing page
- visible pricing navigation
- upload logs restored prominently in workspace overview and explorer
- separate login and create-account pages
- background worker, invites, email verification, password reset
- Gunicorn runtime for Railway
- subdomain-ready org slug model

## Deploy
Use Railway with the included `railway.toml`.

## Required env
- `SECRET_KEY`
- `PUBLIC_BASE_URL`

## Optional env
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`
