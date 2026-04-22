# ObserveX — Log Management Platform

## Fixes in this build
- **Modal close**: clicking backdrop or ✕ now properly closes the log detail popup
- **Search clear**: clearing the search bar auto-refreshes results (no manual Refresh needed)
- **Level badge display**: all level badges (Error/Warn/Info/Success/Debug) now render with correct colors in both dark and light themes
- **Binary file rejection**: uploading ZIP/PDF/PNG/etc. now returns a clear error instead of garbled log records — only `.log`, `.txt`, `.json`, `.csv`, `.ndjson`, `.jsonl` are accepted
- **Time filter**: relative presets (Last 15 min / 30 min / 1h / 6h / 24h / 7 days) + **custom date-time range picker** (From → To)
- **Invite email status**: invite creation now reports whether email was actually sent; if SMTP is not configured, a warning with the shareable link is shown

## Deploy
Use Railway with the included `railway.toml`.

## Required environment variables
| Variable | Description |
|---|---|
| `SECRET_KEY` | Random secret for session signing |
| `PUBLIC_BASE_URL` | Full URL e.g. `https://yourapp.up.railway.app` |

## Email / SMTP (required for invite emails & verification)
Without these, invite emails are **silently not sent** — the invite link is still shown in the UI and can be copied and shared manually.

| Variable | Example |
|---|---|
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |
| `SMTP_USER` | `you@gmail.com` |
| `SMTP_PASSWORD` | Gmail App Password (not your login password) |
| `SMTP_FROM` | `noreply@yourdomain.com` |

### Gmail setup (quickest option)
1. Enable 2FA on your Google account
2. Go to **Google Account → Security → App Passwords**
3. Create an app password for "Mail"
4. Use that 16-char password as `SMTP_PASSWORD`

### Railway env setup
In your Railway project → **Variables** tab, add all the above keys.
