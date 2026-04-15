# 🔍 LogLens — Apple-Grade Log Dashboard

A zero-dependency, single-file log analysis dashboard with Apple-inspired glassmorphism UI. Upload any log file and instantly analyze events by level, Event ID, payload, or free-text search.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Multi-format parsing** | `.log`, `.txt`, `.json`, `.ndjson`, `.csv`, CloudWatch JSON exports |
| **Level detection** | ERROR · SUCCESS · WARN · INFO · CLOUDWATCH · DEBUG |
| **Event ID search** | Filter by `eventId`, `requestId`, `traceId`, `correlationId` |
| **Payload drill-down** | Click any row to see full JSON payload with syntax highlighting |
| **CloudWatch view** | Groups events by `logGroup` / `logStream` |
| **Timeline view** | Chronological event stream |
| **Stats cards** | Live counts + percentages per level |
| **Drag & drop** | Drop files anywhere on the page |
| **Apple UI** | Glassmorphism, animated orbs, smooth transitions |

---

## 🚀 Deploy

### GitHub Pages (instant, free)
```
1. Push all files to a GitHub repo
2. Go to Settings → Pages → Source: main branch / root
3. Your dashboard is live at https://<you>.github.io/<repo>/log-dashboard.html
```

### Railway.app
```bash
# 1. Push to GitHub
git init && git add . && git commit -m "init loglens"
git remote add origin https://github.com/<you>/loglens.git
git push -u origin main

# 2. On Railway:
#    New Project → Deploy from GitHub → select your repo
#    Railway auto-detects railway.toml and runs server.py
#    Set PORT env var if needed (default 8080)
```

### Local
```bash
python server.py
# Open http://localhost:8080
```

---

## 📁 File Structure

```
loglens/
├── log-dashboard.html   # Full dashboard (single file, no dependencies)
├── server.py            # Minimal Python HTTP server for Railway
├── railway.toml         # Railway deployment config
└── README.md
```

---

## 📋 Supported Log Formats

### Plain text / .log
```
2024-01-15 10:32:44 ERROR [payment-service] NullPointerException at line 142
2024-01-15 10:33:01 INFO [api-gateway] GET /health 200 OK 12ms
```

### JSON / NDJSON
```json
{"timestamp":"2024-01-15T10:32:44Z","level":"ERROR","message":"DB timeout","eventId":"EVT-001","source":"db-service"}
```

### AWS CloudWatch Export
```json
{
  "logGroup": "/aws/lambda/loan-processor",
  "logStream": "2024/01/15/[$LATEST]abc123",
  "logEvents": [
    {"timestamp": 1705312364000, "message": "START RequestId: abc123 Version: $LATEST"},
    {"timestamp": 1705312380000, "message": "ERROR Task timed out after 15.00 seconds"}
  ]
}
```

### CSV
```csv
timestamp,level,eventId,message,source
2024-01-15 10:32:44,ERROR,EVT-001,Payment failed,payment-service
```

---

## 🎨 Design

- **Font**: DM Sans + JetBrains Mono
- **Theme**: Dark glassmorphism with animated gradient orbs
- **Accent**: Apple system blue `#2997ff`
- **Animations**: CSS-only, 60fps, hardware-accelerated

---

Built for MuleSoft · FastAPI · Kite Connect · CloudWatch log analysis
