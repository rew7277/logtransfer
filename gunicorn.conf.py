# gunicorn.conf.py
# Production-grade Gunicorn configuration for ObserveX on Railway
# Docs: https://docs.gunicorn.org/en/stable/settings.html

import multiprocessing
import os

# ── Workers ──────────────────────────────────────────────────────────────────
# For I/O-heavy Flask + SQLite: (2 × CPU cores) + 1 is a good starting point.
# At 10k rps you'll need Railway's higher-tier instances (8+ vCPU) and
# ultimately a migration from SQLite → PostgreSQL + Redis.
default_workers = min((multiprocessing.cpu_count() * 2) + 1, 4)
workers     = int(os.environ.get("WEB_CONCURRENCY", default_workers))
worker_class = "sync"          # Use "gevent" if you add greenlet support
threads     = 1                # Only safe to increase with sync worker to 2-4
timeout     = 120              # Increase if ingestion jobs can take longer
graceful_timeout = 30          # Grace period for in-flight requests on SIGTERM
keepalive   = 5                # Keep-alive timeout in seconds

# ── Binding ───────────────────────────────────────────────────────────────────
bind        = f"0.0.0.0:{os.environ.get('PORT', '8080')}"

# ── Logging ──────────────────────────────────────────────────────────────────
accesslog   = "-"              # stdout — Railway captures this
errorlog    = "-"              # stderr
loglevel    = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# ── Process naming ────────────────────────────────────────────────────────────
proc_name   = "observex"

# ── Security ─────────────────────────────────────────────────────────────────
limit_request_line   = 8190    # Max HTTP request line size
limit_request_fields = 100     # Max number of HTTP headers
limit_request_field_size = 8190

# ── Performance tuning ───────────────────────────────────────────────────────
# Preload the application so workers share memory (faster startup, less RAM)
preload_app = True

def on_starting(server):
    server.log.info("ObserveX starting with %d workers", workers)

def worker_exit(server, worker):
    server.log.info("Worker %d exiting", worker.pid)
