# Deployment

## Quick-start (local dev, SQLite + eager tasks)

```bash
./scripts/setup.sh    # creates .venv, SQLite DB, random admin password (shown once)
./scripts/start.sh    # http://localhost:8000/dashboard/
```

No environment editing needed. Celery runs eager (in-process) — no Redis required.
Missing recon tools are skipped gracefully (MISSING in Settings → Tools & System).

## Production checklist (Docker Compose + Postgres + Redis)

> Backend note: the app boots `config.settings.development` by default
> (`manage.py`, `config/asgi.py`). Production MUST set
> `DJANGO_SETTINGS_MODULE=config.settings.production` (compose below does this). The production
> module **hard-fails** on insecure config instead of booting (Tasks 15/16).

1. **Settings module:** `DJANGO_SETTINGS_MODULE=config.settings.production`
2. **Secret:** `DJANGO_SECRET_KEY=<output of: python -c "import secrets; print(secrets.token_urlsafe(50))">`
   Required at build AND runtime (`migrate`, `collectstatic`, `daphne`, workers all
   need the SAME value, or sessions/CSRF break across processes).
3. **Hosts:** `ALLOWED_HOSTS=app.example.com` (never `*` in production — refused).
4. **Database:** `POSTGRES_DB / POSTGRES_USER / POSTGRES_PASSWORD / DATABASE_URL=postgres://...`
5. **Queue/realtime:** `REDIS_URL=redis://redis:6379/0`, `CELERY_TASK_ALWAYS_EAGER=False`,
   `USE_REDIS_CHANNELS=True`
6. **CSRF behind proxy:** `CSRF_TRUSTED_ORIGINS=https://app.example.com`
7. **TLS termination:** put a reverse proxy (nginx/Caddy) with TLS in front of
   `daphne -p 8000`; only then consider `SECURE_SSL_REDIRECT=True` (it is opt-in
   because enabling it without a TLS proxy lockouts out plain-HTTP health checks).

Worked example:

```bash
cd docker
cp .env.docker.example .env   # fill in REAL secrets (no working defaults)
docker compose up -d --build
docker compose logs -f web
```

Without a filled `.env`, `docker compose config` fails fast naming the missing
variable — it never boots `DEBUG=True` / `POSTGRES_PASSWORD=recon` (Task 26).
For a throwaway local loop see `docker-compose.override.yml.example`.

## Authorizing targets for scanning (Task 29)

New targets default to `PENDING` and are **not scannable**. To authorize:
Targets → edit → set Authorized **with** the confirmation checkbox (or an
authorization expiry date) → save (audited). Expiry auto-pauses scanning.

## WebSocket auth (Tasks 18/19)

Realtime sockets require a logged-in session (`AuthMiddlewareStack` in
`config/asgi.py`); anonymous sockets are closed immediately. Behind a
subdomain reverse-proxy, keep `SESSION_COOKIE_SAMESITE` default (Lax) and list
the public origin in `CSRF_TRUSTED_ORIGINS`.
