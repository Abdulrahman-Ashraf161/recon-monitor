# Recon Monitor — Continuous Reconnaissance & Attack-Surface Monitoring

> **Authorized security testing only.** Every active operation passes through scope
> validation. GitHub/GitLab repository discovery is intentionally NOT part of the pipeline.

A Django web app that continuously discovers and monitors an organization's external
attack surface: subdomains → DNS → IPs → ports → HTTP services → URLs/APIs → JavaScript
analysis → technologies → CVE correlation → nuclei validation — with persistent state,
change detection, real-time dashboard (WebSockets), and immediate Discord alerts.

---

## 1. Run it in 2 commands (recommended)

You only provide **your private things** (Discord webhook, subfinder API keys).
Secret key, database, and task queue all have working defaults.

```bash
git clone https://github.com/Abdulrahman-Ashraf161/recon-monitor.git
cd recon-monitor
./scripts/setup.sh    # asks only for your Discord webhook (optional, Enter to skip)
./scripts/start.sh    # open http://localhost:8000/dashboard/
```

`setup.sh` creates the Python env, installs dependencies, prepares the SQLite database,
and creates the `admin` login. No manual database or secret-key steps.

### Default credentials

- **Username:** `admin`
- **Password:** `admin` (static default — change it right after first login!)
- Custom password at setup: `ADMIN_PASSWORD=secret ./scripts/setup.sh`
- If locked out, reset: `.venv/bin/python manage.py changepassword admin`

### How to change the password

- Via UI (logged in): **Admin** (`/admin/`) → Users → `admin` → change password, or
- Via terminal: `.venv/bin/python manage.py changepassword admin`

Expose it to your phone/another machine without opening firewall ports:

```bash
cloudflared tunnel --url http://localhost:8000
# open the printed https://<random>.trycloudflare.com/dashboard/
```

---

## 2. Manual setup (if you prefer)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # only fill DISCORD_WEBHOOK_URL if you want alerts
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8000
```

Requirements: Python 3.12+. Celery runs **eager** by default, so scans execute
in-process — no Redis needed. Missing recon tools are skipped gracefully (shown as
MISSING in Settings → Tools & System, pipeline never crashes because of them).

---

## 3. Production (Docker Compose)

```bash
cd docker && docker compose up --build
```

Services: `web` (Daphne) + `worker` (Celery) + `beat` (schedules) + Postgres + Redis.
Set in environment: `DJANGO_SECRET_KEY`, `DATABASE_URL`
(postgres://recon:recon@db:5432/recon), `REDIS_URL`, `CELERY_TASK_ALWAYS_EAGER=False`.
See [`docs/deployment.md`](docs/deployment.md).

---

## 4. Keys & tokens (all optional except in production)

| Key / token | Where | Required? | Effect |
|---|---|---|---|
| `DISCORD_WEBHOOK_URL` (+ `DISCORD_ENABLED=True`) | `.env` | No | Immediate Discord alerts (HIGH/CRITICAL instant, INFO/LOW digested, secrets redacted) |
| `DISCORD_MIN_SEVERITY` | `.env` | No | Minimum severity sent (`INFO`/`LOW`/`MEDIUM`/`HIGH`) |
| Subfinder provider keys | `~/.config/subfinder/provider-config.yaml` | No | 40+ passive sources (shodan, censys, virustotal, github, chaos, urlscan…). Works without keys via free sources |
| Nuclei templates | run `nuclei -update-templates` once | Recommended | Template catalog for validation |
| `DJANGO_SECRET_KEY` | `.env` | Prod only | Auto-generated otherwise (sessions reset on restart) |
| `DATABASE_URL` / `REDIS_URL` | env | Prod only | Postgres + Celery/Channels backend (dev: SQLite + eager) |

Example `provider-config.yaml` (fill only what you have):

```yaml
shodan: [<key>]
censys: [<id:secret>]
virustotal: [<key>]
github: [<token>]
chaos: [<key>]
urlscan: [<key>]
```

> Never commit `.env`, databases, `data/exports/`, or key files — all git-ignored.

---

## 5. Recon tools (optional, all auto-detected)

Health anytime: **Settings → Tools & System**, or `bash scripts/setup_tools.sh`.

- Go: `subfinder amass findomain assetfinder dnsx puredns naabu httpx nuclei katana
  gau waybackurls ffuf gobuster jsluice` — `go install <module>@latest`
  (findomain: release binary)
- Python: `pip install waymore dirsearch knock-subdomains semgrep`
- JS: clone LinkFinder + SecretFinder, `npm i -g retire`

---

## 6. First use

1. **Targets → Add Target** (root domain, e.g. `example.com`). `Scan config` is optional
   JSON like `{"ports": "80,443,8080,8443"}` — leave `{}` for defaults.
2. Baseline starts automatically — watch **Jobs** and **Live Events**. First run sends
   ONE Discord summary, not a flood.
3. After `BASELINE_COMPLETE`, every real change (new subdomain/IP/port/URL/JS/tech/CVE/
   finding) creates a persistent event, triggers only the relevant downstream jobs for
   that asset, updates the dashboard live, and alerts per policy.

Per target you get: overview counts, pipeline stages, **What's New** (1h/6h/24h/7d/since
baseline), history timeline, **Exports** (TXT/JSON/CSV + full snapshot ZIP), jobs, events.

---

## 7. Daily use map

| Page | URL |
|---|---|
| Dashboard (live feed) | `/dashboard/` |
| What's New (all targets) | `/changes/` |
| Targets / detail | `/targets/` → `/targets/<id>/` |
| Subdomains, IPs, Ports, HTTP, URLs, APIs | `/subdomains/`, `/assets/ips/`, `/ports/`, `/http/`, `/urls/`, `/apis/` |
| JavaScript (+ staged analysis) | `/javascript/` → `/javascript/<id>/scan/` |
| Technologies, CVEs, Findings | `/technologies/`, `/cves/`, `/findings/` |
| Jobs, Logs, Workers | `/jobs/`, `/logs/`, `/monitoring/workers/` |
| Alert (Discord) history | `/alerts/` |
| Scope, Tools & System, Audit | `/scope/`, `/settings/system/`, `/audit/` |
| REST API (auth, paginated) | `/api/targets/`, `/api/subdomains/`, … |
| Health | `/health/` (JSON with `Accept: application/json`) |

Key rules: per-target kill-switch (Pause stops only that target), authorization expiry
auto-pauses, scope edits emit `SCOPE_CHANGED` + audit entries, stalled jobs raise
`JOB_STALLED`, roles are Admin/Operator/Viewer.

---

## 8. How it works

```text
Authorized root domain → scope check → passive + active subdomain enum
→ wildcard guard → DNS → ports → HTTP → URLs/APIs → JS download/hash/diff
→ staged analyzers (jsluice/linkfinder/secretfinder/semgrep/retire.js)
→ tech/version → CVE correlation → targeted nuclei
→ state compare → persistent event → WebSocket + dependent jobs + Discord
```

Discovery is periodic, alerting is immediate. First scan builds a silent baseline;
after that, only genuine changes notify. Duplicates never re-alert (fingerprint dedup).

## 9. Docs

- Setup & keys: [`docs/setup.md`](docs/setup.md) · Architecture: [`docs/architecture.md`](docs/architecture.md)
- Database: [`docs/database.md`](docs/database.md) · Deployment: [`docs/deployment.md`](docs/deployment.md)
- Alerting: [`docs/alerting.md`](docs/alerting.md) · Operations: [`docs/operations.md`](docs/operations.md)
