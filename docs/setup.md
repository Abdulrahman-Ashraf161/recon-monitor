# Setup & Run Guide

## 1. Prerequisites

- Python 3.12+ (3.14 works)
- pip + venv
- Optional (production): Docker + Docker Compose, PostgreSQL, Redis
- Optional (richer scans): Go toolchain + recon binaries (see §5)

## 2. Quickstart — one script, only YOUR private things needed

```bash
git clone https://github.com/Abdulrahman-Ashraf161/recon-monitor.git
cd recon-monitor
./scripts/setup.sh     # asks only for your Discord webhook (optional)
./scripts/start.sh     # open http://localhost:8000/dashboard/
```

`setup.sh` creates the Python env, installs dependencies, generates the secret key,
prepares the SQLite database, and creates the `admin` login. No manual database or secret-key steps.

### Default credentials

- **Username:** `admin`
- **Password:** `admin` (static default — change it right after first login!)
- Custom password at setup: `ADMIN_PASSWORD=secret ./scripts/setup.sh`
- Missed/locked out? Reset: `.venv/bin/python manage.py changepassword admin`
- Change anytime: log in → **Admin** (`/admin/`) → Users → `admin`, or the
  `changepassword` command above. Roles: Admin / Operator / Viewer
  (new users default to Viewer; Admins can promote via profiles in `/admin/`).

Manual equivalent (if you prefer):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # only fill DISCORD_WEBHOOK_URL if you want alerts
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

> Dev defaults: SQLite database, Celery runs **eager** (no Redis needed),
> missing recon tools are skipped gracefully.

## 3. Production (Docker Compose)

```bash
cd docker && docker compose up --build
```

Set in environment: `DJANGO_SECRET_KEY`, `DATABASE_URL`
(postgres://recon:recon@db:5432/recon), `REDIS_URL`, `CELERY_TASK_ALWAYS_EAGER=False`.
Web on :8000, plus `worker` and `beat` services.

## 4. Keys & tokens you may need

| Key / token | Where to put it | Required? | What it does |
|---|---|---|---|
| `DJANGO_SECRET_KEY` | `.env` / env | Yes (prod) | Django sessions/crypto. Generate: `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
| `DATABASE_URL` | env | Prod | Postgres. Dev default: `sqlite:///db.sqlite3` |
| `REDIS_URL` | env | Prod | Celery broker + Channels. Dev default: eager/in-memory |
| `DISCORD_WEBHOOK_URL` | env | No | Discord channel webhook for alerts |
| `DISCORD_ENABLED` | env (`True`/`False`) | No | Master switch for Discord delivery |
| `DISCORD_MIN_SEVERITY` | env (`INFO`/`LOW`/`MEDIUM`/`HIGH`) | No | Minimum severity sent to Discord |
| Subfinder provider keys | `~/.config/subfinder/provider-config.yaml` | No | 40+ passive sources (shodan, censys, virustotal, github, chaos, urlscan…) — without keys subfinder still works via free sources |
| Nuclei templates | run `nuclei -update-templates` once | Recommended | Template catalog for validation; without it nuclei finds nothing |

Example `.env` (see `.env.example`):

```bash
DJANGO_SECRET_KEY=<random-50-chars>
DJANGO_DEBUG=False
ALLOWED_HOSTS=recon.example.com
DATABASE_URL=postgres://recon:recon@db:5432/recon
REDIS_URL=redis://redis:6379/0
CELERY_TASK_ALWAYS_EAGER=False
DISCORD_ENABLED=True
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/<id>/<token>
DISCORD_MIN_SEVERITY=LOW
```

Example `provider-config.yaml` (only fill what you have):

```yaml
shodan: [<key>]
censys: [<id:secret>]
virustotal: [<key>]
github: [<token>]
chaos: [<key>]
urlscan: [<key>]
```

> Never commit `.env`, databases, `data/exports/`, or key files. They are git-ignored.

## 5. Recon tools (optional)

Check status anytime: in-app **Settings → Tools & System**, or `bash scripts/setup_tools.sh`.

- Go tools: `subfinder amass findomain assetfinder dnsx puredns naabu httpx nuclei
  katana gau waybackurls ffuf gobuster jsluice` — `go install <module>@latest`
  (findomain: download the release binary)
- Python: `pip install waymore dirsearch knock-subdomains semgrep`
- JS: LinkFinder + SecretFinder (clone repos), `npm i -g retire`
- Then: `nuclei -update-templates`

Missing tools show MISSING and are skipped — the pipeline never crashes because of them.

## 6. First use

1. Log in → **Targets → Add Target** (root domain, e.g. `example.com`).
   `scan config` is optional JSON, e.g. `{"ports": "80,443,8080,8443"}` — leave `{}` for defaults.
2. Baseline starts automatically: watch **Jobs** and **Live Events**.
3. First run sends ONE baseline summary to Discord (if enabled), not a flood.
4. After `BASELINE_COMPLETE`, every real change alerts immediately.
5. Explore per target: overview counts, pipeline stages, What's New, exports.

## 7. Daily use

- **Dashboard**: totals, live event feed, job status
- **What's New** (`/changes/`): every change across targets, with time filters
- **Exports** (per target): TXT/JSON/CSV + full snapshot ZIP
- **Alerts**: Discord delivery history with SENT/FAILED/BATCHED/SUPPRESSED states
- **Pause a target** (kill-switch): target page → Pause. Authorization expiry auto-pauses.
