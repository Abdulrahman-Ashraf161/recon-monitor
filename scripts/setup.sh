#!/usr/bin/env bash
# One-command setup: you only provide YOUR private things (Discord webhook,
# subfinder API keys). Everything else (secret key, database) is automatic.
set -e
cd "$(dirname "$0")/.."

echo "== Recon Monitor setup =="

# 1. Python env
if [ ! -d .venv ]; then
  echo "--> creating .venv"
  python3 -m venv .venv
fi
.venv/bin/pip install --quiet -r requirements.txt
echo "--> dependencies installed"

# 2. .env (only private things; secrets/database auto-defaulted)
if [ ! -f .env ]; then
  cp .env.example .env
  echo "--> created .env"
fi
if grep -q "^DISCORD_WEBHOOK_URL=$" .env 2>/dev/null; then
  read -rp "Discord webhook URL (Enter to skip): " HOOK || HOOK=""
  if [ -n "$HOOK" ]; then
    # escape for sed
    ESCAPED=$(printf '%s' "$HOOK" | sed 's/[&|]/\\&/g')
    sed -i "s|^DISCORD_WEBHOOK_URL=$|DISCORD_WEBHOOK_URL=${ESCAPED}|" .env
    sed -i "s|^DISCORD_ENABLED=False|DISCORD_ENABLED=True|" .env
    echo "--> Discord enabled"
  fi
fi

# 3. Subfinder API keys (optional)
SCONF="$HOME/.config/subfinder/provider-config.yaml"
if [ ! -f "$SCONF" ]; then
  echo "--> tip: add subfinder API keys later with:"
  echo "    subfinder -pc $SCONF"
  echo "    (or edit the file directly; keys: shodan, censys, virustotal, github, chaos, urlscan...)"
fi

# 4. Database (SQLite, automatic)
.venv/bin/python manage.py migrate --noinput
echo "--> database ready"

# 5. Admin user (only if none exists) — Task 27: random password by default,
# never the static admin/admin. The account must change it on first login.
NUSERS=$(echo "from django.contrib.auth.models import User; print(User.objects.count())" | .venv/bin/python manage.py shell 2>/dev/null | tail -n 1)
if [ "$NUSERS" = "0" ]; then
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASS="$ADMIN_PASSWORD"
  else
    ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(16))')"
  fi
  export SETUP_ADMIN_PASS="$ADMIN_PASS"
  .venv/bin/python manage.py createsuperuser --noinput --username admin --email admin@localhost >/dev/null 2>&1 || true
  echo "
import os
from django.contrib.auth.models import User
u = User.objects.get(username='admin')
u.set_password(os.environ['SETUP_ADMIN_PASS']); u.save()
u.profile.must_change_password = True; u.profile.save(update_fields=['must_change_password'])
" | .venv/bin/python manage.py shell >/dev/null 2>&1
  unset SETUP_ADMIN_PASS
  echo "=================================================="
  echo "  Login: admin"
  echo "  Password: $ADMIN_PASS"
  echo "  You will be asked to change it on first login."
  echo "  Custom password: ADMIN_PASSWORD=secret ./scripts/setup.sh"
  echo "=================================================="
fi

echo ""
echo "Done. Start the app with:"
echo "  ./scripts/start.sh"
