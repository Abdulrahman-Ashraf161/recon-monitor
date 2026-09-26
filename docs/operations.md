# Operations

- Onboard target: Add Target → configure scope rules → baseline runs automatically.
- Revoked auth: set status PAUSED (kill-switch) or let authorization_expires_at auto-pause.
- Stuck job: Jobs → Retry/Cancel. Resume: re-run stage; completed state is preserved.
- CVE freshness: Monitoring page shows cvelistV5 last_synced; `sync_cve_database` runs every 6h.
- Tool missing: Settings → System shows MISSING; pipeline skips that source gracefully.

## Dependency upgrades (Task 28)

- Runtime installs use `requirements.lock.txt` (exact pins, Docker included).
- Regenerate monthly (or on HIGH/CRITICAL `pip-audit` findings):
  `pip-compile requirements.txt --generate-hashes -o requirements.lock.txt`,
  then `python manage.py test` before committing the new lock.
- CI (`security.yml`, weekly + on push) runs `pip-audit -r requirements.lock.txt`
  and fails on HIGH/CRITICAL. Triage exceptions explicitly — never silently skip.
