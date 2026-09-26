# Recon Monitor — Architecture (TASK-001/069)

> Generated from repository audit. Describes ACTUAL implementation.

## 1. Current architecture

Django 5 + DRF + Channels (WebSocket) + Celery (eager by default, Redis in prod).
SQLite dev / Postgres prod. Single-tenant: all users see all targets; target
context (`?target=` / session) is the isolation boundary enforced server-side.

```
Browser (?target=) -> views (target-scoped) -> models (target FK)
                    -> /api/ (target filter, auth) 
                    -> /ws/targets/<id>/ (isolated groups)
Celery tasks (target_id, run_id) -> tool adapters -> ingest (normalize/compare)
  -> Event (fingerprint) -> WS broadcast (target group) + dependents + Discord
```

## 2. Data flow

`Target -> subdomain enum (subfinder/amass/findomain/assetfinder/crt.sh)
 -> wildcard guard -> DNS (dnsx/socket) -> IPs -> ports (naabu/socket)
 -> HTTP (httpx/urllib) -> URLs (gau/waybackurls/waymore/katana)
 -> JS download/hash/diff -> analyzers (jsluice/linkfinder/secretfinder/semgrep/retire)
 -> tech/version -> CVE correlation -> targeted nuclei -> findings`

## 3. Task flow

`baseline_target` chains stages in order, each failure-isolated (PARTIAL not FAILED).
Per-asset fan-out: `handle_event_dependents(event_id)` dispatches exactly one
downstream task (never whole-target rescans), coalescing duplicate QUEUED/RUNNING jobs.
Every task carries `target_id`; pipeline stages also carry `run_id` (= ScanRun id
when created via helpers in `apps/jobs/tasks.py`).

## 4. Target ownership

Every recon model has direct `target FK`, except:
- `JavaScriptVersion` -> via `js.target` (validated in clean)
- `JavaScriptFinding.target` nullable for backfill, auto-set from `js.target`, mismatch rejected
- `Alert.target` denormalized from `event.target`
- `AuditLog.target` nullable (system actions)
- Global reference only: `CVESyncState`, `DiscordBatch`, tool definitions.

Enforcement layers: model `clean()` + `apps/core/target_scoping.py`
(`TargetScopedQuerySet/Manager`, `TargetAssetService/EventService/ReportService`)
+ view `?target=` mismatch denial (403) + API target filter + WS group isolation.

## 5. Event flow

`emit_event(type, target, asset, old_state, new_state, ...)`:
fingerprint = `sha256(type|target|asset|extra|old_hash|new_hash)` (TASK-032) —
same state dedups, distinct transitions create distinct events.
Stores `old_state/new_state/scan_run/correlation_id/parent_event/priority+reasons`.
Broadcast: target events ONLY to `target_<id>` group (TASK-043).
Discord: HIGH/CRITICAL immediate, INFO/LOW digested, baseline-suppressed, secrets redacted.

## 6. UI flow

`base.html` persistent target picker -> all nav links preserve `?target=`.
`dashboard` scopes counts/events/jobs when target selected (TASK-040).
`live.js` connects to `/ws/targets/<id>/` when scoped (client + server isolation).
Tables: search/filter/sort/pagination (TASK-046). Timeline in changes/events (TASK-047).
Scan health via Jobs detail + ToolExecution; Tools & System matrix (TASK-048/049).

## 7. Tool execution flow

`services/tool_adapters/base.py`: `BaseAdapter.run()` returns
`COMPLETED/PARTIAL/FAILED/SKIPPED` (SKIPPED when binary missing — never crash).
Commands redacted (`redact_command`). Per-tool `ToolExecution` rows when ScanRun
helpers used. Coverage = executed/failed/degraded/skipped per scan (TASK-073).

## 8. Known gaps (honest)

- `ScanRun/ToolExecution/AssetObservation` models exist; not every legacy task
  creates rows yet (baseline + new code paths do; older per-asset tasks still use ScanJob).
- No per-user target ACL (single-tenant by design).
- Nuclei validation is targeted per affected URL (TASK-030) but template-to-CVE
  mapping is heuristic (severity-based), not full TTP mapping.
- CVE matching uses local rules + cvelistV5 snapshot; not live NVD API.
- `Asset` generic table coexists with typed tables (legacy compat).
