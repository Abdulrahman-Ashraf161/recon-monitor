# Recon Monitor — Architecture (TASK-001/069)

> Generated from repository audit. Describes ACTUAL implementation.

## 1. Current architecture

Django 5 + DRF + Channels (WebSocket) + Celery (eager by default, Redis in prod).
SQLite dev / Postgres prod.

**Multi-tenant with enforced membership (P0-002/P0-003/P0-008).** A *global role*
(`VIEWER`/`OPERATOR`/`ADMIN`/`OWNER`) is **not** an authorization decision: every
read or action resolves a `TargetMembership` row for the specific target through
`apps.core.authorization` (`get_authorized_target`, `user_can_access_target`,
`require_capability`, `scope_queryset_for_user`, `authorized_targets`). A viewer
with no membership sees nothing; an administrator keeps portfolio visibility
unless a target is explicitly validated.

```
Browser
  -> views           : @require_viewer + get_authorized_target/require_capability
  -> /api/           : AuthViewSet.get_queryset -> membership-scoped querysets
  -> /ws/targets/<id>/: membership checked BEFORE group_add, re-checked per message
Celery tasks (target_id, scan_run_id) -> tool adapters -> ingest (normalize/compare)
  -> AssetObservation (run/job/tool_execution) -> Event (fingerprint) -> dependents
```

### Execution model (P0-009)

```
User
 -> TargetMembership        (who may read/operate/manage a target)
    -> Target               (authorization window, scan profile, TLS policy, kill switch)
       -> ScanRun           (the canonical execution root; at most one live run
                              per (target, scan_type), enforced by a partial
                              unique index)
          -> ScanJob        (one stage; heartbeats, kill switch, kill-switch status)
          -> ToolExecution  (one tool invocation: redacted command, exit code,
                              duration, fallback flag, coverage, stdout/stderr refs)
          -> AssetObservation (one asset, with its run/job/tool_execution links)
          -> Event          (dedup by unique fingerprint; parent_event +
                              correlation_id link children to their change)
             -> Alert
```

Liveness is the `heartbeat_at` column refreshed cooperatively during long work
(P1-006); `detect_stalled_jobs` uses it as the primary signal.

## 2. Data flow

`Target -> subdomain enum (subfinder/amass/findomain/assetfinder/crt.sh)
 -> wildcard guard -> DNS (dnsx/socket) -> IPs -> ports (naabu/socket)
 -> HTTP (httpx/urllib) -> URLs (gau/waybackurls/waymore/katana)
 -> JS download/hash/diff -> analyzers (jsluice/linkfinder/secretfinder/semgrep/retire)
 -> tech/version -> CVE correlation -> targeted nuclei -> findings`

## 3. Task flow

`baseline_target` chains stages in order under **one** `ScanRun`; each stage is
failure-isolated and the final status is an explicit aggregation
(`_aggregate_baseline`): COMPLETE only when every required stage completed, PARTIAL
for reduced coverage, FAILED for a failed required stage. Manual scans go through
the same orchestration via `manual_scan` (P2-006).

Per-asset fan-out: `handle_event_dependents(event_id)` dispatches exactly one
downstream task (never whole-target rescans), coalescing duplicate QUEUED/RUNNING
jobs. Every task carries `target_id` and the canonical `scan_run_id`; there is no
free-form run id (the legacy `run_id_legacy` column is audit-only).

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
Commands redacted (`redact_command`) and tool output redacted
(`services/redaction.py`) before it is written under `data/raw/`; the row keeps a
reference, not the bytes (P1-002). A missing tool or a capped fallback is recorded
with `fallback_used=True` and an explicit `coverage` record
(`configured`/`attempted`/`reduced`/`coverage_ratio`), and degrades the stage to
PARTIAL — a limited fallback is never reported as equivalent coverage (P1-011/P1-012).
A lost evidence row is logged, counted, surfaced as a `JOB_FAILED` event, and
degrades the stage rather than being swallowed (P1-003/P1-004).

## 8. Known gaps (honest)

- Per-target ACL is enforced in code (`TargetMembership` + `apps.core.authorization`)
  and in the database for uniqueness, not yet by a per-row policy engine.
- Nuclei validation is targeted per affected URL (TASK-030) but template-to-CVE
  mapping is heuristic (severity-based), not full TTP mapping.
- CVE matching uses local rules + cvelistV5 snapshot; not live NVD API.
- `Asset` generic table coexists with typed tables (legacy compat).


## 9. Target authorization and execution lifecycle (P0/P1/P2)

* **Authorization** — a `TargetMembership(user, target, role)` grants
  VIEWER/OPERATOR/OWNER. Every target-scoped read filters by membership; every
  target-scoped action requires the matching capability. The target picker, the
  dashboard overview, the API, the WebSocket, exports, job/log views and the
  reconciliation/export tasks all use the same helpers, so an unpinned page can
  never become a global one.
* **Scannability** — `Target.is_scannable` is the single definition of "may this
  target run work": not archived, ACTIVE, explicitly AUTHORIZED, inside the
  authorization window, and not cancel-requested. Pausing or an authorization
  lapse both stop *new* work and trip the in-flight kill switch.
* **Lifecycle transitions** — `apps/targets/target_lifecycle.py` is the only
  sanctioned way to change status/authorization. It validates the transition,
  halts in-flight work, stamps `archived_at`, emits the matching events and
  records an audit line. Removal is archive-first; a hard delete requires an
  explicit `PURGE` confirmation and returns a manifest of what it destroyed.
* **Reconciliation** — an asset is only marked removed when a *completed* stage
  that would have observed it proves its absence; partial, failed, cancelled,
  profile-skipped and never-run stages withhold the removal and report it
  (`withheld`, `scan_states`) instead of emitting a false removal (P1-010).
