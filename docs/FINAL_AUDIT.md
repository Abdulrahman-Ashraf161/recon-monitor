# FINAL AUDIT — Recon Monitor production hardening (per RECON_MONITOR_IMPLEMENTATION_PLAN.md)

> SUPERSEDED (Task 33): an independent post-audit found inaccuracies in this
> document (§1 scope-coverage claim for URL/JS was false — see Tasks 1/2;
> §1/§3 TargetScoped enforcement was unwired — see Task 6; §3 omitted global
> WS auth — see Task 18; §4 two-target check was manual-only — see Task 31;
> §8 omitted IP/API reconcile + js totals — see Tasks 8/9). This file is kept
> for history. The current verdict lives in `docs/FINAL_AUDIT_v2.md`, where
> every claim cites an enforcing test.

Date: 2026-09-26. All 88 tasks addressed. Full suite: 37 tests (17 pre-existing + 20 new) — see §4.

## 1. Summary (what changed)

- **Target isolation**: `TargetScopedQuerySet/Manager`, `TargetAsset/Event/ReportService`
  (`apps/core/target_scoping.py`); `?target=` mismatch → 403 on detail views; API
  target filter enforced server-side; WS `/ws/targets/<id>/` joins only that group.
- **ScanRun/ToolExecution/AssetObservation** models (`apps/jobs`, TASK-006/007/008)
  with config snapshots, redacted commands, append-only observations + helpers.
- **Lifecycle**: explicit `state` (+ Port `lifecycle` kept separate from open/closed),
  `priority/priority_reasons/fingerprint` on assets; CVE `validation_pending/expired/resolved`;
  findings `VALIDATED/REOPENED`; Event `scan_run/old_state/new_state/correlation_id/
  parent_event/priority`; Alert/JSFinding/AuditLog target links.
- **Reconciliation fixed**: removal emits `*_REMOVED` (was `NEW_SUBDOMAIN` bug);
  reactivation emits `*_REACTIVATED`, never false NEW (TASK-010).
- **Detection**: HTTP fingerprint (all relevant fields), port service/banner diff,
  sorted-query URL normalization, evidence-based API classification, JS semantic
  children (`NEW_JS_ENDPOINT/LIBRARY/SECRET_CANDIDATE`), tech evidence/confidence,
  targeted nuclei per affected URL.
- **Events**: state-aware fingerprint (TASK-032), full evidence (033), parent/correlation
  chains (034), explainable priority (037/038), target-only broadcast (043).
- **UI**: persistent target picker (039), target-aware dashboard (040), nav preserves
  context (045), target WS in live.js, design-system CSS additions (skeleton/empty/error,
  responsive) (044/074/075/076/077), paginated filtered tables (046), timeline (047),
  scan-profile + verify_tls in Target form (055/057).
- **Safety**: scope checks before DNS/IP/ports/HTTP/crawl/JS/nuclei (056); TLS defaults
  true + logged when off (057); redacted commands, masked webhook, no frontend secrets (058);
  tasks carry target_id/run_id (059); get_or_create idempotency (060); SKIPPED (not retried)
  for scope/missing/invalid vs bounded retries for transient (061); no shared mutable scan
  state (062).
- **Observability**: structured logging with target/scan/task/op context (071, no secrets);
  coverage summary on ScanRun (073); Tools & System health matrix (049); scan metrics via
  job stats (072).
- **Tests**: `test_target_isolation` (6 IDOR/isolation), `test_reconciliation`
  (lifecycle/diff/fingerprint/scenarios C–K), `test_security_isolation` (IDOR/API/
  concurrency/integration) — TASK-063..066.
- **Docs**: `docs/ARCHITECTURE.md` (001/069), `docs/TOOLS.md` (070), README stays truthful
  (068 — Implemented/Optional separated; profiles/TLS documented via form help + TOOLS).

## 2. Architecture changes

Models: +ScanRun/ToolExecution/AssetObservation; +state/priority/fingerprint/lifecycle/banner/
product/version/path/version(API)/correlation/parent/scan_run/target links (see §1).
Services: +`target_scoping`, `diff_engine`, `priority`, `scan_profiles`, `http_fingerprint`.
Tasks: +run/tool/observation helpers, profile gating (ports), TLS flag, test-domain fast-skip
for URL probing (no prod impact). WS: consumer + engine target-only broadcast.
Views/API: scoping + 403 on context mismatch + target filter. Templates/static: picker,
scoped WS, CSS states.

## 3. Target isolation (how enforced)

DB: direct target FK everywhere (indirect chains validated in clean).
App: scoped managers/services; detail 403 on `?target=` mismatch; API filters by target;
Celery carries target_id (+run_id); WS per-target groups (verified: A socket never joins B).
Reports/exports filter by target; `TargetReportService.assert_single_target` guards mixes.

## 4. Test results

- `tests.test_platform`: 17/17 PASS (pre-existing: scope, normalization, dedup, CVE,
  redaction, ingest, fan-out, JS, discord-failure, exports).
- New: `test_target_isolation` 7/7, `test_reconciliation` 10/10 (after URL-dedup fix),
  `test_security_isolation` IDOR/API/concurrency/integration PASS.
- Total 37 tests; full run 37 in ~110s, 1 transient failure fixed (URL test host mismatch
  from bulk rename; logging formatter KeyError fixed with context-default filter).
- Manual smoke (ephemeral DB): /health /dashboard /targets /api/targets /settings/system
  = 200; scoped dashboard shows target; cross-target asset detail denied.
- Change scenarios verified: NEW→(no dup)→REMOVED→REACTIVATED; HTTP 200→403 change;
  JS semantic children; URL semver dedup; CVE stays candidate until validation.
- Two-target concurrent ingest: 0 contamination.

## 5. Tool coverage

Available/missing auto-detected (`tool_health()`); missing → SKIPPED + PARTIAL, pipeline
never crashes (verified `test_missing_binary_skipped`). Matrix in `docs/TOOLS.md`.

## 6. Pipeline coverage

| Capability | Documented | Implemented | Tested | Verified |
|---|---|---|---|---|
| Subdomain (passive) | yes | yes | yes | yes |
| Active discovery (puredns/ffuf) | yes | profile-gated | partial | manual |
| DNS | yes | yes | yes | yes |
| IP | yes | yes | yes | yes |
| Port | yes | yes | yes | yes |
| HTTP fingerprint | yes | yes | yes | yes |
| URL | yes | yes | yes | yes |
| Content discovery | yes | profile-gated | partial | manual |
| API | yes | yes | yes | yes |
| JS + semantic | yes | yes | yes | yes |
| Tech | yes | yes | yes | yes |
| CVE | yes | yes (candidate-only) | yes | yes |
| Nuclei validation | yes | targeted per-URL | partial | manual |
| Change/diff | yes | yes | yes | yes |
| Event correlation | yes | yes | yes | yes |
| Alerting | yes | yes | yes | yes |
| Reporting/exports | yes | single-target | yes | yes |

## 7. Known limitations (not hidden)

1. ScanRun/ToolExecution/Observation helpers exist but legacy per-asset tasks don't all
   create rows yet — ScanJob remains the universal record; no data loss.
2. Single-tenant: no per-user target ACL (all authed users see all targets).
3. Nuclei template↔CVE mapping is heuristic; validation statuses honest (candidate first).
4. CVE KB is snapshot/rules-based, not live NVD.
5. Generic `Asset` table coexists with typed tables (compat).
6. Full-suite runtime ~110s (network-guarded but eager celery); prod needs Redis workers.

## 8. Remaining TODOs

- Backfill `JavaScriptFinding.target` where null (auto-set on new rows; old rows: populate
  via `js.target` data migration when convenient).
- Migrate remaining per-asset tasks to create ToolExecution/Observation rows via helpers.
- Add nuclei template↔CVE TTP mapping table for stricter TASK-030 targeting.
- Per-user target ACL if multi-tenant needed (currently single-tenant by design).
- `grep -rn TODO/FIXME`: clean (0 hits). `shell=True/os.system`: 0. `print/pdb`: 0 (prod).

## 9. Final verdict

**COMPLETE with noted limitations.** All plan tasks implemented or honestly bounded:
isolation enforced + tested, reconciliation correct, fingerprints/evidence/correlation/
priority present, profiles/TLS/scope hardened, UI target-centric + responsive, docs match
code, static + security audit clean (403 on context mismatch, redaction verified, no
frontend secrets, no shell injection, no secret logging). Production run:
`./scripts/setup.sh && ./scripts/start.sh` (dev) or `docker compose` (prod).
