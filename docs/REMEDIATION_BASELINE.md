# Remediation Baseline — P0-001

Recorded **before** any code modification.

| Field | Value |
|---|---|
| Commit | `5a8e72bdc3811f03955aec6e8ecc48ebdfd17766` |
| Branch | `main` |
| `git status` | **dirty by design** — 96 entries (42 modified, 54 new) are the remediation work |
| Python | 3.12.3 |
| Django (venv) | 5.2.17 |
| Django (lockfile) | 5.2.17 — **RESOLVED**, matches the installed venv (the earlier "6.1.1" reading was a stale claim) |
| Django checks | `System check identified no issues (0 silenced)` |
| Migrations drift | **RESOLVED** — `assets.Asset.asset_type` captured in migration `0007`; `makemigrations --check` reports `No changes detected` |
| `manage.py test` | **93 → 560 tests, 560 OK, 0 skipped** |
| Docker daemon | reachable (`docker info` OK, server 29.1.3) |
| Docker image | built and run; full 5-service production stack verified live |
| `docker compose` plugin | **absent** in WSL (broken symlink to a Docker Desktop path). Worked around by running the identical stack with `docker run` against a user-defined network — see `docs/FINAL_REPORT.md` §7 |

## Pre-existing failures (must not be attributed to remediation work)

1. **`makemigrations --check` fails** — pending migration `0007_alter_asset_asset_type`
   (model/migration drift on `apps/assets/models.py`).
2. **`ruff check .`** — 302 errors (37 auto-fixable).
3. **`flake8`** — numerous `E501` line-too-long (default 79-col limit, repo has no
   `setup.cfg`/`.flake8` config).
4. **`black --check .`** — 84 files would be reformatted.
5. **`mypy .`** — 361 errors, dominated by missing third-party stubs
   (`rest_framework`, `celery`, `channels.layers`). Two real findings:
   - `apps/jobs/tasks.py:540` — `Assignment to variable "e" outside except: block`
   - `apps/jobs/tasks.py:941` — same pattern
6. **No `pytest`/`ruff`/`flake8`/`black`/`mypy` config file** in repo, and none of
   these tools were declared in `requirements*.txt` or the CI workflows.

## Tooling installed for this remediation

`pytest pytest-django pytest-cov ruff flake8 black mypy django-stubs` installed
into `.venv`. None of these were previously declared as dev dependencies.

## Baseline note

`data/`, `db.sqlite3` and `.env` are untracked/ignored — the dev database is
pre-populated but not part of the source of truth.

---

# Progress log

## P0-002 / P0-003 / P0-009 / P1-005 / P1-006 / P2-006 (execution + isolation)

### Fixed: legacy `ScanJob.run_id` was silently destroyed

`jobs.0004` (generated) removed the old `run_id` column, and the follow-up data
migration then tried to copy values out of `run_id_legacy`, which was still blank.
The copy could never see a value: every pre-migration run id was lost.

The `RunPython` copy now lives *inside* `0004`, ordered `AddField(run_id_legacy)`
-> `RunPython(copy)` -> `RemoveField(run_id)`. `0005` only links jobs to real
`ScanRun` rows, and stays unlinked when the match would be ambiguous rather than
guessing. Verified against a database seeded with legacy ids:

```
9 rows preserved, `run_id` column dropped, non-legacy rows left blank
```

### Fixed: owner backfill could strip real access on rollback

`targets.0006` reverse deleted **every** OWNER membership of **every** current
superuser, which includes grants an operator made after the backfill. Those rows
carry no provenance marker, so the destructive version is unrecoverable. Reverse
is now an explicit no-op that logs a warning.

### Fixed: IDOR in every asset detail view

`_deny_on_context_mismatch()` only compared the caller's `?target=` / session
context with the object's target. Naming the correct `?target=` therefore granted
read access to **any** target with **no membership check at all** — caught by
`test_non_member_denied_even_with_matching_context`. Detail views now call
`require_capability(..., CAP_READ)`, and the target picker only offers
`authorized_targets(user)` so the target inventory does not leak either.

### Fixed: `detect_wildcard` reported a clean verdict when it could not probe

A swallowed `except` around the whole probe meant a `dnspython` import failure
recorded `wildcard_detected=False` — a *false negative* on the control that gates
subdomain acceptance. The verdict is now only written when the probe actually
resolved; inconclusive probes log and leave the previous value alone.

### Execution integrity

- `_job()` returns `(job, target, run)`; every stage and `reconcile_target` bind
  to a real `ScanRun` FK. No free-form run-id strings remain in the pipeline.
- `execution_context` ambient provenance is recorded from `services/correlation/
  ingest.py` for subdomains, DNS, ports, HTTP services, URLs, JS, technology,
  and findings, so persisted assets trace back to job/tool execution.
- `TargetConsistencyMixin` now *inherits* `target` from a target-scoped parent
  when its own `target` is nullable (`Event.target`), instead of rejecting valid
  global events. A genuine contradiction is still an error.
- Cooperative cancellation checkpoints added to every long loop, including
  `reconcile_target`, which previously created a `_cancellable` block and never
  called `check()`.
- The cancel check re-reads the target and defers to `Target.is_scannable`
  rather than re-deriving the rule (the re-derived copy referenced a
  non-existent `Target.AUTH_REVOKED` and raised `AttributeError`).

### Test expectation updated (behaviour intentionally changed)

`test_detail_view_without_target_param_on_fresh_session` asserted 200 for a
fresh session with no context, which was only true under the retired
single-tenant default. `SINGLE_TENANT_ALL_TARGETS` is now `False`, so a member
must still name the target. Updated to 403 and paired with positive
(member + matching context -> 200) and non-member coverage.

### Verification

| Check | Result |
|---|---|
| `manage.py check` | 0 issues |
| `makemigrations --check --dry-run` | No changes detected |
| Clean DB `migrate` | OK (all apps) |
| Upgrade from pre-change schema w/ legacy data | OK, values preserved |
| `migrate targets 0005` -> `0006` round trip | OK |
| `migrate jobs 0004` -> `0005` round trip | OK |
| Test suite | **95 passed** (baseline was 93) |

---

## P0-004 … P0-008 — Target authorization group (2026-09-28)

**Tests: 143 passed, 31 subtests passed** (`python -m pytest -q`), up from 95.

### Defects found and fixed

| Task | Defect | Fix |
| --- | --- | --- |
| P0-004 | `dashboard` resolved `?target=` with `Target.objects.get(pk=…)` — no membership check, so any authenticated user could read another tenant's counts/events/jobs. | Resolve through `get_authorized_target` (403/404). |
| P0-004 | A denied/unknown target fell through to the "global" branch, whose querysets were **unscoped** — the failure mode of a 403 was a full cross-tenant dump. | Overview branch restricted to `authorized_target_ids(user)`. |
| P0-005 | `event_list` / `changes` built unscoped `Event.objects` chains and applied `?target=<id>` straight into `filter(target_id=…)`. `Target.objects.all()` rendered as the picker. | `scope_queryset_for_user` base queryset, authorized `?target=`, `authorized_targets()` picker. |
| P0-006 | `LiveConsumer.connect` authenticated the socket but never checked membership — any logged-in user could `group_add` to `target_<id>` and receive another tenant's live telemetry. | `require_websocket_target_access` **before** `group_add`; close 4401/4403/4404. |
| P0-006 | No re-check at delivery time, so a membership revoked after connect kept streaming. | `event_message` re-authorizes each delivery and closes on revocation. |
| P0-006 | No guard that a payload's `target_id` matched the subscribed target. | Cross-target payloads are logged and dropped. |
| P0-007 | **All 12 DRF viewsets used `IsAuthenticated` only with `Model.objects.all()`.** Omitting `?target=` returned the entire table; supplying it applied the id with no authorization. | `AuthViewSet` resolves ownership per model and scopes to membership; explicit target is validated (403/404) for every caller including admins. |
| P0-007 | Ownership inferred by string-matching `model.__name__` (`"JavaScriptFinding"`, `"Alert"`), which silently returned **unfiltered** data for unrecognised models. | Ownership declared explicitly per viewset (`target_lookup`). |
| P0-007 | `global_search` searched every asset model unscoped and returned JSON — a cross-tenant search and existence oracle. | Results restricted to authorized targets. |
| P0-007 | Unauthenticated `health` published the per-tool inventory. | Tool detail restricted to administrators. |
| P0-007 | `JobSerializer` exposed `command_redacted` and `run_id_legacy`. | Both excluded. |
| P0-007 | Paginated unordered querysets (rows could repeat/skip across pages). | `ordering = ["-id"]` default. |
| P0-008 | `get_object_for_target` probed a hard-coded attribute list (`js`, `event`, `scan_run`) with `getattr`, issuing a query per attribute, missing unlisted models, and disagreeing with other querysets because `Alert` owns a *direct* target FK. | `OWNERSHIP_PATHS` + `classify_model` / `ownership_of`; direct and indirect resolved uniformly. |
| P0-008 | `effective_role` ordered memberships by the role **string** (`-role` → `VIEWER` first, the weakest role); safe only because of the unique constraint. | Explicit rank comparison. |
| P0-008 | `audit()` swallowed every failure with `except Exception: pass` — audit rows are security evidence. | Logged and re-raised. |
| — | `global_admin_override` used two blind `except Exception` returns in the security-critical path. | Narrowed to `getattr(..., None)`. |
| — | `role_of` returned `VIEWER` on any exception when reading the profile. | `getattr(..., None)`, still least privilege. |

### Latent bugs found in never-exercised fixture code

* `ToolExecution` had no `STATUS_COMPLETED` (it borrowed `ScanRun.STATUS_CHOICES`) — `tests/fixtures.make_tool_execution` raised `AttributeError`. Added local constants (class-level only, no migration).
* `tests/fixtures.seed_assets_for` was unusable: wrong field names (`source`), missing `first_seen`/`last_seen`, and it passed model instances into `Port.ip`/`HTTPService.ip`/`port`, which are `CharField`/`IntegerField`, not relations. Rewritten against the real schema.

### New tests

* `tests/test_api_isolation.py` — 26 tests (new file): list scoping, explicit-target 403/404, detail-route IDOR, read-only enforcement, anonymous rejection, admin override, serializer redaction, search/health scoping.
* `tests/test_websocket.py` — 15 tests: 5 anonymous/auth, **7 new** membership cases (non-member refused *and never added to the group*, other-tenant refusal, unknown target 4404, superuser, revocation stops delivery, cross-target payload dropped), 3 broadcast-routing.
* `tests/test_target_isolation.py` — 30 tests: **+15** for ownership classification, `for_user` default-deny, `get_object_for_target`.
* `tests/test_requirements.py` — 7 tests (new file) pinning the dependency resolution below.

> WebSocket membership tests use `TransactionTestCase`: the consumer resolves membership through
> `database_sync_to_async`, i.e. a separate thread and connection that cannot see the uncommitted
> rows inside a `TestCase` atomic block ("database table is locked").

### Requirements discrepancy — resolved

`requirements.txt` allowed `Django>=5.0,<6.0` while `requirements.lock.txt` pinned
`Django==6.1.1`, and the venv the project is developed and tested against runs **5.2.17**. A
deploy built from the lock would not have been the tested configuration.

* `requirements.txt` → `Django>=5.2,<5.3` — the LTS line, with the upper bound at `<5.3` so a new
  major cannot change behaviour under a deploy without an explicit decision.
* `requirements.lock.txt` → `Django==5.2.17`; header rewritten to state the verified line, to
  declare itself a **runtime** lock (it omits pytest/ruff/black/flake8/mypy, so the old
  "generated from the verified venv (pip freeze)" claim was false), and to explain the
  `psycopg2-binary` pin (2.9.10 → 2.9.13, prod-only driver not exercised by the SQLite venv).
* `tests/test_requirements.py` prevents recurrence: lock must equal the installed version, the
  range must be satisfied, the installed version must satisfy the range, and the major must be 5.

Dev/lint/type tooling still has no pinned source of truth — recorded for the P3 tooling task.

---

## P0-010 / P0-011 — Canonical execution root + cross-model target consistency (2026-09-28)

**Tests: 191 passed, 48 subtests passed** (up from 150). New file
`tests/test_consistency.py`: **41 tests, 5 subtests**.

### The enforcement existed — but three write paths bypassed it

`TargetConsistencyMixin.save()` was already called on every `save()`, and all
eight required invariants were already declared. A probe of the ORM showed the
guarantee did not actually hold:

| Bypass | Behaviour before the fix |
| --- | --- |
| `bulk_create()` | Persisted an `AssetObservation(target=A, scan_run of B)` with **no error** — `save()` never runs. |
| `.update()` | `ToolExecution.objects.filter(...).update(target=B)` moved a row off its run's target silently. `all_objects` was a plain `models.Manager()`, so the unscoped path was *also* unguarded. |
| Validator side effect | `_consistency_violations()` **assigned `self.target_id`** while validating. `full_clean()` could therefore return a mutated object even if a later validation step failed, and inheritance depended on dict iteration order. |

All three are fixed:

* `ConsistentTargetScopedManager` / `ConsistentTargetScopedQuerySet` now guard
  `bulk_create()` and `update()`. `objects` **and** `all_objects` use it, so the
  two managers differ only in read scope, never in write safety. Managers are
  not serialized into migrations, so this needed no migration.
* Validation is side-effect free. Target inheritance is a deliberate, explicit
  step in `save()` (`inherited_target_id()`), not a validator side effect, and it
  only applies when **every** present parent agrees — contradictory parents are
  now rejected rather than silently resolved to whichever came first.

### P0-010 — the chain was not actually closed

`JSAnalysisJob` is named in the required chain
`ScanRun → ScanJob → JSAnalysisJob → ToolExecution → AssetObservation → Event`,
but its only link to the execution root was `parent_job`, which is **nullable** —
so a JS analysis with no parent job could not be traced to any run at all, and
"which run produced this finding?" had no answer. Added a real
`scan_run` FK (`apps/jobs/migrations/0006_jsanalysisjob_scan_run.py`); the
redundancy with `parent_job` is deliberate (root vs. dispatch link) and
`RELATED_TARGET_FKS` now checks it too.

### DB-level constraints

Cross-table target equality is not expressible as a portable SQL `CHECK`, and
PostgreSQL would need a trigger. The ORM guards are the practical backstop; raw
`cursor.execute` remains the documented trust boundary and is now stated as such
in the module docstring.

### Tests

41 negative tests, each with a matching **positive** case so a test cannot pass
by being inverted or by the rule being broken. All eight taskbook invariants are
exercised through `save()`, `bulk_create()` and `update()`; plus side-effect-free
validation, explicit inheritance, contradictory-parent rejection, the full
`ScanRun` chain walked by relation, and batch atomicity (a rejected batch leaves
no valid rows behind).

### Migration evidence

Clean init → `0006` applied; back to `0004`; forward again; `0006` unapplied
alone (column dropped) and re-applied (column restored); `check` clean;
`makemigrations --check --dry-run` reports no drift.

### Note on ruff

RUF012 fires 27 times in the model files on Django's own `choices`,
`Meta.ordering` and `indexes` attributes. Those must be mutable lists in
Django's API, so this is a ruff/Django false positive; the genuine cases
(`RELATED_TARGET_FKS`, `REQUIRED_PARENT_FKS`) are now correctly annotated
`ClassVar`. The framework cases are deferred to the P3 ruff configuration task.

---

## P0-012 — Race-safe event deduplication (2026-09-28)

**Tests: 198 passed, 48 subtests passed** (up from 191). New file
`tests/test_event_dedup.py`: 7 tests.

### The defect

`Event.fingerprint` already carried `unique=True` (verified: a duplicate insert
raises `IntegrityError`, backed by `sqlite_autoindex_events_event_1`), so the
database guarantee existed. The **dedup logic** did not use it —
`services/event_engine/engine.py` did:

```python
existing = Event.objects.filter(fingerprint=fingerprint).first()   # probe
if existing:
    return existing, False
event = Event.objects.create(...)                                   # insert
```

That is check-then-act. Two concurrent submitters for the same state both read
"nothing there" and both insert; the loser's `IntegrityError` was never caught,
so a duplicate-detection race surfaced as a **crashed scan** rather than a
deduped event. Verified empirically by reverting the fix — the concurrent test
then fails with exactly the production symptom:

```
IntegrityError: UNIQUE constraint failed: events_event.fingerprint
```

### The fix

One atomic `get_or_create(fingerprint=..., defaults=...)`. The race is resolved
inside the database and the losers get the winner's row back, so N simultaneous
submissions yield exactly one `Event` and every caller receives it. The
`created` flag now gates the side effects, so a deduped emit no longer
re-broadcasts the WebSocket update or re-dispatches the alert/dependent jobs.

### Tests

Two styles, because each catches a different regression:

* **Real threads** — 8 writers released from a `threading.Barrier` at the same
  instant, each with its own connection. Asserts: all 8 return the same row,
  exactly one is told `created=True`, and the fingerprint has exactly one row.
  A second test proves 6 *distinct* states still all persist, so the fix cannot
  be a blanket collapse.
* **Deterministic interleaving** — forces the losing-writer `IntegrityError`
  branch directly, and asserts side effects run exactly once across three
  duplicate emits. These do not depend on thread scheduling, so a
  timing-lucky pass cannot hide a regression.

**Concurrency caveat, stated explicitly in the test module:** production runs
PostgreSQL (per `requirements.lock.txt`), where writers are genuinely parallel.
The suite runs on SQLite, which allows one writer at a time, so raw concurrent
writers fail with `database table is locked` regardless of application code. The
harness enables WAL plus a busy timeout so writers queue, and retries only that
SQLite lock artefact. The race under test is still real — if `emit_event`
regresses to check-then-create, these assertions fail (demonstrated above).

---

## P1-001 — Race-safe ScanRun creation (2026-09-28)

**Tests: 213 passed, 48 subtests passed** (up from 198). New file
`tests/test_run_race.py`: 15 tests.

### The defect

`_get_or_create_run()` resolved the execution root with the same
check-then-act pattern P0-012 removed from the event engine:

```python
run = ScanRun.objects.filter(target=target, status="RUNNING", scan_type=scan_type)...
if run: return run
return ScanRun.objects.create(...)          # nothing in the database prevents this
```

Two Celery workers starting the same logical operation concurrently both
observed "no live run" and both inserted one. Nothing in the schema prevented
it: `ScanRun` had no uniqueness on `(target, scan_type)`. Consequences — two
schedulers racing on the same target, two kill-switch states to reconcile, and
no single row that can answer *"is this target currently scanning?"* This is the
row the pause/resume and expiry logic (P0-013/P0-014) depends on, so the
ambiguity propagates.

Verified by reverting the fix — the concurrency test then fails with the
original crash:

```
IntegrityError: UNIQUE constraint failed: jobs_scanrun.target_id, jobs_scanrun.scan_type
```

### The fix

Two layers, because either alone is insufficient.

**1. Database guarantee (the real one).** A conditional unique index — the only
way to express "active" as a schema rule, and the layer that holds across
processes:

```python
constraints = [
    models.UniqueConstraint(
        fields=["target", "scan_type"],
        condition=models.Q(status__in=["PENDING", "RUNNING"]),
        name="uniq_live_run_per_target_type",
    ),
]
```

The condition is what makes this safe: terminal runs stay unconstrained, so run
history accumulates normally while two *concurrent* runs cannot exist.

**2. Insert-and-catch in the helper.** The probe is kept as a fast path, then
the insert is wrapped in `transaction.atomic()` with `IntegrityError` treated as
"another worker won" and its run adopted. The loser's `IntegrityError` is a
signal, not a crash. If the index fires for any other reason the error is
re-raised rather than papered over.

`PENDING` counts as live, so a re-entrant stage adopts the pending run instead
of orphaning a second one.

### Migrations

Split in two, because the constraint cannot be applied while duplicates exist:

* **`0007_close_duplicate_live_scan_runs`** — data migration. Groups live runs
  by `(target_id, scan_type)`, keeps the **newest** per group (the run a worker
  was most likely holding), retires older ones to `SKIPPED` with an explanatory
  `error_summary`. Nothing is deleted: jobs, tool executions and observations
  remain intact and queryable. Deliberately **not** reversible — restoring a
  duplicate to live would re-create the exact race the migration closes.
* **`0008_scanrun_uniq_live_run_per_target_type`** — the constraint.

Verified against a seeded duplicate: migrate to `0006`, insert two live runs for
one `(target, scan_type)` plus a `BASELINE` run, then migrate forward —

```
seeded duplicate live runs: 1 2 -> count = 2
--- after 0007 + 0008 ---
  live run pk=2 type=MONITORING error=''
  live run pk=3 type=BASELINE error=''
  total rows preserved: 3 (nothing deleted)
  OK: duplicate live run rejected by DB
  OK: multiple terminal runs allowed -> 1 completed
  OK: backward migrate to 0006 succeeded
  OK: re-apply forward succeeded
```

`python manage.py check` clean; `makemigrations --check --dry-run` reports no
changes; forward/backward/reapply verified.

### Tests

`LiveRunConstraintTests` (6) — the schema guarantee in isolation: second live
run rejected, `PENDING` counts as live, distinct `scan_type` and distinct
targets may run concurrently, terminal runs unconstrained, a new run allowed
once the previous finishes.

`GetOrCreateRunTests` (7) — helper contract: creates, reuses, adopts a pending
run, starts fresh after a terminal run, honours an explicit `scan_run_id`, and
rejects both a missing and a cross-target `scan_run_id`.

`ConcurrentRunCreationTests` (2) — **8 threads** released from a
`threading.Barrier` with one connection each. Asserts all 8 receive the *same*
`pk` and exactly one live run exists. A second test confirms `MONITORING` and
`BASELINE` racing for the same target do not collide, so the fix cannot be a
blanket collapse.

**Concurrency caveat, as in P0-012:** production runs PostgreSQL, where writers
are genuinely parallel. The suite runs on SQLite, which allows one writer at a
time, so raw concurrent writers fail with `database table is locked` regardless
of application code. The harness enables WAL plus `busy_timeout` and retries
**only** that lock artefact, never the race itself. Reverting the fix makes these
assertions fail, as shown above.

### Lint

> **Correction (2026-09-28, P0-013):** the delta quoted here (62 → 59) was
> measured with `git stash` against the *whole uncommitted remediation tree*,
> not P1-001 in isolation, so the per-code attribution below overstated what
> P1-001 alone changed. The only lint change actually attributable to P1-001 is
> the new `constraints` list on `ScanRun.Meta` (`RUF012` mutable-class-default,
> a known Django false positive already accepted for the existing
> `indexes`/`ordering`).

The P1-001 test file is Ruff-clean. `apps/jobs/tasks.py` + `apps/jobs/models.py`
sit at 59 findings at P1-001 time (62 on the pre-remediation tree); the bulk is
pre-existing debt (`BLE001`/`S112`/`G201`/`S110`), not introduced here.

### Open defect found while linting — FIXED in P0-013

> **Corrected scope (2026-09-28, P0-013):** the earlier report below claimed six
> undefined `check()` sites (661, 753, 771, 843, 921) and recommended deciding
> the cancellation contract before P0-013. On re-inspection, **only line 753**
> (`resolve_dns`, dnsx result loop) was an actual `F821: Undefined name 'check'`
> — the other`check()` calls were already bound inside their
> `with _cancellable(...) as check:` blocks. That single latent crash is **now
> fixed** as part of P0-013 (see the P0-013 section); `ruff --select F821` is
> clean across `apps/`, `services/`, `config/` and `tests/`.

Ruff surfaced a **latent crash introduced by earlier P2-006 remediation work**:
`resolve_dns()` on a `PARTIAL` dnsx result reached `check()` inside its parsing
loop with no `_cancellable` binding (F821), raising `NameError` at runtime in the
cooperative-cancellation path. P0-013 wraps the dnsx `adapter.run()` + parsing
loop in `_cancellable` and converts the crash into a proper `_stop_if_cancelled`.

## P0-013 — Pause is a real kill switch (2026-09-28)

**Requirement:** pausing a target must (1) stop already-queued work, (2) make
running jobs detect the stop on a bounded interval, (3) terminate long tool
subprocesses *and their process groups* (no orphaned children), (4) prevent
per-asset / child-job fan-out while paused, (5) finalize the job as
cancelled/paused with an attributable reason, and (6) resume cleanly —
re-activating the target, re-queueing PAUSED jobs and freeing a fresh execution
root so P1-001's single-live-run guarantee is not blocked by the cancelled run.

### What was wrong

* `services/tool_adapters/base.py` used blocking `subprocess.run`: no process
  group, no cancellation — a 5-minute default timeout could keep a tool running
  long after the target was paused.
* `target_pause` in `apps/targets/views.py` was a *label flip*: it relabelled
  `QUEUED`/`RUNNING` jobs to `PAUSED` and never tripped `ScanRun.cancel_requested_at`,
  so no RUNNING tool was ever told to stop and the run stayed "live" forever.
* Several adapter sites called `check()` inside long loops with no
  `_cancellable` binding (the F821 at `resolve_dns` line 753) or ran
  `adapter.run()` with no `cancel_check` at all, so a pause mid-tool was not
  honoured until the tool returned on its own.

### The fix

* **`services/tool_adapters/base.py`** — new `_run_tool_process()` runner:
  `subprocess.Popen(start_new_session=True)` gives each tool its own process
  group; a pump thread drains stdout/stderr; a poll loop invokes the
  `cancel_check` callback every ~0.2s instead of blocking. On cancel/timeout,
  `_kill_tool_group()` SIGTERMs the whole group, waits a 2s grace, then SIGKILLs —
  so the tool and any grandchild it spawned are terminated together. The
  original `cancel_check` exception is re-raised *after* teardown so the caller's
  own `_stop_if_cancelled` handling decides the final state (CANCELLED, never
  FAILED, for kill-switch trips). `run()` / `run_stdin()` gained a `cancel_check`
  parameter; `TimeoutExpired` still maps to a FAILED "timeout" result.
* **`apps/jobs/tasks.py`** — every adapter call site now runs inside
  `with _cancellable(target, job=job, run=run) as check:` (or the child-task
  variant `run=None`) with `cancel_check=check`, and converts `_Cancelled` with
  `_stop_if_cancelled(exc, job, target)`:
  - `resolve_dns` — dnsx `adapter.run(hosts, timeout=300, cancel_check=check)` +
    the per-batch parsing loop (fixes the F821) and the stdlib fallback loop;
  - `discover_subdomains` — assetfinder adapter;
  - `scan_ports` — naabu adapter + stdlib connect fallback;
  - `probe_http` — httpx adapter (1000-candidate run) + stdlib urllib fallback;
  - `discover_urls` / `run_nuclei` (per-URL) / `process_new_ip` (naabu per-IP) /
    `probe_http_targets` (httpx per-asset) / `nuclei_for_url` (per-URL child).
  The per-asset urllib loops additionally check `target.is_scannable` before
  each fetch so no per-asset network work happens after a kill switch.
* **`apps/targets/views.py` `target_pause`** — now:
  - sets `status=PAUSED` (makes `is_scannable()` False, so `_gate`,
    `_asset_job`, `handle_event_dependents` and `baseline_target` all refuse new
    work immediately);
  - pauses *only* `QUEUED` jobs (resumable) — `RUNNING` jobs are left for the
    cooperative kill switch, which alone owns their final state;
  - calls `run.request_cancel(reason="TARGET_PAUSED")` on every live run and, if
    no live job remains under a run, finalizes that run as CANCELLED right away
    so P1-001 can never mistake it for a live run.
  `target_resume` (unchanged) sets ACTIVE and re-queues PAUSED jobs.

### Verification

* `tests/test_kill_switch.py` — **16 tests**, covering the taskbook matrix:
  queued (pause makes `is_scannable` False, `_gate` fails, `_asset_job` returns
  None, `handle_event_dependents` skips → no child work), running (a RUNNING job
  detects the pause at the *first* `check()`, no poll wait; `_stop_if_cancelled`
  finalizes job `CANCELLED_KILL_SWITCH` + run `CANCELLED` with
  `cancel_reason=TARGET_PAUSED`), multi-stage (a baseline paused after
  `resolve_dns` returns CANCELLED, baseline_status stays INITIAL_BASELINE,
  Baseline→CANCELLED, and the control baseline still completes), subprocess
  (a real `_run_tool_process` run spawns a grandchild; on cancel the whole
  process group dies within grace — grandchild reaped, survival marker never
  written — plus timeout and clean-output cases), and pause/resume through the
  views (queued→PAUSED, RUNNING left to the cooperative path with
  `cancel_requested_at` tripped, run finalized when no live job remains, resume
  re-queues and a fresh execution root is creatable under P1-001).
* Full regression: **229 tests + 48 subtests, all pass** (pre-P0-013: 213).
* `python manage.py check` clean; `makemigrations --check --dry-run` → no
  changes (no schema change required).
* F821 is gone across `apps/`, `services/`, `config/`, `tests/`
  (`ruff --select F821` clean); the earlier P1-001 doc block correctly bounds
  the scope of that defect as a single line now fixed here.

## P0-014 — Stop execution after authorization expiry (2026-09-28)

**Requirement:** when authorization expires the target becomes non-scannable,
queued work pauses, running work detects cancellation, no child job is
launched, tool execution stops cooperatively, and a lifecycle event is
recorded — tested while queued, while running, and between stages.

### What was wrong

`check_authorization_expiry` already flipped `AUTH_EXPIRED` + `PAUSED` (making
the target non-scannable) and emitted the `AUTHORIZATION_EXPIRED` event, but it
was a *status write, not a halt*: QUEUED `ScanJob`s stayed QUEUED, live
`ScanRun`s were never tripped (`cancel_requested_at` untouched) so an idle run
could sit "live" forever and block the next run under P1-001, and the reason
trail for RUNNING work stopped by expiry read `TARGET_PAUSED` — because the
scheduler pauses the target and `_cancel_reason()` tested `STATUS_PAUSED`
before `authorization_expired()`.

### The fix

* **Shared halt helper.** `_halt_work(target, reason)` in `apps/jobs/tasks.py`:
  QUEUED → PAUSED (resumable), tripped `request_cancel(reason)` on every live
  run, and a live run with no live job left under it finalized CANCELLED
  immediately. Used by both `target_pause` (`TARGET_PAUSED`) and the expiry
  task (`AUTH_EXPIRED`) so the two front doors cannot drift apart.
* **`check_authorization_expiry`** now calls `_halt_work(t, "AUTH_EXPIRED")`
  the moment a target's window lapses, before emitting the lifecycle event.
* **`_cancel_reason()` precedence:** a genuinely lapsed authorization is now
  reported as `AUTH_EXPIRED`/`AUTH_REVOKED` *before* the paused/disabled status
  (still after archived and operator-cancel), so worker-finalized jobs and runs
  carry `cancel_reason="AUTH_EXPIRED"` instead of `TARGET_PAUSED`.
* **`baseline_target` cancelled branch** now `run.request_cancel(reason=...)`
  before finalizing, so the chain's stop reason lands on the run itself.

### Verification

* `tests/test_authorization_expiry.py` — **7 tests**:
  - queued: the scheduler pauses QUEUED jobs, trips the run to
    `cancel_reason="AUTH_EXPIRED"`, finalizes an idle run now, and emits the
    HIGH `AUTHORIZATION_EXPIRED` event exactly once across repeated runs;
  - running: the run is tripped but stays RUNNING while a live job remains, and
    the worker's next `check()` + `_stop_if_cancelled` finalizes the job
    `CANCELLED_KILL_SWITCH` with reason `AUTH_EXPIRED`;
  - between stages: a baseline expired after `resolve_dns` returns CANCELLED
    with `reason=AUTH_EXPIRED`, baseline_status stays INITIAL_BASELINE, the
    Baseline and run finalize CANCELLED with the reason recorded;
  - child work: `_asset_job` and `handle_event_dependents` refuse an expired
    target; the `_cancel_reason` precedence test pins `AUTH_EXPIRED` vs
    `TARGET_PAUSED` depending on whether the window actually lapsed.
* Full regression: **236 tests + 48 subtests, all pass** (pre-P0-014: 229).
  The `_cancel_reason` reorder is neutral for pure pauses (healthy window) and
  archives, confirmed by the still-green P0-013 view tests.
* `python manage.py check` clean; `makemigrations --check --dry-run` → no
  changes; `ruff --select F821` clean.

> P2-001 (split `AUTHORIZATION_EXPIRING`/`AUTHORIZATION_EXPIRED`) and P2-002
> (deduplicate the recurring warning event) are separate tasks further down the
> list and are intentionally left for their own pass.

## P2-001/P2-002 — Distinct expiring/expired events, deduplicated (2026-09-28)

**P2-001:** the scheduler uses the distinct lifecycle events
`AUTHORIZATION_EXPIRING` (warning window, MEDIUM) and `AUTHORIZATION_EXPIRED`
(actual lapse, HIGH) — tested for scheduler behavior and state transitions.
**P2-002:** repeated scheduler runs must not stream unbounded identical warning
events — tested across the window and after renewals.

### What was wrong

Both branches in `check_authorization_expiry` emitted bare
`AUTHORIZATION_EXPIRED`, differentiated only by `evidence` (`warning: True`).
That was worse than cosmetic: `emit_event`'s P0-012 fingerprint ignores evidence
— it is `sha256(event_type|target|asset|old_state|new_state)`. A warned target
therefore got its MEDIUM warning event first, and the later HIGH expired event
hit the *same* fingerprint, so `get_or_create` returned the warning row and the
real expiry alert was silently suppressed. (No unbounded stream existed yet
thanks to P0-012 dedup, but only because the two distinct-signal events were
collapsing into one.)

### The fix

* **Distinct types + registrations:** warning emits `AUTHORIZATION_EXPIRING`
  (added to `Event.EVENT_TYPE_CHOICES` and `SEVERITY_BY_EVENT` as MEDIUM);
  expiry keeps `AUTHORIZATION_EXPIRED` (HIGH).
* **Window-scoped state (P2-002 dedup, no schema change):** every emits passes
  the authorization window in `new_state` — the warning carries
  `{authorization: EXPIRING, expires_at, warning_days}`, the expiry carries
  `{authorization: EXPIRED, expires_at}` plus the prior status in `old_state`.
  Because the fingerprint (TASK-053) folds in that state:
  - a stable window dedups across every scheduler run → exactly one event;
  - a renewed window (`authorization_expires_at` moved, as the edit form does)
    produces a fresh fingerprint → the warning and the HIGH expiry each re-arm
    for the new window instead of being deduped forever.
* The `warning: True` flag stays in `evidence` for the UI, but the event *type*
  now carries the meaning.

### Verification

`tests/test_expiry_warning_events.py` — **6 tests**:
- window emits one MEDIUM `AUTHORIZATION_EXPIRING` (never `EXPIRED`, target not
  touched) across six scheduler runs; a renewal re-arms a fresh warning;
  outside-window targets emit nothing;
- a warned target still receives its HIGH `AUTHORIZATION_EXPIRED` at actual
  lapse (the collision regression); the expired event dedups across five runs;
  re-authorizing a new window re-arms a second HIGH event.
- Full regression: **242 tests + 48 subtests, all pass** (pre-P2: 236). Git
  stash comparison confirmed the 22 ruff findings on the three touched files are
  identical on baseline (no new debt introduced); `ruff --select F821` clean;
  `manage.py check` clean; no schema change (`makemigrations --check --dry-run`).

## P0-015/P0-016 — Every outbound fetch through the centralized TLS/SSRF layer (2026-09-28)

**P0-015:** the JS recheck path (`recheck_javascript`)
no longer builds `ctx.check_hostname = False / ssl.CERT_NONE`; it fetches
through the same centralized `_fetch_url_for_recon` used by the main recon
pipeline and therefore honors `target.verify_tls`.
**P0-016:** audited every outbound fetch site (`requests`, `httpx`, `urllib`,
`urlopen`, `socket`, `ssl`, subprocess tool calls) and consolidated the two
target-originated fetches (JS recheck and the JS-analysis DOWNLOAD stage in
`services/correlation/jsanalysis.py`, which had its own identical `CERT_NONE`
block) onto the centralized layer; added per-hop redirect validation; pinned the
SSRF matrix in tests.

### Outbound-fetch audit (sites, verdict)

| Site | Origin | Verdict |
| --- | --- | --- |
| `_fetch_url_for_recon` (apps/jobs/tasks.py) | target | centralized T2/T3/T4; redirect hops now re-validated |
| `probe_http` urllib fallback | target | pre-checked + TLS-honoring; now uses `_safe_opener` (redirect-revalidated) |
| `probe_http_targets` urllib fallback | target | same, switched to `_safe_opener` |
| `recheck_javascript` (apps/monitoring/tasks.py) | target | **P0-015**: was `CERT_NONE`; now `_fetch_url_for_recon` |
| `jsanalysis.run_analysis` DOWNLOAD | target | was `CERT_NONE`; now `_fetch_url_for_recon`; policy refusals fail loudly with the block reason |
| `alerting/discord.py` (requests.post webhook) | system | Discord API, `requests` default `verify=True`, 15s timeout; not target-originated — left |
| `tool_adapters/adapters.py` crt.sh CT lookup | system | fixed trusted upstream `https://crt.sh`, `verify=True`; target data only in the query — left |

### What was added

* **`_ScopedRedirectHandler` + `_safe_opener`** (apps/jobs/tasks.py): every
  redirect hop from a fetch is re-checked through `_url_allowed_for_fetch`.
  urllib otherwise follows redirects internally, so a fetch checked at its
  initial URL could redirect into a private/reserved IP or out of scope; any
  forbidden hop raises `_ReconFetchSkipped` (a policy skip, not a crash).
  `_safe_opener` composes `_ssl_context_for` (T3) with the redirect gate, and is
  used by `_fetch_url_for_recon` and both probe_http fallbacks.
* A bare `FileHandler`/other schemes are already refused by the scheme gate in
  `_url_allowed_for_fetch` (`Bandit B310` existed).

### Verification

`tests/test_ssrf_and_fetch.py` — **19 tests**:
- SSRF matrix against `_url_allowed_for_fetch`: loopback, RFC1918
  (10/172.16/192.168), IPv6 `::1`, link-local/metadata `169.254.169.254`,
  CGNAT `100.64`, out-of-scope host, `file://` scheme, in-scope subdomain pass,
  DNS-rebinding defense (allowed-by-rule hostname still refused when it resolves
  to a blocked IP);
- redirect validation against a live loopback server: redirect to private IP
  blocked, redirect out of scope blocked, in-scope redirect followed
  (real `302` -> 200 round trip);
- TLS policy for `_ssl_context_for` (default = CERT_REQUIRED/hostname check;
  opt-in `verify_tls=False` = CERT_NONE) plus real handshakes against a
  self-signed `wronghost.invalid` cert: verification on raises
  `URLError(SSLCertVerificationError)`, intentional opt-out succeeds;
- JS path consistency: `recheck_javascript` now calls
  `_fetch_url_for_recon(target, js.js_url, stage="js-recheck")` and flows into
  the shared `ingest_js`; `run_analysis` DOWNLOAD is refused with
  `download blocked` for an out-of-scope JS url and honors `verify_tls`.
- Full regression: **261 tests + 48 subtests, all pass** (pre-P0-015/016: 242).
  One isolation test was updated to fake the new network seam
  (`_safe_opener`) instead of the module-level `urllib.request.urlopen` that the
  pipeline no longer calls; its assertions (never fetch `evil.example.org`,
  in-scope `/local.js` is ingested) are unchanged and the real scope gate stays
  active beneath the fake.
- `manage.py check` clean; no schema change
  (`makemigrations --check --dry-run`); `ruff --select F821` clean; the only
  surviving deliberate `CERT_NONE` is the opt-in `verify_tls=False` branch of
  `_ssl_context_for`, which logs an explicit WARNING.

## P0-017 — Correct baseline final status (2026-09-28)

`baseline_target` previously stamped `BASELINE_COMPLETE` after any un-cancelled
run, regardless of stage outcome. It now aggregates stage results explicitly.

### Aggregation (`_aggregate_baseline` in apps/jobs/tasks.py)

* Required spine: `discover_subdomains -> resolve_dns -> scan_ports -> probe_http`.
  Optional: `discover_urls`.
* **COMPLETE** — every required stage `COMPLETED` (or `SKIPPED` only because the
  scan profile deliberately excludes that capability, e.g. balanced has no
  `port_scan`) and the URL crawl neither failed nor degraded.
* **PARTIAL** — a required stage ended `PARTIAL` or unexpectedly `SKIPPED`, or
  the optional URL crawl `FAILED`/`PARTIAL`/left no record. Never COMPLETE.
* **FAILED** — a required stage `FAILED` or left no record at all.

### Honest stage results

`scan_ports` and `probe_http` no longer report an unconditional `COMPLETED`
when coverage was reduced: a partial naabu/httpx run, or the capped stdlib
fallback (limited port list / 200-URL urllib probe, usually because the primary
tool is missing), degrades the stage to `PARTIAL`. The stage job is closed as
`PARTIAL` and now closes its idle execution root as `PARTIAL` too (ScanJob
gained `STATUS_PARTIAL` in `TERMINAL_STATUSES`; `_close_run_if_idle` maps a
PARTIAL job to a PARTIAL run instead of a FAILED run).

### Effects

`Target.baseline_status` gains `BASELINE_PARTIAL` / `BASELINE_FAILED`;
`Baseline.status` gains `PARTIAL` / `FAILED` (migration
`monitoring.0003_alter_baseline_status`, forward/backward/reapply verified);
new event types `BASELINE_PARTIAL` (INFO) / `BASELINE_FAILED` (MEDIUM). A manual
"baseline" retrigger on a partial/failed target still routes to the baseline
path (views gate on `!= BASELINE_COMPLETE`), and a partial baseline never
counts as a completed scan upstream.

### Verification

`tests/test_baseline_aggregation.py` — 18 tests:
- aggregator matrix: all-success, required PARTIAL, required unexpected SKIPPED,
  required profile-exclusion SKIPPED (COMPLETE), optional FAILED, optional
  PARTIAL, optional missing, required FAILED, required missing record, empty;
- end-to-end `baseline_target` with stubbed stages (all COMPLETED -> run/target/
  Baseline `COMPLETED`/`BASELINE_COMPLETE`/`COMPLETE` + `BASELINE_COMPLETED` event;
  required PARTIAL and optional FAILED -> PARTIAL; required FAILED and a stage
  exception -> FAILED, each also asserting the emitted event type);
- stage honesty: naabu unavailable -> `scan_ports` returns PARTIAL and the run
  closes PARTIAL with `fallback_used=True` ToolExecution; httpx unavailable ->
  `probe_http` returns PARTIAL.
- Full regression: **279 tests + 48 subtests, all pass** (pre-P0-017: 261).
  `manage.py check` clean; `makemigrations --check` clean (new migration present).
  The `test_uninterrupted_baseline_still_completes` kill-switch test was updated
  only where it asserted the task result spelling `COMPLETED` (unchanged
  contract) — the patched-complete baseline still lands on COMPLETE.

## P1-011/P1-012 — Fallback coverage is explicit, recorded, never overstated (2026-09-28)

Every optional-tool fallback in the pipeline now records *that* it degraded, *how
much* it covered, and marks the stage/job accordingly. A limited fallback is
never labeled equivalent coverage of the primary tool.

### Shared coverage record

`_coverage_note(configured, attempted, **extra)` (apps/jobs/tasks.py) builds the
uniform record persisted on `ToolExecution.coverage`:
`{configured, attempted, reduced, coverage_ratio, dimension, ...}` — `configured`
is what the engagement asked for, `attempted` what we actually checked,
`reduced` is true whenever the attempt is narrower, and `coverage_ratio`
quantifies the shortfall. This gives P1-002's `coverage` column a real,
queryable meaning instead of a bare "open ports" count.

### Fallback sites fixed (all of them)

| Site | Before | Now |
| --- | --- | --- |
| `scan_ports` (target stage) | naabu missing recorded nowhere; socket fallback coverage was `{"open": N}` with a hardcoded `port_list[:20]` cap | naabu recorded `SKIPPED` + `fallback_used` with the reduced coverage it implies; socket fallback records `PORT_FALLBACK_MAX_PORTS` vs configured ports, `coverage_ratio`, and the shared-suspect IPs that were skipped; stage/job is `PARTIAL` |
| `probe_http` (target stage) | httpx missing recorded nowhere; urllib fallback coverage was `{"services": N}` despite probing only 200 of N candidates | httpx recorded `SKIPPED` + `fallback_used`; urllib fallback records `HTTP_FALLBACK_MAX_URLS` vs candidate count with `reduced`; stage/job is `PARTIAL` |
| `process_new_ip` (per-IP) | no ToolExecution at all for naabu or the socket sweep | naabu (used/failed/missing) and the socket fallback are both recorded; the per-IP sweep covers the full capped list so its coverage is correctly reported as *not* reduced, with the fallback reason recorded |
| `host_url_discovery` | katana missing was silent; the job still reported `COMPLETED` with only script-src extraction done | katana recorded `SKIPPED` + `fallback_used` + `reduced`; the job is `PARTIAL` |
| `run_nuclei` / `nuclei_for_url` | `SKIPPED` with no coverage detail (single-URL path recorded nothing at all) | both record the missing validator with `validated: false`, `degraded: true`, and the affected URL; the single-URL path now records its real tool run status and does not report COMPLETE for a PARTIAL nuclei run |
| `discover_subdomains` | already per-source correct (each source recorded, missing -> `PARTIAL`) | unchanged, now covered by tests |
| `jsanalysis._run_tool` | **a run with all five analyzers missing reported `ok=True` and finished `COMPLETED` with zero coverage** | each analyzer is recorded (`ToolExecution` against the run) with `analyzed: false`; a run with skipped analyzers is `PARTIAL` and names them: `degraded coverage: JSLUICE, SEMGREP, ...` |

### P1-012 — port fallback audit

The stdlib socket fallback cannot afford a full port-list x IP sweep (1.5s
`connect()` per probe), so the cap stays — but it is now an explicit, reported
limitation rather than a silent one: `PORT_FALLBACK_MAX_PORTS = 20`, recorded
as `ports_configured` vs `ports_attempted` with `reduced: true` and a ratio.
A stage whose coverage was reduced is `PARTIAL`, which P0-017's baseline
aggregator then propagates to `BASELINE_PARTIAL` — a missing naabu can no
longer produce a `BASELINE_COMPLETE` target. When naabu *is* available and
completes, coverage is recorded as unreduced and the stage is `COMPLETED`.

### Verification

`tests/test_fallback_coverage.py` — 14 tests covering the missing-tool path for
subfinder/amass/findomain/assetfinder, naabu, httpx, nuclei (target + per-URL),
katana, and all five JS analyzers, plus:
- `_coverage_note` arithmetic (full coverage not reduced; partial flagged with ratio),
- port fallback: missing naabu recorded, capped coverage reported, stage/job/run
  all `PARTIAL`, progress still 100 (work finished, just reduced),
  shared-suspect IP reduction recorded, naabu-available path unreduced/COMPLETED,
- http fallback: httpx `SKIPPED` + fallback flag, urllib capped at
  `HTTP_FALLBACK_MAX_URLS` with the exact ratio,
- per-IP path and JS-analyzer degradation end to end.
- Full regression: **293 tests + 48 subtests, all pass** (pre-P1-011/012: 279).
  `manage.py check` clean; no schema change.

## P1-002/P1-003 — Complete tool-execution evidence, no silent evidence loss (2026-09-28)

### P1-002 — the full evidence set is now persisted

Every `ToolExecution` row now carries all required fields. Previously the model
had `command`, `stdout_reference`, `stderr_reference` and `duration`, but
**nothing ever wrote them** — they were permanently empty.

* `AdapterResult` (services/tool_adapters/base.py) now carries `command`
  (already redacted via `redact_command`), `exit_code`, `stdout` and `stderr`
  alongside `status`/`data`/`error`/`duration_ms`; both `run()` and
  `run_stdin()` populate them from the real process result, including the
  timeout path (status FAILED, `exit_code=None`).
* `_record_tool` (apps/jobs/tasks.py) persists: `tool_name`, redacted
  `command`, `status`, `started_at`/`finished_at`, `duration` (seconds, derived
  or explicit), `exit_code`, `fallback_used`, `coverage`, `error`,
  `failure_kind`, and **stdout/stderr references**.
* stdout/stderr are *referenced*, not inlined: `_store_tool_output` writes a
  bounded (512 KiB/stream), **redacted** file under `settings.RAW_DIR/<tool>/<date>/`
  (mode 0600) and the row stores the relative path. The previously-unused
  `RAW_DIR` setting is now the evidence store, and `data/raw/*` is already
  gitignored.
* All 10 real tool call sites plus every `SKIPPED`/missing-tool site now pass
  the evidence through (naabu, httpx, dnsx, katana, nuclei, gau/waybackurls/
  waymore, subfinder/amass/findomain/assetfinder/crtsh, jsluice/linkfinder/
  secretfinder/semgrep/retire).

### Redaction before persistence

New `services/redaction.py` masks credential material in any text about to be
persisted: `key=value`/`key: value` assignments, `Authorization`/`Cookie`/
`X-Api-Key` headers, `Bearer`/`Basic` schemes, AWS/GitHub/Slack/Stripe token
shapes, PEM private-key blocks, URL userinfo, and Discord/Slack webhook URLs.
This matters because scanner output is attacker-influenced *and* frequently
contains the very secrets it found (e.g. secretfinder) — previously `raw`
output was never persisted, and now it must be redacted first.

### P1-003 — persistence failures are explicit

`_record_tool` no longer only logs a failed write. `_note_evidence_failure`:
1. logs the loss with full context,
2. records it in a per-stage counter (`_evidence_failures`, reset at the start
   of each instrumented stage),
3. writes a `JobLog` ERROR line on the job,
4. emits a `JOB_FAILED` event with `evidence_lost: true` so the degradation is
   visible in the product.

Stages consult the counter before reporting success, so **a lost evidence row
can never leave a clean COMPLETED**:
`discover_subdomains`, `scan_ports`, `probe_http`, `discover_urls` and
`run_nuclei` all downgrade to `PARTIAL` (which P0-017 then propagates to
`BASELINE_PARTIAL`). `jsanalysis` reports through the same mechanism.

### Verification

`tests/test_tool_evidence.py` — 18 tests:
- redaction: key/value assignments, auth headers, URL credentials, PEM blocks,
  webhook URLs, benign text untouched, bounded truncation, `contains_secret`;
- adapter evidence: missing tool (SKIPPED + command), success (exit code,
  command, stdout, readable on-disk reference), timeout (FAILED, no exit code),
  nonzero exit (PARTIAL + exit code + stderr), command secrets redacted before
  persistence, output secrets redacted before writing to disk;
- evidence loss: row returned `None`, counter incremented, `JOB_FAILED` event
  emitted, `scan_ports` downgraded to PARTIAL, counter resets per stage;
- full pipeline: a real `resolve_dns` dnsx run persists command, exit code,
  stdout reference, duration, started/finished, scan_run, target and job.
- Full regression: **311 tests + 48 subtests, all pass** (pre-P1-002/003: 293).
  `manage.py check` clean; no schema change (the fields already existed).

## P1-004/P1-005 — Observation failures are visible; observations trace to the tool (2026-09-28)

### P1-004 — no silently discarded AssetObservation

`record_observation` logged an error and returned `None`, but nothing downstream
knew: the stage still reported `COMPLETED`, so a scan with an untraceable
execution looked clean.

Losses now flow through one shared counter in `apps/core/execution_context.py`
(`note_evidence_loss` / `evidence_failures`) that both lost `ToolExecution` rows
(P1-003) and lost `AssetObservation` rows feed. A lost observation is logged with
full context, counted, and the instrumented stages consult the counter before
reporting success — `discover_subdomains`, `resolve_dns`, `scan_ports`,
`probe_http`, `discover_urls` and `run_nuclei` all downgrade to `PARTIAL`. Since
P0-017 aggregates that into `BASELINE_PARTIAL`, a run that lost provenance can
no longer be reported as a complete baseline. The counter lives in the core
module (not the orchestrator) so the ingest layer can report a loss without
importing `apps.jobs.tasks` — no circular import, and the reset is per stage so
one stage's loss cannot silently degrade an unrelated later stage.

### P1-005 — observations link to job *and* tool execution

The model already had `job` and `tool_execution` FKs, but nothing ever populated
`tool_execution`: `tool_context()` was dead code, so "which tool found this
asset?" was unanswerable and every observation pointed at a job with no tool
provenance.

`_tool_context()` now binds the recording tool's `ToolExecution` row around the
ingest that its results feed, so observations resolve the full chain
`ScanRun -> ScanJob -> ToolExecution -> AssetObservation -> Event`:
- `scan_ports`: the socket/naabu row is recorded *before* `ingest_ports`, and the
  ingest runs under it (whichever executed — naabu when available, the socket
  fallback otherwise);
- `resolve_dns`: the dnsx row when dnsx ran, the `socket-getaddrinfo` row for the
  fallback;
- `probe_http`: the httpx row for the tool path, the urllib row for the fallback
  (which is now recorded before `ingest_http`);
- `run_nuclei`: each URL's findings are bound to that URL's nuclei execution, so
  a finding traces to the exact run that produced it;
- `discover_subdomains` / `discover_urls` aggregate several sources into one
  ingest, so their observations stay bound to the job only — attributing assets
  to one of several contributing tools would be a guess, not provenance.

### Verification

`tests/test_observation_evidence.py` — 9 tests:
- P1-004: write failure counted (not silent), stage downgraded to PARTIAL,
  visible event/loss record, success path not counted, no-context is a no-op;
- P1-005: observation links to run + target + timestamp, links to a
  `ToolExecution` when bound, a real `scan_ports` run links its PORT observation
  to the `socket-connect` row (with a fake open socket so the asset is created),
  cross-target consistency is enforced (an observation may not claim another
  target's tool execution/run), and the tool-run observation is rejected.
- Full regression: **320 tests + 48 subtests, all pass** (pre-P1-004/005: 311).
  `manage.py check` clean; no schema change.

## P1-006 — Heartbeat is the primary liveness signal (2026-09-28)

The `HeartbeatMixin`/`heartbeat_at` field and the cooperative `beat()` already
existed (indexed on `(status, heartbeat_at)`), and long loops already refreshed
it via `_cancellable`. What was wrong was the **detector**: it judged liveness
from `JobLog` activity with a hard-coded 30-minute window, ignored
`settings.JOB_STALL_SECONDS`, ignored heartbeat-write failures, and left a
wedged job in `RUNNING` forever.

### `detect_stalled_jobs` rewritten

* Liveness is decided by `heartbeat_at` (falling back to `started_at` only when a
  job never wrote one). Log timestamps are recorded as *secondary* evidence and
  never rescue a stale heartbeat — a chatty-but-wedged job is still stalled.
* The window is `settings.JOB_STALL_SECONDS` (not a hard-coded 30 min), and the
  sweep reports it in its return value.
* A stalled job is flagged, emitted as `JOB_STALLED` (severity raised to HIGH
  with the full liveness evidence: heartbeat time, last log, running-since,
  heartbeat-write error) and — unless `settings.JOB_STALL_MARK_FAILED=False` —
  moved out of `RUNNING` into `FAILED`, then the execution root is closed via
  `_close_run_if_idle`. A job stuck in `RUNNING` forever is indistinguishable
  from a live one, which defeats stall detection, run bookkeeping (P0-012) and
  the kill switch (P0-013) at once.
* A failed heartbeat *write* is reported as a distinct reason
  (`stalled_reason: heartbeat_write_failed`, from the `last_heartbeat_error` the
  mixin persists) because "we could not prove liveness" is a more serious
  condition than silence.
* New setting `JOB_STALL_MARK_FAILED` (default true) allows flag/report-only
  operation.

### Liveness during long analyzer runs

JS analyzers previously ran with no liveness signal at all (a semgrep pass over
a bundle can run for minutes while the JSAnalysisJob heartbeat went stale).
`_heartbeat_checker` is now passed as the analyzers' `cancel_check`, so a long
tool execution keeps refreshing the job heartbeat.

### Verification

`tests/test_heartbeat_stall.py` — 12 tests:
- fresh heartbeat not flagged; stale heartbeat flagged, closed, run closed,
  `JOB_STALLED` event carries `liveness_signal: heartbeat`;
- recent logs do **not** rescue a stale heartbeat; heartbeat (not logs) is the
  deciding signal and the configured window is honoured;
- heartbeat-write failure reported distinctly and included in the event;
- no duplicate event on a second sweep; flag-only mode leaves the status alone;
- a job that never wrote a heartbeat is judged from its start time; terminal
  jobs are never flagged;
- a long-running job that keeps beating is never flagged; `beat()` swallows a
  storage outage without killing work;
- the JS analyzer heartbeat checker actually writes a heartbeat.
- Full regression: **332 tests + 48 subtests, all pass** (pre-P1-006: 320).
  `manage.py check` clean; no schema change.

## P1-007/P1-008 — Total CVE correlation coverage, idempotent synchronization (2026-09-28)

### P1-007 — the global `[:2000]` cap is gone

`sync_cve_database` correlated `Technology.objects.select_related("target").all()[:2000]`:
a hard global cap that silently left **every technology past the 2000th**
un-correlated, with no record that anything had been skipped. It also swallowed
per-technology failures with a bare `except Exception: continue`, so a failing
correlation was indistinguishable from a truncated sweep.

The sweep now:
* walks the table in **keyset-paginated batches** (`CVE_CORRELATION_BATCH_SIZE`,
  default 500) until no rows remain — bounded memory and latency per step,
  **total** coverage, no OFFSET scan, and it keeps working while correlation
  writes new rows;
* counts and logs per-technology failures instead of swallowing them, and
  reports `failed` in the result;
* reports the mode (`full`/`incremental`), the batch size, and whether the KB
  changed.

### Incremental correlation (preferred where feasible)

`Technology.cve_checked_at` (new indexed field, migration
`assets.0008_technology_cve_checked_at`, forward/backward/reapply verified) is
stamped after each correlation. When the CVE KB is *unchanged* since the last
successful pass (same record count, same KB path — a **failed** sync always
forces a full pass so a prior truncation cannot persist), the sweep re-checks
only what could have changed: technologies never correlated before
(`cve_checked_at is null`) or whose `last_changed` post-dates their last
correlation. `sync_cve_database(full_sync=True)` forces the full pass.

### P1-008 — repeated synchronization is idempotent

Correlation was already `CVE.objects.get_or_create` on the unique key
`(target, cve_id, asset_value, product)` with events emitted only on create, so
repeats duplicate nothing. This is now pinned by tests, including repeated
`full_sync=True` runs, and the incremental path is verified not to *skip* a
technology that was never correlated.

### Verification

`tests/test_cve_sync_coverage.py` — 9 tests:
- **2300 technology records (above the old cap) are all correlated** and all
  stamped — nothing silently skipped;
- a 100-row batch size still walks 450 rows (pagination crosses page boundaries);
- candidates + events are created for a matching technology;
- one failing technology does not abort the sweep (1 failed, 9 correlated, all
  10 attempted);
- two runs (and three `full_sync` runs) create exactly one CVE and one event;
- incremental: an already-correlated, unchanged technology is skipped; a brand
  new one is still correlated while the KB is unchanged; a changed KB count
  forces a full pass.
- Full regression: **341 tests + 48 subtests, all pass** (pre-P1-007/008: 332).
  `manage.py check` clean; `makemigrations --check` clean (new migration
  present); the CVE suite no longer shells out to `git` (it was cloning
  cvelistV5 during tests, 245s -> 2.8s).

## P1-009 — The JS recheck sweep is batched, not truncated (2026-09-28)

`recheck_javascript` iterated `qs[:200]` and returned only `{"changed": n}`.
Two defects: a target with more than 200 scripts silently had the remainder
never rechecked (so a changed bundle beyond #200 could never raise
`JS_CHANGED`), and the return value made partial coverage impossible to detect.

It now:
* walks **every** asset in keyset-paginated batches
  (`JS_RECHECK_BATCH_SIZE`, default 100) — bounded memory per step, total
  coverage, no OFFSET scan;
* reports what it actually covered: `{changed, scanned, skipped, failed,
  not_scannable, batch_size}` — a policy skip (`_ReconFetchSkipped`), a hard
  failure and an unscannable target are now distinguishable instead of all
  collapsing into a silent `continue`;
* queries through `JavaScriptAsset.all_objects` so the sweep is not silently
  narrowed by a request-scoped manager.

### Verification

`tests/test_js_recheck_coverage.py` — 6 tests:
- **250 assets (above the old 200 cap) are all fetched and ingested**, each
  exactly once, with a 50-row batch size;
- a 25-row batch still walks 130 assets (pagination crosses page boundaries);
- a single failing asset does not stop the sweep (1 failed, 19 scanned, all 20
  attempted);
- assets of a paused target are counted as `not_scannable`, not silently
  dropped;
- policy skips are counted separately from failures;
- a targetless sweep covers every target's assets.
- Full regression: **347 tests + 48 subtests, all pass** (pre-P1-009: 341).
  `manage.py check` clean; no schema change.

## P1-010 — Removal requires proof of absence (2026-09-28)

`reconcile_target` flipped assets to `REMOVED` purely because `last_seen` had
aged past the grace period. Nothing tied the removal to the quality of the scan
that should have re-observed the asset, so a failed, cancelled, or
*silently reduced* scan manufactured false "removed" events — e.g. a target
whose naabu/httpx were missing (P1-011) had every port and service declared
gone, and any transient DNS blip (or a paused target) removed live subdomains.

### The four states are now explicit

`OBSERVED` / `NOT_OBSERVED_DURING_SUCCESSFUL_SCAN` / `SCAN_PARTIAL` /
`SCAN_FAILED` are module constants in apps/jobs/tasks.py, and the decision is
made **per asset type** from the latest execution of the stage that would have
observed it (`RECONCILE_ASSET_STAGES`: subdomains -> `subdomain_enum`, IPs ->
`dns`, ports -> `ports`, services/URLs/APIs -> `http`/`urls`, JS -> `js`):

* stage `COMPLETED` -> `OBSERVED`: the stage did run, so its silence is proof;
* stage `PARTIAL`/`SKIPPED`/`PAUSED`/`CANCELLED`/still running, **or never run
  at all** -> `SCAN_PARTIAL`: reduced or unproven coverage, absence proves
  nothing and the asset is left alone (a profile-excluded or never-run stage is
  explicitly *not* a coverage promise);
* stage `FAILED` -> `SCAN_FAILED`, also withholding removals.

Removals now carry the evidence that justified them
(`evidence.absence = NOT_OBSERVED_DURING_SUCCESSFUL_SCAN`,
`evidence.scan_state = OBSERVED`). Withheld assets are **not** silently
dropped: they are counted per type on the job stats
(`withheld`, `withheld_by_type`), logged as a WARNING, and returned in the task
result together with the full `scan_states` map.

Reduced coverage is now isolated per asset type — a degraded port scan no longer
blocks subdomain removals (and vice versa) — which is exactly the "reduced port
coverage" case in the taskbook.

### Batching

The stale rows were sliced with `[:500]`/`[:200]`, so a target with more stale
assets than one page left a silent remainder. `_batched()` now walks them in
keyset batches (`RECONCILE_BATCH_SIZE`, default 500) with the kill-switch check
between batches: bounded per batch, complete overall.

### Verification

`tests/test_reconcile_safety.py` — 10 tests: complete successful scan removes
and labels the state; a partial scan never removes; a failed scan never removes;
a cancelled/timeout scan never removes; reduced port coverage blocks **only**
port removals; a never-run stage proves nothing; a profile-skipped stage proves
nothing; withheld counts are per asset and reported on the job stats; 45 stale
subdomains reconcile fully at a 10-row batch size; the grace period still
protects recent assets.

`tests/test_reconciliation.py::test_custom_grace_respected` encoded the old
unsafe behavior (a `dns` job "proving" a subdomain was gone), so it was updated
to create the enumeration-stage proof its second assertion depends on, and a
new test pins the withholding behavior when that proof is absent.

- Full regression: **358 tests + 48 subtests, all pass** (pre-P1-010: 347).
  `manage.py check` clean; no schema change.

## P1-015/P1-016 — Export security and per-target purity (2026-09-28)

### P1-015 — exports are authorized per target, and their storage is hardened

**The critical hole:** `export_download` fetched the job with
`get_object_or_404(ExportJob, pk=pk)` behind a **role** check only
(`@require_viewer`). `require_viewer` verifies the caller's *global* role, not
membership in the job's target — so **any authenticated user could download any
target's export by iterating sequential ids**. `export_history` had the same
flaw (a global list of every export across every target), and `export_index` /
`export_create` only checked the role too.

Fixes:
* `export_download` fetches the job **unscoped** (the worker and the view must
  not depend on ambient session state for a security decision) and then
  enforces `user_can_access_target(user, job.target, "read")` explicitly,
  logging a `DENIED` audit event and raising 403. Guessing the id no longer helps.
* `export_history` is scoped with `scope_queryset_for_user`, so a user only ever
  sees exports for targets they may read.
* `export_index` uses `get_authorized_target(..., "read")` and `export_create`
  uses `get_authorized_target(..., "operate")` — the capability is checked
  against *that target*, not just the role.
* `export_create` validates `export_type` against `ExportJob.EXPORT_TYPES` and
  clamps `format` instead of queueing a job that can only fail.
* Revoked membership immediately denies download (no stale session grant).

**Storage hardening:**
* Export directories are keyed by an **opaque target id** (`target-00000042/`)
  instead of the raw domain, and use the (previously unused, git-ignored)
  `settings.EXPORTS_DIR` root. A hostile or awkward domain can no longer steer
  a path.
* Every path component is sanitized by `_safe_segment` (charset-restricted,
  separator-free, `..`-stripped) and the export type is validated.
* Writes go through `write_atomic` (temp file in the same directory +
  `os.replace`), so a download can never read a half-written file and a failed
  export leaves no `.tmp-` residue.
* Filenames carry a per-run uuid, so two concurrent exports of the same
  type/target cannot overwrite each other.
* Downloads re-resolve the stored path with `os.path.realpath` and require it to
  stay inside that target's export directory (`commonpath` check) — a tampered
  or legacy `file_path` (`../..`, absolute path, planted symlink) yields 404
  instead of arbitrary file disclosure.
* `run_export_job` uses `all_objects` (no request-scoped manager in a worker)
  and abandons the job if its target no longer exists.

### P1-016 — exports never mix targets

`collect()` already filtered every asset class by `target=`, and it now has a
test suite that proves it: a snapshot export of target A contains A's
subdomains, DNS, IPs, ports, URLs, APIs, technologies, JS, events and scan
metadata and contains **no** trace of target B (each asset class is checked
individually, plus the events collection and the metadata block).

### Verification

`tests/test_export_security.py` — 19 tests:
- P1-015: authorized download works; unauthorized download is 403; walking the
  whole id space around a victim's job never yields 200 while the caller's own
  export still does; anonymous is refused; history is scoped; index/create deny
  an unauthorized target; a viewer cannot create; an unknown/traversal export
  type is rejected (no job created); revoked membership denies immediately;
  a stored path outside the export root, a `../../etc/passwd` path, a missing
  file and an in-progress job are all 404 with no content leak.
- concurrency: four simultaneous exports of one target produce four distinct
  artifacts and leave no temp files (`TransactionTestCase` + the project's
  SQLite WAL/`busy_timeout` retry convention, so the real single-writer
  behaviour is exercised).
- P1-016: snapshot and per-type `collect()` output contain only the exporting
  target's data; the export directory is id-keyed; metadata is present.
- Full regression: **377 tests + 48 subtests, all pass** (pre-P1-015/016: 358).
  `manage.py check` clean; no schema change.

## P2-003 — JS semantic diff correlation is complete and bidirectional (2026-09-28)

### What the audit found

`services/correlation/ingest.py::ingest_js` emitted semantic children only for
*additions*:

* only `set(new) - set(old)`, so a route, library or secret that **disappeared**
  produced no event at all — a silently shrinking attack surface looked
  identical to an unchanged one;
* secret candidates were not a correlated dimension on the change path: their
  events were emitted by `_store_js_findings` with **no parent event, no
  correlation id and no ScanRun**, so a secret found in a changed bundle could
  not be traced to the change or the scan that introduced it;
* a latent crash: `detect_js_libraries` returns `{"library": ..., "version": ...}`
  dicts, but the diff did `set(js.dependencies)` — *"unhashable type: dict"* —
  so **any** JS change that reached that line raised, and the child events were
  never emitted at all (the failure was logged, then swallowed by a bare
  `except`);
* `JavaScriptFinding` was keyed `(js, finding_type, location="body")`, so every
  occurrence of e.g. `aws_key` collapsed into one row: a **rotated credential
  was indistinguishable from an unchanged one**, and its old value could never
  be reported as gone.

### What was implemented

* `_emit_js_children` emits one child event per semantic delta, in **both**
  directions, for all three dimensions: `NEW_JS_ENDPOINT` /
  `JS_ENDPOINT_REMOVED`, `NEW_JS_LIBRARY` / `JS_LIBRARY_REMOVED`,
  `NEW_JS_SECRET_CANDIDATE` / `JS_SECRET_CANDIDATE_REMOVED` (new event types,
  wired into `EVENT_TYPE_CHOICES` and `SEVERITY_BY_EVENT`).
* Each child carries the **correct parent event, the parent's correlation id,
  the target, and the execution's ScanRun** (`_current_scan_run()`, P2-012), with
  `old_state`/`new_state` presence flags so the fingerprint distinguishes
  add from remove.
* `_js_dependency_keys` gives libraries a hashable `(name, version)` identity
  (fixing the crash).
* Secret identity is now **per distinct value**, not per type:
  `JavaScriptAsset.current_secret_keys` (new JSON field, migration
  `assets.0009_javascriptasset_current_secret_keys`, forward/backward/reapply
  verified) stores `{type: [sha256[:12], ...]}` for the *current* content — no
  secret material, only digests. Because the finding table is cumulative
  history, a removal can only be detected against this live snapshot.
  `JavaScriptFinding.location` now carries a value digest (`body@<digest>`) so
  two different credentials of the same type get distinct rows.
* A replaced credential is reported as add **and** remove, with the new
  candidate flagged `rotated: true`.
* `_store_js_findings(..., emit_events=False)` on the change path removes the
  duplicate, unparented secret event; on the new-file path it still emits.
* The parent `JS_CHANGED` event is updated with a `semantic_delta` summary
  (`{endpoints_added/removed, libraries_added/removed, secrets_added/removed}`),
  so a partially-correlated change is visible rather than assumed complete.

### Verification

`tests/test_js_correlation.py` — 11 tests: added route and added library emit
children; removed route and removed library are reported; secret candidates
added and removed are reported; a **rotated** credential is add+remove with
`rotated` set; every child carries the parent's correlation id, the right
target and `asset_type`; children and parent carry the active ScanRun; the
parent summarises the delta; unchanged content emits no children; findings for
a removed secret are retained as history; children never cross targets.
Full regression: **388 tests + 48 subtests, all pass** (pre-P2-003: 377).
`manage.py check` clean; `makemigrations --check` clean (new migration present).

## P2-004 — Global feeds and job/log surfaces leak no target data (2026-09-28)

### What the audit found

The **websocket** routing was already correct: `broadcast_event` /
`broadcast_job_like` send a target's payload only to `target_<id>`, the global
`events`/`jobs` groups receive target-less system messages only, and the consumer
authorizes membership *before* `group_add` and re-checks it on every delivery
with a `target_id` match guard.

The **HTTP job/log surfaces** were not. Every view in `apps/jobs/views.py`
applied a **role** check only, and queried the unscoped default managers:

| View | Before | Leak |
| --- | --- | --- |
| `job_list` | `ScanJob.objects...` (unscoped) | every target's job inventory |
| `job_detail` | `get_object_or_404(ScanJob, pk)` | any job by guessed id: target, tool, asset value, command, logs |
| `job_cancel` | unscoped | **any operator could cancel another target's job** |
| `job_retry` | unscoped | could re-trigger another target's scan |
| `log_list` | `JobLog.objects...` (unscoped) | every target's tool logs (hosts, commands, errors) |

`require_viewer`/`require_operator` check a *global role*; they never verified
membership in the job's target. Any authenticated user could read (and any
operator could act on) another tenant's execution history.

### Fixes

* `_authorized_job(request, pk, capability)` fetches the job from the **unscoped**
  manager and then enforces `require_capability` against its target — a security
  boundary implemented by an explicit check, not by ambient session state — with
  a `DENIED` structured log. `job_detail` requires `read`; `job_cancel` and
  `job_retry` require `operate`.
* `job_list` and `log_list` are filtered with `scope_queryset_for_user`
  (`JobLog` via its `job__target_id` path), so listings contain only authorized
  targets.
* A target-less system job is visible to global administrators only.
* `log_list` was implemented but **never routed**; it is now registered at
  `jobs/logs/` with the same scoping rather than left as dead, unscoped code.
* `JobLog` gained an explicit unscoped `objects` manager (it had none, so
  explicit filtering was impossible) — manager definitions only, no schema
  change.

### Verification

`tests/test_job_feed_privacy.py` — 13 tests:
- feed routing: a target event/job goes **only** to `target_<id>` (never the
  global group) and carries the right `target`/`target_id`; payloads are
  captured through a fake channel layer;
- HTTP: the job list, the job detail, the log list, cancel and retry all deny
  another target's data; walking the whole id space yields 200 only for the
  caller's own job; the foreign job is left untouched by a denied cancel;
  anonymous is rejected on every endpoint; an archived target still requires
  membership;
- websocket: the global feed rejects an anonymous handshake outright.
- Full regression: **401 tests + 48 subtests, all pass** (pre-P2-004: 388).
  `manage.py check` clean; `makemigrations --check` clean.

## P2-005/P2-007 — Target lifecycle: archive-first removal, centralized transitions (2026-09-28)

### What the audit found

`Target` already declared `ALLOWED_STATUS_TRANSITIONS` /
`ALLOWED_AUTH_TRANSITIONS`, `STATUS_ARCHIVED` and `archived_at` — and a comment
pointing at a `target_lifecycle.transition_to()` module **that was never
written**. Every writer went around the policy: views assigned
`target.status = ...` directly.

`target_delete` was a single POST with **no confirmation and no archive step**:
`t.delete()` hard-deleted the target and, by cascade, destroyed every historical
ScanRun, ScanJob, ToolExecution, AssetObservation, event and asset — the entire
evidence trail an engagement depends on, with no record that it happened.

### P2-005 — removal is archive-first

`apps/targets/target_lifecycle.py` (new):

* **`archive_target(target)`** — soft delete. `status=ARCHIVED`,
  `archived_at` stamped, the target stops being scannable, in-flight work is
  halted, and **every historical artifact survives** (verified per model in
  tests). A `TARGET_ARCHIVED` event records the decision.
* **`purge_target(target, confirmation=...)`** — hard delete, still available for
  genuine data-removal requests, but it (a) refuses to run unless
  `confirmation == "PURGE"`, (b) **halts all in-flight work first** so no
  worker can recreate rows mid-purge, and (c) returns a **manifest of exactly
  what it destroyed** (counts per model) which the view writes into the audit log.
* The view now **archives by default**: a `target-delete` POST without a
  confirmation token archives; `confirm=PURGE` hard-deletes; any other
  confirmation value is a 403 with an explanatory message.

### P2-007 — transitions are centralized and enforced

`transition_to(target, new_status=, new_auth=, reason=, actor=, force=)` is now
the single entry point:

1. **Illegal transitions raise `InvalidTransition` before any write**
   (e.g. `ARCHIVED -> PAUSED`); an unchanged value is an idempotent no-op.
2. **Required side effects always run**: halting in-flight work through the same
   kill switch the pause path uses (P0-013), re-queuing `PAUSED` jobs on resume,
   stamping `archived_at` (and clearing it on restore), emitting
   `AUTHORIZATION_EXPIRED` / `AUTHORIZATION_REAUTHORIZED` / `TARGET_ARCHIVED`,
   and a structured audit log line carrying actor, reason and the before/after.
3. **A real bug fixed here**: side effects were keyed on `new_status` alone, so an
   **authorization-only** change (expiry/withdrawal) did *not* halt in-flight
   work — a target could keep running live tools after its authorization lapsed.
   The halt now triggers whenever the target stops being scannable, whichever
   field caused it.
4. Pause/resume views go through the module (with `require_capability`) instead of
   raw assignment, so a target can no longer be flipped to a state the policy
   forbids.

### Verification

`tests/test_target_lifecycle.py` — 19 tests:
- archive keeps subdomains, ScanRuns, ScanJobs, AssetObservations and events, and
  emits `TARGET_ARCHIVED`; archiving halts in-flight work and cancels the live run;
  restore makes the target scannable again;
- purge is refused without/with a wrong confirmation (target untouched), and with
  `PURGE` returns a correct manifest and really destroys the rows; purge halts
  work first;
- view level: delete archives by default, `confirm=PURGE` hard-deletes, a wrong
  confirmation is 403 with no state change, a non-admin cannot delete, and
  pause/resume go through the policy;
- transitions: all legal pairs succeed, illegal pairs raise and leave the state
  unchanged, idempotent transitions are no-ops, authorization transitions are
  validated, expiry halts work and emits its event, re-authorization emits its
  own, resume re-queues paused jobs, and `force` bypasses the table but still
  writes.
- Full regression: **420 tests + 48 subtests, all pass** (pre-P2-005/007: 401).
  `manage.py check` clean; no schema change.

## P2-006 — Manual scans run through the canonical ScanRun orchestration (2026-09-28)

`target_scan` fired two loose tasks:

```python
if t.baseline_status != "BASELINE_COMPLETE":
    jt.baseline_target.delay(t.id)
else:
    jt.discover_subdomains.delay(t.id)
    jt.resolve_dns.delay(t.id)
```

so a "scan" was: no target authorization (role only), no scannable check, two
stage tasks that **each opened their own execution root**, and coverage of only
subdomains + DNS — while the UI implied a full scan. Jobs, tool executions and
observations were scattered across unrelated runs, and there was no accurate
status anywhere.

### `manual_scan` — one entry point, the full contract

`apps.jobs/tasks.py::manual_scan(target_id, requested_by)` now:

1. **authorizes** the target and records `requested_by` on the run;
2. **verifies scannable state** via `_gate` *before* dispatching anything
   (a paused/expired/archived target starts no work);
3. **creates/reuses one canonical ScanRun** (`scan_type=DISCOVERY`,
   `trigger=manual`) and hands **that run id to every stage**, so they join it
   instead of orphaning new roots;
4. **dispatches the full canonical chain** in order
   (subdomains -> DNS -> ports -> HTTP -> URLs), re-checking
   `is_scannable` before each stage and stopping with `CANCELLED` if the target
   is paused mid-scan;
5. **exposes accurate status**: the run ends `COMPLETED` / `PARTIAL` /
   `FAILED` using the same P0-017 aggregation (a failed required stage, a
   degraded stage, or lost evidence rows all produce the honest status), with
   the coverage summary attached to the run and the failed stage names on
   `error_summary`.

An incomplete baseline still routes through `baseline_target` (the baseline
chain *is* the canonical first scan, under the same single root).

### View + status surface

`target_scan` now requires the `operate` capability **on that target**, refuses
(audited) a non-scannable target instead of queueing work, and dispatches
`manual_scan`. A new `scan-run-detail` page
(`templates/jobs/run_detail.html`) shows the execution root's status, coverage
summary, jobs and tool executions — the traceable answer to "what happened in
my scan", membership-scoped like every other target surface.

### Verification

`tests/test_manual_scan_orchestration.py` — 13 tests: all stages receive the one
canonical run id and exactly one run exists; an incomplete baseline routes to the
baseline chain; a paused target and an expired authorization are refused with
zero jobs; a FAILED required stage yields a FAILED run; a PARTIAL stage yields
PARTIAL (never COMPLETED); the coverage summary is attached; a mid-chain pause
stops the chain and cancels the run; lost evidence downgrades the run; the view
dispatches the orchestrator with the caller's identity, denies a non-member
operator, refuses a paused target, and the run detail page is membership-scoped.
Full regression: **433 tests + 48 subtests, all pass** (pre-P2-006: 420).
`manage.py check` clean; no schema change.

## P2-008 — Duplicate prevention enforced in the database (2026-09-28)

### Audit result

The four invariants the taskbook names were already present:

| Invariant | Enforcement |
| --- | --- |
| Unique event fingerprint | `Event.fingerprint` `unique=True` + index |
| Unique target membership | `TargetMembership` `UniqueConstraint(user, target)` |
| One live scan run per (target, type) | `ScanRun` conditional `UniqueConstraint` on `status IN (PENDING, RUNNING)` |
| Asset-model duplicate prevention | `unique_together` on Subdomain, Port, URLAsset, APIEndpoint, HTTPService, IPAddress, DNSRecord, JavaScriptAsset, Technology, CVE |

Application validation alone is not sufficient for race-sensitive rules, so the
**audit also looked for invariants enforced only in Python** — and found three:

### Gaps closed

1. **`Asset` (the deduplicated inventory of everything known about a target) had
   no uniqueness at all.** `services/correlation/ingest.py::_asset` relies on
   `get_or_create(target, asset_type, value)`, which cannot prevent duplicates
   under concurrency: two ingesters can both observe "no existing row" and both
   insert. Now enforced by
   `uniq_asset_per_target_type_value (target, asset_type, value)`.
2. **`JavaScriptFinding` had no uniqueness**, while P2-003's semantic diff reads
   that table to decide what was added/removed — a duplicate row would corrupt
   the delta. Now `uniq_js_finding_per_js_type_location (js, finding_type,
   location)`, matching the finding identity the code already uses.
3. **`JSAnalysisJob` allowed two live analyses of the same asset.**
   `queue_js_analysis` checks for an existing `QUEUED`/`RUNNING` job, but that is
   check-then-act: two events for the same script could queue the same analysis
   twice and download/analyze the bundle concurrently. Now a conditional
   `uniq_live_js_analysis_per_asset (js) WHERE status IN (QUEUED, RUNNING)` —
   terminal jobs stay unconstrained so history is preserved.

### Production-safe migrations

Adding a unique constraint to a table that already contains duplicates **fails**,
so each migration deduplicates first, in the same migration:

* `assets/0010` — folds duplicate assets onto the **oldest** row and carries the
  duplicate's `discovered_by_job` provenance onto the survivor before deleting it
  (no evidence is lost), then folds duplicate JS findings;
* `jobs/0009` — keeps the **oldest** live JS analysis per asset and marks the
  rest `FAILED` with an explicit "superseded by an existing live analysis"
  reason (never silently dropped), then adds the constraint.

Both verified forward / backward / reapply; `makemigrations --check` is clean.

### Verification

`tests/test_db_constraints.py` — 21 tests, all at the **database** level
(`IntegrityError` on a duplicate insert, not an application check):
duplicate event fingerprints, duplicate memberships (while a second target's
membership is allowed), a second live ScanRun of the same type (while terminal
runs accumulate and different types coexist), duplicate assets (while the same
value under a different type or on a different target is allowed, and
`get_or_create` stays idempotent), duplicate JS findings, a second live JS
analysis (while finished analyses accumulate and different assets coexist), the
asset `unique_together` families (Subdomain/Port/URLAsset), and that history
models (ScanJob/ToolExecution) still allow many rows. The dedupe migration
functions are additionally tested against model-shaped stand-ins carrying real
duplicates, asserting the oldest survives, provenance is inherited and nothing
is silently dropped.
Full regression: **454 tests + 48 subtests, all pass** (pre-P2-008: 433).

## P2-009/P2-010 — Security regression suite, architectural invariants, and a real leak closed (2026-09-28)

### A cross-target leak found by the suite

`apps/assets/views.py::scoped_queryset` — the single helper behind every asset
list view — returned the queryset **unchanged when no `?target=` was supplied**:

```python
target_id = request.GET.get("target", "")
if not target_id:
    return qs, "", ""          # <- every asset in the installation
```

The target *picker* was correctly membership-scoped (`_ctx_targets`), which is
why the bug was invisible: the user could only *choose* their own targets, yet
the "All targets (overview)" table underneath listed **every target's assets**
to any authenticated user. It is now scoped to the caller's authorized targets,
and an explicit `?target=` is validated through `get_authorized_target` (an
unowned id yields an empty page + a notice instead of silently answering).

`tests/test_asset_views.py` had encoded the leak: its viewer had **no
memberships** and asserted it could see both targets' rows. The viewer is now
granted membership on both (so those expectations still hold legitimately), and
the isolation property itself is asserted in the new suites.

### P2-010 — the ten architectural invariants, encoded

`tests/test_architectural_invariants.py` — 25 tests, one class per invariant,
numbered as in the taskbook:

1. every target-specific artifact belongs to one target (assets, observations);
2. parent/child execution artifacts cannot cross targets (ScanJob->ScanRun,
   ScanJob->parent, JSAnalysisJob->JavaScriptAsset, and `_get_or_create_run`
   rejecting a foreign run id);
3. unauthorized users cannot retrieve target data (API + views);
4. partial scans cannot create removal events;
5. paused/expired/archived targets cannot start new work;
6. ScanRun is the canonical root (a whole chain shares one run; every child row
   is reachable from it);
7. event fingerprints are unique (DB-level and via `emit_event`);
8. TLS policy is consistent — checked by **AST**, not substring, so the
   `CERT_NONE` in a docstring describing the removed defect is not mistaken for
   insecure configuration, and the only real `CERT_NONE` left is the explicit
   `verify_tls=False` opt-out in `_ssl_context_for`;
9. exports are target-specific;
10. tool failures cannot be represented as complete coverage.

### P2-009 — the consolidated security regression suite

`tests/test_security_regression.py` — 18 tests, one class per required area,
asserted end to end against real models/views/tasks:
cross-target views, APIs, websockets and exports; object-id guessing; SSRF and
redirect-hop revalidation; DNS rebinding; TLS; pause/cancellation; authorization
expiry; cross-target model relationships; duplicate ScanRuns; duplicate events.

### Verification

Full regression: **497 tests + 48 subtests, all pass** (pre-P2-009/010: 454).
`manage.py check` clean; `makemigrations --check` clean.

## P2-011/P2-012/P2-013 — Structured execution logs, correlation, secret hygiene (2026-09-28)

### P2-011 — one structured shape for every major stage

Stage logging was ad-hoc `logger.error("... %s", e, extra={...})` at nine call
sites, with no common field set. There is now one emitter,
`_log_stage_event(...)`, and a context manager `_StageTimer` that emits a
START/OK|ERROR pair per stage. Every record carries the required fields as
**structured extras** (not interpolated into the message, so a log processor can
index them): `target_id`, `scan_run_id`, `job_id`, `stage`, `tool`, `status`,
`duration_ms`, `error`, `operation`.

It is wired into the stages that actually run for minutes and matter:
`scan_ports` (whole stage + a nested per-tool line), `probe_http` (httpx),
`discover_subdomains` (per source tool), each baseline and manual-scan stage,
and the `baseline:start/finish` / `manual_scan:start/finish` run lifecycle lines
carrying the final status and duration.

**Secrets are never logged**: on an exception the `error` extra carries the
*exception class name* only, never the message (which may embed a token), and
messages carry identifiers, never raw tool output.

### P2-012 — correlation end to end

The chain `ScanRun -> ScanJob -> JSAnalysisJob -> ToolExecution ->
AssetObservation -> Event` is now asserted end to end: an observation created
inside a scan context carries the run, the job *and* the tool execution; the
event carries the run and a `correlation_id`; JS semantic children inherit the
parent's `correlation_id` (P2-003); `requested_by` is recorded on the run.

### P2-013 — a real redaction gap found and fixed

Synthetic-secret tests against `services/redaction.py` exposed that the AWS-key
pattern required **exactly** 16 characters after the prefix, so a longer key
(`AKIA…SECRET`, or any of the other AWS key-id prefixes) was written verbatim to
the evidence store. The pattern now covers `AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA`
with 12–40 trailing characters.

Proven for the whole persistence path: tool stdout/stderr references on disk,
the persisted command line, `Event.evidence` (a JS secret-candidate event
carries the *type*, never the value), operator-visible `JobLog` messages, and
exported snapshots (which list asset URLs but no secret material).

### Verification

`tests/test_observability.py` — 14 tests: every required structured field is
present on a stage event; the timer emits START/OK with a duration; an exception
is reported with the class name only (the message, which contained a token, is
not logged); a real `scan_ports` run emits the stage pair; `manual_scan` logs
start and finish with status and duration; the run→job→tool→observation→event
chain is linked and children inherit the correlation id; and the six
secret-hygiene properties above.
Full regression: **511 tests + 48 subtests, all pass** (pre-P2-011/012/013: 497).
`manage.py check` clean; `makemigrations --check` clean.

## P3-001/P3-002/P3-003/P3-004/P3-006 — Code-quality and documentation audits (2026-09-28)

### P3-001 — unscoped lookups: three real authorization holes closed

| Site | Before | Now |
| --- | --- | --- |
| `apps/targets/views.py::target_detail` | `@require_viewer` + `get_object_or_404(Target, pk=pk)` — **no membership check**, so any viewer could read any target's assets, pipeline and scan history by id | `get_authorized_target(user, pk, "read")` |
| `apps/targets/views.py::target_edit` | same — and it **edits** another tenant's target (scope, authorization, schedule) | `get_authorized_target(user, pk, "manage")` |
| `apps/core/context_processors.py` | `Target.objects.all()[:200]` + `Target.objects.get(pk=tid)` in the **context processor**, so every page's sidebar leaked the target inventory, and `?target=<other id>` pinned it in the session | picker lists only authorized targets; an unowned `active_target_id` is ignored and cleared |

System/worker lookups (`Target.objects.get(pk=target_id)` in Celery tasks) are
**intentionally unscoped** — a worker has no request — and are safe because every
stage is gated on `Target.is_scannable` before doing work. That gate is now pinned
by a test rather than assumed.

A duplicated `@require_operator` decorator on `target_pause` was also removed.

### P3-002 — arbitrary limits: every truncation classified, coverage holes closed

Most `[:N]` in the codebase are **string-length truncations** (error text, log
lines) and are fine. The real *processing* limits were silently dropping scan
work:

* `resolve_dns`: `[:2000]` on active subdomains — hosts past #2000 were never
  resolved, with no record. Now paginated in keyset batches
  (`DNS_HOST_BATCH_SIZE`) over the **full** set.
* `scan_ports`: `[:500]` on active IPs and `[:500]` on the shared-suspect
  set — now the full set. (The suspect set in particular is a **safety** filter:
  capping it would actively scan unconfirmed shared IPs.)
* `probe_http`: `[:1000]` on subdomains and `[:1000]` on open ports when
  building candidates — now every host/port contributes a candidate; the probing
  *work* stays bounded by the reported `HTTP_FALLBACK_MAX_URLS` cap.

Remaining limits are classified in code and pinned by a test: display limits
(dashboard previews, the target picker, per-URL crawl samples, the diff view) and
named/reported processing constants (`PORT_FALLBACK_MAX_PORTS`,
`HTTP_FALLBACK_MAX_URLS`, `CVE_CORRELATION_BATCH_SIZE`, `RECONCILE_BATCH_SIZE`,
`JS_RECHECK_BATCH_SIZE`, `DNS_HOST_BATCH_SIZE`).

### P3-003 — Port model

`Port.state` was **declared twice** (identical definitions, so no migration
drift was visible). The duplicate is removed; `makemigrations --check` stays
clean, and port uniqueness/state behaviour is now tested directly.

### P3-004 — stale repository URL

`README.md` and `docs/setup.md` cloned `github.com/Abdo-Badawi/recon-monitor`;
both now point at `https://github.com/Abdulrahman-Ashraf161/recon-monitor`.

### P3-005/P3-007 — credentials and Docker (verified compliant)

* No `admin/admin` anywhere: `scripts/setup.sh` generates a random password
  (`secrets.token_urlsafe(16)`) unless `ADMIN_PASSWORD` is explicitly provided,
  and the profile carries `must_change_password` enforced on first login.
* `docker/docker-compose.yml` requires every secret via `${VAR:?...}` (the stack
  refuses to start with a missing/empty value), `.env` is gitignored and
  untracked, and production settings hard-fail on a placeholder `SECRET_KEY`,
  `DEBUG`, wildcard `ALLOWED_HOSTS`, or insecure cookie settings.

### P3-006 — architecture documentation

`docs/ARCHITECTURE.md` claimed *"Single-tenant: all users see all targets"* and
that tasks carried a free-form `run_id`. Both were stale. It now documents the
membership model (`User -> TargetMembership -> Target -> ScanRun -> ScanJob ->
ToolExecution -> AssetObservation -> Event -> Alert`), the canonical execution root
and its partial unique index, heartbeat liveness, the per-target authorization
API, the lifecycle/archive/purge policy, the reconciliation proof rule, and the
evidence/coverage contract.

### Verification

`tests/test_code_quality_audit.py` — 16 tests: target detail/edit require
membership (including a POST that must not mutate a foreign target), the context
processor exposes only authorized targets and refuses an unowned active id, a
static AST audit proving no *executed* `get_object_or_404(Target, …)` lacks an
authorization call, worker lookups are gated (a paused target starts no tool), the
DNS stage resolves every host across batches, the port scan probes every active
IP, the shared-suspect set is uncapped, display limits are still bounded, no
duplicate model field declarations exist, and port uniqueness/state are enforced.
Full regression: **527 tests + 48 subtests, all pass** (pre-P3: 511).
`manage.py check` clean; `makemigrations --check` clean.

## P3-009/P3-010 — Deterministic fixtures and the complete end-to-end test (2026-09-28)

### P3-009 — fixtures (verified complete)

`tests/fixtures.py` provides reusable, non-TestCase-bound factories for every
required entity: admin, user A/B, target A/B, membership grants, `make_world()`
(the canonical two-user/two-target world), `make_scan_run`, `make_scan_job`,
`make_tool_execution`, `make_observation`, `make_event`, `make_alert`,
`make_export_job` and `seed_assets_for(target, marker)` (one of every asset
type, all tagged with a marker so cross-target mixing is provable).

### P3-010 — the full end-to-end scenario

`tests/test_end_to_end.py` walks the taskbook's 14 steps against real models,
real orchestration, real views and real channel routing (only the external tool
binaries are absent, which is why tool invocations are stubbed at the
`ToolExecution` boundary — every persistence, authorization and lifecycle path
around them is the production one):

1–2. two targets; User A is granted **only** A.
3–4. `manual_scan` on A; the full chain is asserted:
`ScanRun` (canonical root, `trigger=manual`, `requested_by` set, COMPLETED) ->
`ScanJob`s (all on A, all attached to that run) -> `ToolExecution`s (command,
timestamps, duration, status) -> `AssetObservation`s (on A, attached to the run,
**and at least one linked to a tool execution**) -> `Event`s (on A; **none on B**);
assets landed on A only.
5. A cannot reach B through the detail view, the unpinned subdomain list, or the
   API; A's own data is visible.
6. pausing A through the lifecycle module makes `is_scannable` false, the
   orchestrator returns `SKIPPED`, and the stage short-circuits inside its own
   gate before any tool work.
7–8. resuming A restores scannability, and a second scan opens a **new** run.
9–10. a snapshot export is generated and contains A's data and no trace of B.
11–14. the async websocket test asserts an anonymous socket is rejected, a
non-member cannot authorize, and a target event is broadcast **only** to
`target_<id>` (the consumer checks membership before `group_add` and re-checks on
every delivery).

Full regression at this point: **529 tests + 48 subtests, all pass**. `manage.py
check` and `makemigrations --check` clean.

---

## Final verification (Sections 22–23)

After the end-to-end work, a further round of verification was executed, and it
found **two real production defects** that only a live stack could expose:

1. `docker/docker-compose.yml` set `DJANGO_SETTINGS_MODULE: production`, which is
   not an importable module — every container in the documented deployment died
   with `ModuleNotFoundError: No module named 'production'`. Fixed to the dotted
   path `config.settings.production` (compose + `docs/deployment.md`).
2. There was **no `.dockerignore`**, so `COPY . .` baked the developer's
   virtualenv, SQLite database, generated evidence, `.git` and the real `.env`
   secret file into the production image. Created, with the `!.env.example`
   negation ordered last (last-match-wins).

Both are now pinned by `tests/test_deployment_artifacts.py` (12 tests).

FINAL-003 also fixed genuine defects surfaced by the linters: a duplicate
`"target"` dict key in `apps/targets/views.py` (`F601`, silently shadowed), a
loop-variable capture in `tests/test_manual_scan_orchestration.py` (`B023`),
three `logger.error(..., exc_info=True)` calls (`G201`), and two variable-shadowing
errors in `apps/jobs/tasks.py` (mypy `misc`).

FINAL-004 verified every app's migrations are reversible and re-appliable
(zero→head→zero→head for targets, jobs, assets, events, monitoring, accounts) and
that a clean database initialises, on SQLite **and** PostgreSQL 16.

FINAL-005/006/007 stood up the real production stack — Postgres 16, Redis 7,
Daphne (ASGI), Celery worker, Celery beat — and verified, live: login, target
creation, membership, target detail/changes, jobs, events and exports pages;
cross-target 403s for an outsider; export download 403 for an outsider and 200
for the owner with no filename or domain leak; WebSocket 101 for the owner and 403
for anonymous **and** for an outsider on another tenant's target stream; SSRF
denial of loopback/private/link-local/metadata/non-HTTP-scheme URLs; strict TLS by
default with `CERT_NONE` only on explicit opt-in; archive-first lifecycle with
`confirm=PURGE`; the kill switch returning `SKIPPED` for an archived target; a
real `manual_scan` producing one `ScanRun`, five `ScanJob`s, honest `PARTIAL`
stages and `BASELINE_PARTIAL`; the Celery queue path (task consumed and executed
by the worker); and beat dispatching its five schedules on time.

`pytest.ini` was added so `python -m pytest tests/` works as well — the suite is a
Django suite and pytest previously failed collection with `ImproperlyConfigured`
because no settings module was declared.

A further tooling pass established that the repository had **no linter
configuration at all** — no `ruff.toml`, `.flake8`, `mypy.ini` or `pyproject.toml` —
so every tool ran on its own defaults and reported Django-idiomatic code as
errors. `ruff.toml`, `.flake8`, `mypy.ini` and `pyproject.toml` were added, all
held to a consistent 100-column limit so they cannot contradict each other, and
every suppression justified inline in the config itself.

That pass also surfaced real defects: a duplicate class definition in
`apps/core/consistency.py` (a mixin and the concrete class shared the name
`ConsistentTargetScopedQuerySet`, so the second silently shadowed the first); a
hardcoded world-writable `/tmp/cvelistV5` clone path in the CVE sync task; three
`Http404` raises that chained a `DoesNotExist` and so could confirm absence; a
`DiscordBatch` send failure whose error was computed then discarded, leaving a
`FAILED` batch undiagnosable; and `dict(zip(header, row))` in the JSON export
renderer, which would silently zero-fill a short row or drop values from a long
one and so write a corrupted evidence artifact.

`black` was then adopted (line-length 100) as a dedicated formatting pass, which
cleared the remaining flake8 continuation-indent findings.

Final tool state: **mypy, ruff, flake8 and black all pass with zero findings.**

The compose file was additionally validated with the real
`docker-compose.exe` v2.39.2 binary (`config --quiet` exit 0, resolved
`DJANGO_SETTINGS_MODULE=config.settings.production` on all three app services),
and its required-secret guard was confirmed to refuse to start when
`DJANGO_SECRET_KEY` is absent.

Finally, real recon binaries (`httpx`, `naabu`, `katana`) were installed and a
live `manual_scan` was run over a public test domain: 1150 subdomains, 1151
events, 1151 scan jobs, 4 tool executions COMPLETED and `crtsh` FAILED with
HTTP 502. That failure is the intended P1-003 behaviour — the error was recorded
on the `ToolExecution` row and the stage degraded rather than reporting a clean
success. See `docs/FINAL_REPORT.md` §7.

### Late finding: P0-003 was not actually satisfied

Auditing the task table against the taskbook revealed that P0-001..P0-011 and
P2-001/P2-002 had never been enumerated in the report, and that **P0-003 was
genuinely broken**: `/targets/` and `/scope/` returned another tenant's target
domain to a logged-in user holding no membership.

`TargetScopedManager.get_queryset()` applies no filter of its own — scoping only
happens when `.for_user()` is called explicitly — so `Target.objects.all()` in a
view is an unfiltered cross-tenant read even though the manager looks scoped.
Object detail pages were correctly 403 and `/api/targets/` was correctly scoped
and tested, which is why the existing isolation tests did not catch it.

Both views now use `authorized_targets()` / `scope_queryset_for_user()`, the same
helpers the API viewset uses. `UnscopedDefaultManagerTests` and
`AllPagesLeakSweepTests` (which enumerates the live URL conf and probes every
page as a non-member) pin it; both were verified to fail when the fix is
reverted.

**Final state: 560 tests pass under both runners, 0 failures, 0 errors, 0 skipped.**
Full report, including all remaining issues and their impact, is in
[`docs/FINAL_REPORT.md`](FINAL_REPORT.md).
