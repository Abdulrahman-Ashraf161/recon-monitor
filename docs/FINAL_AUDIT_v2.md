# FINAL AUDIT v2 — Recon Monitor post-audit hardening (tasks.md, Tasks 1–34)

Date: 2026-09-26. Supersedes `docs/FINAL_AUDIT.md` (kept for history with a
top-note; its inaccuracies are listed there). Every claim below cites an
enforcing test as `tests.<module>.py::<Class>::test_<name>`; anything without
a citation is labeled **manually verified, not CI-enforced**.

Citation check loop (translates `::` to Django labels):

```bash
grep -oE "tests\.[a-z_.]+\.py::[A-Za-z_]+::test_[a-z_0-9]+" docs/FINAL_AUDIT_v2.md \
  | sed 's/\.py::/./; s/::/./g' | sort -u \
  | while read t; do python manage.py test "$t" -v 0 || echo "BROKEN CITATION: $t"; done
```

## 1. Scope hardening (Tasks 1–5)

- URL/crawl pipeline scope-validates every host before persisting
  (ingest_urls → validate_host; out-of-scope canonical hosts are logged and
  skipped): tests.test_target_isolation.py::TargetIsolationTests::test_ingest_urls_rejects_out_of_scope_host,
  tests.test_target_isolation.py::TargetIsolationTests::test_ingest_urls_keeps_in_scope_host.
- `<script src>` fetches are scope-checked in both JS paths via one shared
  helper (no fetch for third-party/CDN/planted hosts):
  tests.test_target_isolation.py::JsScopeTests::test_out_of_scope_script_not_fetched.
- All stdlib fetches honor target.verify_tls (True = validating context;
  False = insecure + explicit WARNING log):
  tests.test_platform.py::TlsContextTests::test_verify_true_gives_validating_context,
  tests.test_platform.py::TlsContextTests::test_verify_false_gives_insecure_context_with_log.
- Private/reserved IPs blocked unconditionally (metadata, loopback, RFC1918,
  CGNAT, IPv6-mapped loopback; fail-closed on garbage):
  tests.test_security_isolation.py::SsrfProtectionTests::test_ssrf_metadata_ip_blocked,
  tests.test_security_isolation.py::SsrfProtectionTests::test_ssrf_loopback_and_rfc1918_blocked.
- Shared-infrastructure IPs need confirmed_dedicated before port scans
  (first claimant unaffected; IPv6-mapped forms normalized):
  manually verified via shell (T5 session: shared_suspect True/False +
  process_new_ip → shared_ip_unconfirmed), not CI-enforced.
- Validator allow/exclude branches (domains, wildcard, IP lists, scan gating,
  unresolvable + obfuscated-IP edge cases):
  tests.test_platform.py::ScopeRulesTests::test_allow_domain_and_wildcard,
  tests.test_platform.py::ScopeRulesTests::test_exclude_host_wins,
  tests.test_platform.py::ScopeRulesTests::test_ip_allow_exclude_lists,
  tests.test_platform.py::ScopeRulesTests::test_scope_allows_scan_states,
  tests.test_platform.py::ScopeRulesTests::test_resolve_check_unresolvable_and_obfuscation,
  tests.test_platform.py::ScopeRulesTests::test_resolve_check_blocked_and_public.

## 2. Isolation (Tasks 6–8)

- TargetScopedManager is the default `objects` on all 24 target-owned models
  (+ `all_objects` escape hatch; zero plain default managers; no migrations):
  manually verified via shell (T6 session), not CI-enforced.
- Detail views deny on explicit/session context mismatch (403); fresh-session
  global detail stays 200 under SINGLE_TENANT_ALL_TARGETS=True:
  tests.test_target_isolation.py::DetailContextTests::test_detail_view_without_target_param_on_fresh_session,
  tests.test_target_isolation.py::DetailContextTests::test_explicit_target_mismatch_denied,
  tests.test_target_isolation.py::DetailContextTests::test_session_context_mismatch_denied,
  tests.test_security_isolation.py::IDORTests::test_detail_context_mismatch_denied,
  tests.test_security_isolation.py::IDORTests::test_api_target_filter_isolates.
- `?target=` validated (non-numeric/nonexistent → empty page + notice, never 500):
  tests.test_asset_views.py::AssetViewsTests::test_invalid_target_param,
  tests.test_asset_views.py::AssetViewsTests::test_nonexistent_target_param,
  tests.test_asset_views.py::AssetViewsTests::test_invalid_page_param,
  tests.test_asset_views.py::AssetViewsTests::test_page_overflow_clamps.
- js_list totals honor target scope:
  tests.test_asset_views.py::AssetViewsTests::test_js_q_and_scoped_totals.
- List-view parity before/after the Task 20 DRY refactor (all params):
  tests.test_asset_views.py::AssetViewsTests::test_subdomain_default_and_target,
  tests.test_asset_views.py::AssetViewsTests::test_subdomain_q_filter,
  tests.test_asset_views.py::AssetViewsTests::test_port_state_and_q,
  tests.test_asset_views.py::AssetViewsTests::test_http_status_and_q,
  tests.test_asset_views.py::AssetViewsTests::test_url_source_and_q,
  tests.test_asset_views.py::AssetViewsTests::test_api_q_and_target,
  tests.test_asset_views.py::AssetViewsTests::test_tech_q_and_target,
  tests.test_asset_views.py::AssetViewsTests::test_cve_status_and_q,
  tests.test_asset_views.py::AssetViewsTests::test_finding_severity_and_status,
  tests.test_asset_views.py::AssetViewsTests::test_ip_target.

## 3. Lifecycle (Tasks 9–11)

- IP + API reconciliation (IP_REMOVED / API_ENDPOINT_REMOVED; live-DNS-gated IP keep):
  tests.test_reconciliation.py::IpApiReconciliationTests::test_ip_reconciliation_marks_removed,
  tests.test_reconciliation.py::IpApiReconciliationTests::test_ip_with_live_dns_record_kept,
  tests.test_reconciliation.py::IpApiReconciliationTests::test_api_endpoint_reconciliation_marks_removed.
- Re-observed URLs/APIs bump last_seen:
  tests.test_reconciliation.py::UrlLastSeenTests::test_reingest_bumps_last_seen.
- No-baseline gate + configurable grace:
  tests.test_reconciliation.py::ReconcileGraceTests::test_no_baseline_yet_skipped,
  tests.test_reconciliation.py::ReconcileGraceTests::test_custom_grace_respected.
- Subdomain NEW/REMOVED/REACTIVATED (no false NEW):
  tests.test_reconciliation.py::SubdomainLifecycleTests::test_new_removed_reactivated_no_false_new.

## 4. Integrity (Tasks 12–14)

- Malformed URL never aborts batch:
  tests.test_platform.py::IngestRobustnessTests::test_malformed_url_does_not_abort_batch.
- dnsx/httpx via adapter.run(hosts) (stdin piped, redacted cmd stored, no inline
  subprocess left): tests.test_platform.py::ToolFailureTests::test_missing_binary_skipped;
  `grep subprocess.run(\[adapter.binary` is empty (manually verified, not CI-enforced).
- Technology/Finding/CVE dual-write parity:
  manually verified via shell (T14a session: TECHNOLOGY/FINDING counts match), not CI-enforced.

## 5. Deploy (Tasks 15/16/26–29)

- Production refuses wildcard ALLOWED_HOSTS / ephemeral SECRET_KEY; passes with both:
  manually verified via shell (three-state check, T15/T16 session), CI-enforced by
  `.github/workflows/deploy-smoke.yml` (not run here — no CI runner in this env).
- Compose: production module on web/worker/beat + fail-fast vars + example envs:
  manually verified via YAML parse (daemon/compose plugin unavailable in this env),
  live `up` covered by deploy-smoke CI.
- Random setup admin password + forced change:
  tests.test_security_isolation.py::MustChangePasswordTests::test_forced_change_redirect_and_clear,
  tests.test_security_isolation.py::MustChangePasswordTests::test_normal_users_unaffected.
  (`setup.sh` end-to-end (rm db + run) is manual — venv/network dependent here.)
- New targets default PENDING / not scannable; existing AUTHORIZED rows untouched
  (AlterField default-only migration); form requires confirmation/expiry:
  tests.test_platform.py::AuthorizationDefaultTests::test_new_target_defaults_to_not_scannable,
  tests.test_platform.py::AuthorizationDefaultTests::test_existing_authorized_unaffected,
  tests.test_platform.py::AuthorizationDefaultTests::test_form_requires_confirmation_for_authorized.

## 6. Perf (Task 17)

- counts() cached 60s/target (11 queries → 0 on hit; staleness labeled in UI):
  manually verified via shell (CaptureQueriesContext, T17 session), not CI-enforced.
- Measured coverage (full suite, 2026-09-26): validator 92% (bar: 85%),
  ingest 61%, target_scoping 42%, TOTAL 62%. Validator bar met; ingest/scoping
  gaps are network/tool paths exercised only in production-like runs.

## 7. AuthN/realtime (Tasks 18/19/31)

- Anonymous sockets closed on all routes; authed accepted; target sockets join
  only their group; broadcasts target-only; global jobs carry no target keys;
  disconnect discards groups:
  tests.test_websocket.py::WebSocketAuthTests::test_anonymous_rejected_global_events,
  tests.test_websocket.py::WebSocketAuthTests::test_anonymous_rejected_global_jobs,
  tests.test_websocket.py::WebSocketAuthTests::test_anonymous_rejected_target_route,
  tests.test_websocket.py::WebSocketAuthTests::test_authenticated_accepted_global,
  tests.test_websocket.py::WebSocketAuthTests::test_authenticated_target_socket_only_own_group,
  tests.test_websocket.py::WebSocketIsolationTests::test_a_socket_never_receives_b_broadcast,
  tests.test_websocket.py::WebSocketIsolationTests::test_target_socket_receives_own_broadcast,
  tests.test_websocket.py::WebSocketIsolationTests::test_global_jobs_has_no_target_for_linked_jobs,
  tests.test_websocket.py::WebSocketIsolationTests::test_disconnect_discards_groups.
- asgi AuthMiddlewareStack present (Task 19): manually verified via grep, not CI-enforced.

## 8. Redaction/supply-chain (Tasks 23–25/28)

- redact_command (separate-arg, header, userinfo; benign preserved):
  tests.test_platform.py::RedactionTests::test_separate_arg_secret_redacted,
  tests.test_platform.py::RedactionTests::test_header_secret_redacted,
  tests.test_platform.py::RedactionTests::test_url_userinfo_redacted,
  tests.test_platform.py::RedactionTests::test_benign_command_preserved.
- Artifact containment + TOOL_BIN_DIR pinning: manually verified via shell
  (T23/T24/T25 session: ValueError on /etc/passwd, pinned resolution), not CI-enforced.
- requirements.lock.txt ships; Dockerfile installs it; pip-audit clean
  ("No known vulnerabilities found", run 2026-09-26); security.yml CI added.

## 9. Pre-existing behavior (still green)

- tests.test_platform.py::ScopeValidationTests::test_subdomain_allowed_and_excluded,
  tests.test_platform.py::NormalizationTests::test_host_normalization,
  tests.test_platform.py::NormalizationTests::test_url_canonicalization_and_api,
  tests.test_platform.py::EventDedupTests::test_fingerprint_dedup,
  tests.test_platform.py::BaselineSuppressionTests::test_baseline_suppresses_new_alerts_but_persists_events,
  tests.test_platform.py::CVEMatcherTests::test_version_in_range,
  tests.test_platform.py::DiscordRedactionTests::test_secrets_redacted,
  tests.test_platform.py::IngestTests::test_ingest_subdomains_creates_event,
  tests.test_platform.py::IngestTests::test_js_change_detection,
  tests.test_platform.py::IncrementalChainTests::test_new_subdomain_triggers_downstream_job_with_context,
  tests.test_platform.py::IncrementalChainTests::test_fanout_coalesces_while_running,
  tests.test_platform.py::IncrementalChainTests::test_duplicate_url_no_new_event,
  tests.test_platform.py::JSAnalysisTests::test_new_js_queues_analysis_and_logs_stages,
  tests.test_platform.py::JSAnalysisTests::test_changed_js_reanalyzed,
  tests.test_platform.py::DiscordFailureTests::test_discord_failure_keeps_event_and_marks_failed,
  tests.test_platform.py::ExportTests::test_txt_and_snapshot_exports,
  tests.test_target_isolation.py::TargetIsolationTests::test_asset_never_in_other_query,
  tests.test_target_isolation.py::TargetIsolationTests::test_event_never_in_other_dashboard,
  tests.test_target_isolation.py::TargetIsolationTests::test_scan_never_updates_other,
  tests.test_target_isolation.py::TargetIsolationTests::test_report_single_target,
  tests.test_target_isolation.py::TargetIsolationTests::test_alert_contains_own_target,
  tests.test_target_isolation.py::TargetIsolationTests::test_cross_target_reference_rejected,
  tests.test_target_isolation.py::TargetIsolationTests::test_websocket_groups_isolated,
  tests.test_security_isolation.py::ConcurrencyIsolationTests::test_two_targets_simultaneous,
  tests.test_security_isolation.py::IntegrationPipelineTests::test_discovery_to_event_chain,
  tests.test_reconciliation.py::DiffEngineTests::test_added_removed_changed,
  tests.test_reconciliation.py::DiffEngineTests::test_event_fingerprint_state_aware,
  tests.test_reconciliation.py::DiffEngineTests::test_http_fingerprint_stable,
  tests.test_reconciliation.py::ChangeScenarioTests::test_ip_change_old_new,
  tests.test_reconciliation.py::ChangeScenarioTests::test_http_200_to_403,
  tests.test_reconciliation.py::ChangeScenarioTests::test_js_semantic_children,
  tests.test_reconciliation.py::ChangeScenarioTests::test_url_normalization_dedup,
  tests.test_reconciliation.py::ChangeScenarioTests::test_cve_candidate_not_confirmed.

## 10. Known limitations (not hidden)

1. ScanRun/ToolExecution/AssetObservation helpers exist but legacy per-asset tasks
   don't all write rows yet — ScanJob remains universal; no data loss.
2. Single-tenant: no per-user target ACL (SINGLE_TENANT_ALL_TARGETS=True documents it).
3. Nuclei template↔CVE mapping heuristic; candidates stay candidates until validation.
4. CVE KB snapshot/rules-based, not live NVD.
5. Generic Asset table coexists with typed tables by design (T14b scheduled separately).
6. Full suite ~3 min (eager celery + network-guarded paths); prod needs Redis workers.
7. T4 validate_ip blocks private ranges unconditionally — lab/internal targets on
   RFC1918/link-local space CANNOT be scanned without a code change (explicit
   Task 4 requirement; surfaced here so operators aren't surprised).
8. counts() may lag writes by ≤60s (labeled in dashboard).
9. Live `docker compose up` + CI workflows not executed in this environment
   (no compose plugin/daemon, no runner) — covered by deploy-smoke.yml in CI.

## 11. Verdict

COMPLETE with the limitations above. All 34 tasks implemented, verified per their
acceptance criteria (CI-enforced where cited, shell/manual where labeled), full
suite green (93/93 on Django 6.1 and spot-checked on Django 5.2), ruff 302
(baseline 311; all import rules clean, remainder is pre-existing
try-except/subprocess idiom), bandit 0 High / 6 Medium (urlopen-audit +
one pre-existing tmp-dir; fetch paths are scope/SSRF/scheme-gated) /
40 Low, pip-audit clean on requirements.lock.txt.
