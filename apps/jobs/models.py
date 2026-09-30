"""Scan job tracking + structured logs."""

from typing import ClassVar

from django.db import models

from apps.core.consistency import (
    ConsistentTargetScopedManager,
    HeartbeatMixin,
    TargetConsistencyMixin,
)
from apps.core.target_scoping import TargetScopedManager


class ScanJob(HeartbeatMixin, TargetConsistencyMixin, models.Model):
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_FAILED = "FAILED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_PAUSED = "PAUSED"
    STATUS_SKIPPED = "SKIPPED"
    # P0-013: a job stopped because the target was paused / authorization
    # lapsed. Distinct from CANCELLED (operator-initiated) so audits can tell
    # an operator abort from a kill-switch trip.
    STATUS_CANCELLED_KILL_SWITCH = "CANCELLED_KILL_SWITCH"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"),
        (STATUS_PARTIAL, "Partial"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_PAUSED, "Paused"),
        (STATUS_SKIPPED, "Skipped"),
        (STATUS_CANCELLED_KILL_SWITCH, "Cancelled (target kill switch)"),
    ]
    # Terminal states: no further work may be scheduled from them.
    TERMINAL_STATUSES = frozenset(
        {
            STATUS_COMPLETED,
            STATUS_PARTIAL,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_CANCELLED_KILL_SWITCH,
        }
    )
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="jobs")
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children"
    )  # which job triggered this one
    asset_type = models.CharField(max_length=32, default="", blank=True, db_index=True)
    asset_value = models.CharField(max_length=1024, default="", blank=True)
    trigger = models.CharField(
        max_length=32, default="manual", db_index=True
    )  # manual/scheduled/event/baseline/reconcile
    job_type = models.CharField(
        max_length=64, db_index=True
    )  # subdomain_enum/dns/ports/http/urls/js/tech/cve/nuclei/reconcile/baseline
    stage = models.CharField(max_length=64, default="", blank=True)
    current_stage = models.CharField(max_length=64, default="", blank=True, db_index=True)
    tool = models.CharField(max_length=64, default="", blank=True)
    # max_length=32: STATUS_CANCELLED_KILL_SWITCH is 24 chars (fields.E009).
    status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True
    )
    progress = models.IntegerField(default=0)
    command_redacted = models.TextField(default="", blank=True)
    # P0-009: real FK — the canonical execution root. Replaces the free-form
    # `run_id` string that no FK constraint could protect. `run_id_legacy`
    # retains the pre-migration value verbatim for audit.
    scan_run = models.ForeignKey(
        "jobs.ScanRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="jobs"
    )
    run_id_legacy = models.CharField(
        max_length=64,
        default="",
        blank=True,
        db_index=True,
        help_text="Pre-migration free-form run id, kept for audit only.",
    )
    baseline_mode = models.BooleanField(default=False)
    checkpoint = models.JSONField(default=dict, blank=True)
    worker = models.CharField(max_length=128, default="", blank=True)
    error = models.TextField(default="", blank=True)
    stats = models.JSONField(default=dict, blank=True)
    # P1-006: primary liveness signal for stall detection. Provided by
    # HeartbeatMixin (heartbeat_at); job logs are secondary evidence only.
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # P0-011: every parent must live on the same target as this job.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {
        "scan_run": "ScanRun",
        "parent": "parent ScanJob",
    }
    REQUIRED_PARENT_FKS = ()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["target", "status"]),
            models.Index(fields=["status", "heartbeat_at"]),
        ]

    def __str__(self):
        return f"#{self.pk} {self.job_type} {self.target.root_domain} [{self.status}]"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def is_live(self):
        return self.status in (self.STATUS_QUEUED, self.STATUS_RUNNING)

    def liveness_at(self):
        """Best available liveness timestamp: heartbeat first, then last log."""
        if self.heartbeat_at:
            return self.heartbeat_at
        last_log = self.logs.order_by("-created_at").first() if self.pk else None
        if last_log:
            return last_log.created_at
        return self.started_at


class JobLog(models.Model):
    LEVEL_DEBUG = "DEBUG"
    LEVEL_INFO = "INFO"
    LEVEL_WARNING = "WARNING"
    LEVEL_ERROR = "ERROR"
    LEVEL_CHOICES = [
        (LEVEL_DEBUG, "Debug"),
        (LEVEL_INFO, "Info"),
        (LEVEL_WARNING, "Warning"),
        (LEVEL_ERROR, "Error"),
    ]
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="logs")
    # P2-004: unscoped manager, filtered explicitly by membership in the view.
    # A request-scoped manager would be ambient state, not an authorization check.
    objects = models.Manager()
    level = models.CharField(
        max_length=16, choices=LEVEL_CHOICES, default=LEVEL_INFO, db_index=True
    )
    stage = models.CharField(max_length=64, default="", blank=True)
    tool = models.CharField(max_length=64, default="", blank=True, db_index=True)
    message = models.TextField()
    duration_ms = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]


class JSAnalysisJob(HeartbeatMixin, TargetConsistencyMixin, models.Model):
    """Dedicated JS analysis job with per-stage progress (QUEUED..COMPLETED/PARTIAL/FAILED)."""

    STAGES = [
        "QUEUED",
        "DOWNLOADING",
        "HASHING",
        "DEDUPLICATING",
        "BEAUTIFYING",
        "JSLUICE",
        "LINKFINDER",
        "SECRETFINDER",
        "SEMGREP",
        "RETIREJS",
        "AGGREGATING",
        "COMPLETED",
        "FAILED",
        "PARTIAL",
    ]
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_PARTIAL, "Partial"),
        (STATUS_FAILED, "Failed"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="js_jobs")
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    js = models.ForeignKey(
        "assets.JavaScriptAsset", on_delete=models.CASCADE, related_name="analysis_jobs"
    )
    parent_job = models.ForeignKey(
        ScanJob, null=True, blank=True, on_delete=models.SET_NULL, related_name="js_analyses"
    )
    # P0-010: JSAnalysisJob is part of the canonical chain
    #   ScanRun -> ScanJob -> JSAnalysisJob -> ToolExecution -> AssetObservation -> Event
    # `parent_job` is nullable, so without this FK a JS analysis could not be
    # traced back to the execution root at all, and "which run produced this
    # finding?" would have no answer. The two are redundant by design:
    # `scan_run` is the root, `parent_job` is the direct dispatch link.
    scan_run = models.ForeignKey(
        "jobs.ScanRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="js_analyses"
    )
    trigger = models.CharField(
        max_length=32, default="NEW_JS", db_index=True
    )  # NEW_JS/JS_CHANGED/recheck/manual
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True
    )
    current_stage = models.CharField(max_length=32, default="QUEUED", db_index=True)
    progress = models.IntegerField(default=0)
    stages = models.JSONField(default=dict, blank=True)  # stage -> COMPLETED/FAILED/SKIPPED/pending
    stats = models.JSONField(
        default=dict, blank=True
    )  # endpoints/secrets/dependencies/semgrep/retire counts
    error = models.TextField(default="", blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # P0-011: the JS asset, the parent job and the execution root must all live
    # on this job's target.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {
        "js": "JavaScriptAsset",
        "parent_job": "parent ScanJob",
        "scan_run": "ScanRun",
    }

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["target", "status"]),
            models.Index(fields=["status", "heartbeat_at"]),
        ]
        # P2-008: at most one *live* analysis per JS asset. `queue_js_analysis`
        # checks for an existing QUEUED/RUNNING job, but a check-then-create race
        # (two events for the same script) could queue the same analysis twice
        # and download/analyze the bundle concurrently. A conditional unique
        # index expresses "live" in the database; terminal jobs stay unconstrained
        # so history is preserved.
        constraints = [
            models.UniqueConstraint(
                fields=["js"],
                condition=models.Q(status__in=["QUEUED", "RUNNING"]),
                name="uniq_live_js_analysis_per_asset",
            ),
        ]

    def __str__(self):
        return f"JS#{self.pk} {self.js.js_url[:60]} [{self.status}/{self.current_stage}]"


class JSAnalysisLog(models.Model):
    job = models.ForeignKey(JSAnalysisJob, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=16, default="INFO", db_index=True)
    stage = models.CharField(max_length=32, default="", blank=True, db_index=True)
    tool = models.CharField(max_length=64, default="", blank=True)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]


class ScanRun(HeartbeatMixin, models.Model):
    """First-class monitoring execution (TASK-006). Config snapshot preserved for reproducibility.

    P0-009: ``ScanRun`` is the canonical execution root. Every ``ToolExecution``,
    ``ScanJob``, ``AssetObservation`` and ``Event`` produced by an execution
    hangs off this row, so "which run produced this asset?" is answerable with
    a single indexed join and a single kill/pause switch.
    """

    SCAN_TYPES = [
        (s, s) for s in ("DISCOVERY", "MONITORING", "ACTIVE", "PASSIVE", "FULL", "VALIDATION")
    ]
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("RUNNING", "Running"),
        ("COMPLETED", "Completed"),
        ("PARTIAL", "Partial"),
        ("DEGRADED", "Degraded"),
        ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"),
        ("SKIPPED", "Skipped"),
    ]
    # Terminal states: the execution root is closed, nothing may be attached
    # as live work any more (historical rows may still be back-filled).
    TERMINAL_STATUSES = frozenset({"COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "SKIPPED"})
    LIVE_STATUSES = frozenset({"PENDING", "RUNNING"})
    # P0-012: cancellation is requested by flipping the target, but the run
    # records that it saw the request and when.
    CANCEL_REASON_CHOICES = [
        ("", "—"),
        ("OPERATOR", "Operator requested"),
        ("TARGET_PAUSED", "Target paused"),
        ("TARGET_ARCHIVED", "Target archived"),
        ("AUTH_EXPIRED", "Authorization expired"),
        ("AUTH_REVOKED", "Authorization revoked"),
        ("TARGET_DISABLED", "Target disabled"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="scan_runs")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    scan_type = models.CharField(
        max_length=16, choices=SCAN_TYPES, default="MONITORING", db_index=True
    )
    profile = models.CharField(max_length=16, default="balanced", db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default="PENDING", db_index=True
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    requested_by = models.CharField(max_length=255, default="", blank=True)
    trigger = models.CharField(max_length=32, default="manual", db_index=True)
    configuration_snapshot = models.JSONField(default=dict, blank=True)
    error_summary = models.TextField(default="", blank=True)
    coverage_summary = models.JSONField(default=dict, blank=True)
    # P0-012: kill-switch evidence on the execution root.
    cancel_requested_at = models.DateTimeField(null=True, blank=True, db_index=True)
    cancel_reason = models.CharField(
        max_length=24, choices=CANCEL_REASON_CHOICES, default="", blank=True, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["target", "status"]),
            models.Index(fields=["status", "heartbeat_at"]),
        ]
        # P1-001: at most one *live* run per (target, scan_type). A conditional
        # unique index is the only way to express "active" in the database —
        # terminal runs stay unconstrained, so a target accumulates history but
        # never two concurrent schedulers. This is the guarantee that makes
        # concurrent `_get_or_create_run()` calls safe across processes.
        constraints = [
            models.UniqueConstraint(
                fields=["target", "scan_type"],
                condition=models.Q(status__in=["PENDING", "RUNNING"]),
                name="uniq_live_run_per_target_type",
            ),
        ]

    def __str__(self):
        return f"Run#{self.pk} {self.target} {self.scan_type}/{self.profile} [{self.status}]"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def is_live(self):
        return self.status in self.LIVE_STATUSES

    def request_cancel(self, reason="OPERATOR", commit=True):
        """Record a kill-switch trip. Idempotent: the first reason wins so a
        later, weaker reason cannot overwrite the real cause."""
        from django.utils import timezone

        if self.status not in self.LIVE_STATUSES and self.cancel_requested_at:
            return self.cancel_requested_at
        now = timezone.now()
        if self.cancel_requested_at is None:
            self.cancel_requested_at = now
        if not self.cancel_reason and reason:
            self.cancel_reason = reason
        if commit:
            ScanRun._base_manager.filter(pk=self.pk).update(
                cancel_requested_at=self.cancel_requested_at, cancel_reason=self.cancel_reason
            )
        return self.cancel_requested_at

    def heartbeat(self, commit=True):
        """Alias for beat() — the P1-006 liveness signal."""
        return self.beat(commit=commit)


class ToolExecution(HeartbeatMixin, TargetConsistencyMixin, models.Model):
    """Individual tool execution within a ScanRun (TASK-007). No credentials stored."""

    # Reuse ScanRun's status vocabulary (P1-002) but declare the names locally
    # so callers can write ToolExecution.STATUS_COMPLETED. `status` is
    # max_length=16, so the 24-char kill-switch label from ScanRun can never be
    # written here; the constants below are exactly the ones that fit.
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_FAILED = "FAILED"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_CHOICES = ScanRun.STATUS_CHOICES
    TERMINAL_STATUSES = frozenset(
        {
            STATUS_COMPLETED,
            STATUS_PARTIAL,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_SKIPPED,
        }
    )
    # P1-004/P2-002: distinguish a crash from a real tool exit so the
    # orchestrator can tell "tool said no" from "tool vanished".
    FAILURE_KIND_CHOICES = [
        ("", "—"),
        ("CRASH", "Process crashed / killed by signal"),
        ("NONZERO_EXIT", "Tool exited non-zero"),
        ("TIMEOUT", "Timed out"),
        ("CANCELLED", "Cancelled by operator or kill switch"),
        ("LAUNCH_FAILED", "Could not start the tool"),
    ]
    scan_run = models.ForeignKey(
        ScanRun, null=True, blank=True, on_delete=models.CASCADE, related_name="tool_executions"
    )
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="tool_executions"
    )
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    job = models.ForeignKey(
        ScanJob, null=True, blank=True, on_delete=models.SET_NULL, related_name="tool_executions"
    )
    tool_name = models.CharField(max_length=64, db_index=True)
    command = models.TextField(default="", blank=True)  # redacted, never secrets
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default="PENDING", db_index=True
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    exit_code = models.IntegerField(null=True, blank=True)
    failure_kind = models.CharField(
        max_length=16, choices=FAILURE_KIND_CHOICES, default="", blank=True, db_index=True
    )
    stdout_reference = models.CharField(max_length=1024, default="", blank=True)
    stderr_reference = models.CharField(max_length=1024, default="", blank=True)
    duration = models.FloatField(null=True, blank=True)
    fallback_used = models.BooleanField(default=False)
    coverage = models.JSONField(default=dict, blank=True)
    error = models.TextField(default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # P0-011: a ToolExecution may not claim to belong to a run or job on a
    # different target than itself.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {"scan_run": "ScanRun", "job": "ScanJob"}

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["target", "status"])]

    def __str__(self):
        return f"{self.tool_name} run#{self.scan_run_id} [{self.status}]"


class AssetObservation(TargetConsistencyMixin, models.Model):
    """What was observed during each scan (TASK-008). History preserved, never overwritten.

    P1-005: an observation is only useful if you can trace it back to the exact
    job and tool invocation that produced it, so ``job`` and ``tool_execution``
    are real FKs alongside the canonical ``scan_run``.
    """

    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="observations")
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="observations"
    )
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    job = models.ForeignKey(
        ScanJob, null=True, blank=True, on_delete=models.SET_NULL, related_name="observations"
    )
    tool_execution = models.ForeignKey(
        ToolExecution, null=True, blank=True, on_delete=models.SET_NULL, related_name="observations"
    )
    asset_type = models.CharField(max_length=32, db_index=True)
    asset_id = models.IntegerField(null=True, blank=True)
    asset_value = models.CharField(max_length=2048, default="", blank=True, db_index=True)
    observed = models.BooleanField(default=True, db_index=True)
    metadata_hash = models.CharField(max_length=64, default="", blank=True, db_index=True)
    observed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    evidence = models.JSONField(default=dict, blank=True)

    # P0-011: run, job and tool execution must all agree on the target.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {
        "scan_run": "ScanRun",
        "job": "ScanJob",
        "tool_execution": "ToolExecution",
    }
    REQUIRED_PARENT_FKS: ClassVar[tuple[str, ...]] = ("scan_run",)

    class Meta:
        ordering = ["-observed_at"]
        indexes = [models.Index(fields=["target", "asset_type", "observed_at"])]

    def __str__(self):
        return f"obs {self.asset_type}:{self.asset_value[:60]} run#{self.scan_run_id} {'seen' if self.observed else 'missing'}"
