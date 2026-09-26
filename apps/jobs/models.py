"""Scan job tracking + structured logs."""
from django.db import models


class ScanJob(models.Model):
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_FAILED = "FAILED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_PAUSED = "PAUSED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"), (STATUS_RUNNING, "Running"), (STATUS_COMPLETED, "Completed"),
        (STATUS_FAILED, "Failed"), (STATUS_PARTIAL, "Partial"), (STATUS_CANCELLED, "Cancelled"),
        (STATUS_PAUSED, "Paused"), (STATUS_SKIPPED, "Skipped"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="jobs")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL,
                               related_name="children")  # which job triggered this one
    asset_type = models.CharField(max_length=32, default="", blank=True, db_index=True)
    asset_value = models.CharField(max_length=1024, default="", blank=True)
    trigger = models.CharField(max_length=32, default="manual",
                               db_index=True)  # manual/scheduled/event/baseline/reconcile
    job_type = models.CharField(max_length=64, db_index=True)  # subdomain_enum/dns/ports/http/urls/js/tech/cve/nuclei/reconcile/baseline
    stage = models.CharField(max_length=64, default="", blank=True)
    current_stage = models.CharField(max_length=64, default="", blank=True, db_index=True)
    tool = models.CharField(max_length=64, default="", blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    progress = models.IntegerField(default=0)
    command_redacted = models.TextField(default="", blank=True)
    run_id = models.CharField(max_length=64, default="", blank=True, db_index=True)
    baseline_mode = models.BooleanField(default=False)
    checkpoint = models.JSONField(default=dict, blank=True)
    worker = models.CharField(max_length=128, default="", blank=True)
    error = models.TextField(default="", blank=True)
    stats = models.JSONField(default=dict, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.job_type} {self.target.root_domain} [{self.status}]"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class JobLog(models.Model):
    LEVEL_DEBUG = "DEBUG"
    LEVEL_INFO = "INFO"
    LEVEL_WARNING = "WARNING"
    LEVEL_ERROR = "ERROR"
    LEVEL_CHOICES = [(LEVEL_DEBUG, "Debug"), (LEVEL_INFO, "Info"), (LEVEL_WARNING, "Warning"), (LEVEL_ERROR, "Error")]
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=16, choices=LEVEL_CHOICES, default=LEVEL_INFO, db_index=True)
    stage = models.CharField(max_length=64, default="", blank=True)
    tool = models.CharField(max_length=64, default="", blank=True, db_index=True)
    message = models.TextField()
    duration_ms = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]


class JSAnalysisJob(models.Model):
    """Dedicated JS analysis job with per-stage progress (QUEUED..COMPLETED/PARTIAL/FAILED)."""

    STAGES = ["QUEUED", "DOWNLOADING", "HASHING", "DEDUPLICATING", "BEAUTIFYING",
              "JSLUICE", "LINKFINDER", "SECRETFINDER", "SEMGREP", "RETIREJS",
              "AGGREGATING", "COMPLETED", "FAILED", "PARTIAL"]
    STATUS_QUEUED = "QUEUED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_PARTIAL = "PARTIAL"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"), (STATUS_RUNNING, "Running"), (STATUS_COMPLETED, "Completed"),
        (STATUS_PARTIAL, "Partial"), (STATUS_FAILED, "Failed"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="js_jobs")
    js = models.ForeignKey("assets.JavaScriptAsset", on_delete=models.CASCADE, related_name="analysis_jobs")
    parent_job = models.ForeignKey(ScanJob, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="js_analyses")
    trigger = models.CharField(max_length=32, default="NEW_JS", db_index=True)  # NEW_JS/JS_CHANGED/recheck/manual
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    current_stage = models.CharField(max_length=32, default="QUEUED", db_index=True)
    progress = models.IntegerField(default=0)
    stages = models.JSONField(default=dict, blank=True)  # stage -> COMPLETED/FAILED/SKIPPED/pending
    stats = models.JSONField(default=dict, blank=True)  # endpoints/secrets/dependencies/semgrep/retire counts
    error = models.TextField(default="", blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

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


class ScanRun(models.Model):
    """First-class monitoring execution (TASK-006). Config snapshot preserved for reproducibility."""
    SCAN_TYPES = [(s, s) for s in ("DISCOVERY", "MONITORING", "ACTIVE", "PASSIVE", "FULL", "VALIDATION")]
    STATUS_CHOICES = [
        ("PENDING", "Pending"), ("RUNNING", "Running"), ("COMPLETED", "Completed"),
        ("PARTIAL", "Partial"), ("DEGRADED", "Degraded"), ("FAILED", "Failed"),
        ("CANCELLED", "Cancelled"), ("SKIPPED", "Skipped"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="scan_runs")
    scan_type = models.CharField(max_length=16, choices=SCAN_TYPES, default="MONITORING", db_index=True)
    profile = models.CharField(max_length=16, default="balanced", db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="PENDING", db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    requested_by = models.CharField(max_length=255, default="", blank=True)
    trigger = models.CharField(max_length=32, default="manual", db_index=True)
    configuration_snapshot = models.JSONField(default=dict, blank=True)
    error_summary = models.TextField(default="", blank=True)
    coverage_summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Run#{self.pk} {self.target} {self.scan_type}/{self.profile} [{self.status}]"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class ToolExecution(models.Model):
    """Individual tool execution within a ScanRun (TASK-007). No credentials stored."""
    STATUS_CHOICES = ScanRun.STATUS_CHOICES
    scan_run = models.ForeignKey(ScanRun, null=True, blank=True, on_delete=models.CASCADE, related_name="tool_executions")
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="tool_executions")
    job = models.ForeignKey(ScanJob, null=True, blank=True, on_delete=models.SET_NULL, related_name="tool_executions")
    tool_name = models.CharField(max_length=64, db_index=True)
    command = models.TextField(default="", blank=True)  # redacted, never secrets
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="PENDING", db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    exit_code = models.IntegerField(null=True, blank=True)
    stdout_reference = models.CharField(max_length=1024, default="", blank=True)
    stderr_reference = models.CharField(max_length=1024, default="", blank=True)
    duration = models.FloatField(null=True, blank=True)
    fallback_used = models.BooleanField(default=False)
    coverage = models.JSONField(default=dict, blank=True)
    error = models.TextField(default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.scan_run_id and self.scan_run.target_id != self.target_id:
            raise ValidationError("ToolExecution scan_run target mismatch — cross-target rejected")
        if self.job_id and self.job.target_id != self.target_id:
            raise ValidationError("ToolExecution job target mismatch — cross-target rejected")

    def __str__(self):
        return f"{self.tool_name} run#{self.scan_run_id} [{self.status}]"


class AssetObservation(models.Model):
    """What was observed during each scan (TASK-008). History preserved, never overwritten."""
    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="observations")
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="observations")
    asset_type = models.CharField(max_length=32, db_index=True)
    asset_id = models.IntegerField(null=True, blank=True)
    asset_value = models.CharField(max_length=2048, default="", blank=True, db_index=True)
    observed = models.BooleanField(default=True, db_index=True)
    metadata_hash = models.CharField(max_length=64, default="", blank=True, db_index=True)
    observed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-observed_at"]
        indexes = [models.Index(fields=["target", "asset_type", "observed_at"])]

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.scan_run_id and self.scan_run.target_id != self.target_id:
            raise ValidationError("AssetObservation scan_run target mismatch — cross-target rejected")

    def __str__(self):
        return f"obs {self.asset_type}:{self.asset_value[:60]} run#{self.scan_run_id} {'seen' if self.observed else 'missing'}"
