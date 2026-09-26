from django.db import models

from apps.core.target_scoping import TargetScopedManager


class Baseline(models.Model):
    STATUS_NOT_STARTED = "NOT_STARTED"
    STATUS_RUNNING = "RUNNING"
    STATUS_COMPLETE = "COMPLETE"
    STATUS_CHOICES = [
        (STATUS_NOT_STARTED, "Not started"), (STATUS_RUNNING, "Running"), (STATUS_COMPLETE, "Complete"),
    ]
    target = models.OneToOneField("targets.Target", on_delete=models.CASCADE, related_name="baseline")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_NOT_STARTED, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"baseline {self.target.root_domain} [{self.status}]"


class CVESyncState(models.Model):
    source = models.CharField(max_length=128, unique=True)
    last_synced = models.DateTimeField(null=True, blank=True)
    record_count = models.IntegerField(default=0)
    info = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return f"{self.source} synced={self.last_synced}"


class DiscordBatch(models.Model):
    """Pending low/info severity messages aggregated into a digest."""

    status = models.CharField(max_length=16, default="PENDING", db_index=True)
    event_ids = models.JSONField(default=list, blank=True)
    window_ends_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)


class ExportJob(models.Model):
    """Async export generation with history + download."""

    STATUS_QUEUED = "QUEUED"
    STATUS_PROCESSING = "PROCESSING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"), (STATUS_PROCESSING, "Processing"),
        (STATUS_COMPLETED, "Completed"), (STATUS_FAILED, "Failed"),
    ]
    EXPORT_TYPES = [
        ("subdomains", "Subdomains"), ("ips", "IPs"), ("ports", "Ports"),
        ("http", "HTTP URLs"), ("urls", "All URLs"), ("apis", "API Endpoints"),
        ("javascript", "JavaScript URLs"), ("technologies", "Technologies"),
        ("cves", "CVE IDs"), ("findings", "Security Findings"), ("events", "Events"),
        ("snapshot", "Full Target Snapshot (ZIP)"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="exports")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    export_type = models.CharField(max_length=32, db_index=True)
    format = models.CharField(max_length=8, default="txt")  # txt/json/csv/zip
    filters = models.JSONField(default=dict, blank=True)  # active_only, since, source, status...
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED, db_index=True)
    file_path = models.CharField(max_length=1024, default="", blank=True)
    file_size = models.IntegerField(default=0)
    row_count = models.IntegerField(default=0)
    created_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL)
    error = models.TextField(default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"export {self.export_type}.{self.format} for {self.target.root_domain} [{self.status}]"
