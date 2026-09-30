"""Event engine models: persistent events + alert deliveries."""

from typing import ClassVar

from django.db import models

from apps.core.consistency import (
    ConsistentTargetScopedManager,
    TargetConsistencyMixin,
)


class Event(TargetConsistencyMixin, models.Model):
    EVENT_TYPES = [
        ("NEW_SUBDOMAIN", "New subdomain"),
        ("SUBDOMAIN_CHANGED", "Subdomain changed"),
        ("NEW_DNS_RECORD", "New DNS record"),
        ("DNS_RECORD_CHANGED", "DNS record changed"),
        ("DNS_RECORD_REMOVED", "DNS record removed"),
        ("NEW_IP", "New IP"),
        ("IP_CHANGED", "IP changed"),
        ("IP_REMOVED", "IP removed"),
        ("IP_REACTIVATED", "IP reactivated"),
        ("NEW_OPEN_PORT", "New open port"),
        ("PORT_CLOSED", "Port closed"),
        ("PORT_STATE_CHANGED", "Port state changed"),
        ("PORT_SERVICE_CHANGED", "Port service changed"),
        ("PORT_BANNER_CHANGED", "Port banner changed"),
        ("NEW_HTTP_SERVICE", "New HTTP service"),
        ("HTTP_SERVICE_CHANGED", "HTTP service changed"),
        ("HTTP_SERVICE_REMOVED", "HTTP service removed"),
        ("HTTP_SERVICE_REACTIVATED", "HTTP service reactivated"),
        ("NEW_URL", "New URL"),
        ("URL_CHANGED", "URL changed"),
        ("URL_REMOVED", "URL removed"),
        ("URL_REACTIVATED", "URL reactivated"),
        ("NEW_API_ENDPOINT", "New API endpoint"),
        ("API_ENDPOINT_CHANGED", "API endpoint changed"),
        ("API_ENDPOINT_REMOVED", "API removed"),
        ("API_ENDPOINT_REACTIVATED", "API reactivated"),
        ("NEW_JS", "New JS"),
        ("JS_CHANGED", "JS changed"),
        ("JS_REMOVED", "JS removed"),
        ("JS_REACTIVATED", "JS reactivated"),
        ("NEW_JS_ENDPOINT", "New JS endpoint"),
        ("NEW_JS_SECRET_CANDIDATE", "New JS secret candidate"),
        # P2-003: a semantic change is a *difference*, so removals are first-class
        # events too -- a route/library/secret that disappeared is evidence, not
        # silence. (See also JS_ENDPOINT_REMOVED etc. below.)
        ("JS_ENDPOINT_REMOVED", "JS endpoint removed"),
        ("JS_LIBRARY_REMOVED", "JS library removed"),
        ("JS_SECRET_CANDIDATE_REMOVED", "JS secret candidate removed"),
        ("NEW_JS_DEPENDENCY", "New JS dependency"),
        ("NEW_JS_LIBRARY", "New JS library"),
        ("NEW_TECHNOLOGY", "New technology"),
        ("TECHNOLOGY_CHANGED", "Technology changed"),
        ("TECH_VERSION_CHANGED", "Tech version changed"),
        ("TECHNOLOGY_REMOVED", "Technology removed"),
        ("TECHNOLOGY_REACTIVATED", "Technology reactivated"),
        ("NEW_CVE_CANDIDATE", "New CVE candidate"),
        ("CVE_STATUS_CHANGED", "CVE status changed"),
        ("CVE_VALIDATED", "CVE validated"),
        ("NEW_SECURITY_FINDING", "New security finding"),
        ("FINDING_CHANGED", "Finding changed"),
        ("FINDING_RESOLVED", "Finding resolved"),
        ("SCOPE_CHANGED", "Scope changed"),
        ("AUTHORIZATION_EXPIRING", "Authorization expiring"),
        ("AUTHORIZATION_EXPIRED", "Authorization expired"),
        ("AUTHORIZATION_REAUTHORIZED", "Authorization granted/renewed"),
        ("TARGET_ARCHIVED", "Target archived"),
        ("BASELINE_STARTED", "Baseline started"),
        ("BASELINE_COMPLETED", "Baseline completed"),
        ("BASELINE_PARTIAL", "Baseline completed with reduced coverage"),
        ("BASELINE_FAILED", "Baseline failed"),
        ("JOB_FAILED", "Job failed"),
        ("JOB_STALLED", "Job stalled"),
        ("SUBDOMAIN_REMOVED", "Subdomain removed"),
        ("SUBDOMAIN_REACTIVATED", "Subdomain reactivated"),
        ("JS_ANALYSIS_STARTED", "JS analysis started"),
        ("JS_ANALYSIS_COMPLETED", "JS analysis completed"),
    ]
    SEV_CHOICES = [
        ("INFO", "Info"),
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    event_type = models.CharField(max_length=32, db_index=True)
    target = models.ForeignKey(
        "targets.Target", null=True, blank=True, on_delete=models.CASCADE, related_name="events"
    )
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    asset_type = models.CharField(max_length=32, default="", blank=True)
    asset_id = models.IntegerField(null=True, blank=True)
    asset_value = models.CharField(max_length=2048, default="", blank=True, db_index=True)
    severity = models.CharField(max_length=16, choices=SEV_CHOICES, default="INFO", db_index=True)
    confidence = models.CharField(max_length=16, default="unknown")
    source = models.CharField(max_length=128, default="", blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    fingerprint = models.CharField(max_length=128, unique=True, db_index=True)
    # TASK-033 evidence + TASK-034 correlation + TASK-037 priority
    scan_run = models.ForeignKey(
        "jobs.ScanRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="events"
    )
    old_state = models.JSONField(default=dict, blank=True)
    new_state = models.JSONField(default=dict, blank=True)
    correlation_id = models.CharField(max_length=64, default="", blank=True, db_index=True)
    parent_event = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children"
    )
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    # P0-011: an event may not be filed under a different target than the run
    # that produced it, or than the parent event it is a follow-up of.
    # ``Event.target`` stays nullable for genuine cross-target/system events,
    # but a target-scoped parent forces the target to match.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {
        "scan_run": "ScanRun",
        "parent_event": "parent Event",
    }

    @property
    def target_id_safe(self):
        return self.target_id

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event_type", "created_at"]),
            models.Index(fields=["target", "created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} {self.asset_value[:60]}"


class Alert(TargetConsistencyMixin, models.Model):
    STATUS_PENDING = "PENDING"
    STATUS_SENT = "SENT"
    STATUS_BATCHED = "BATCHED"
    STATUS_SUPPRESSED = "SUPPRESSED"
    STATUS_FAILED = "FAILED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_THROTTLED = "THROTTLED"
    STATUS_DEDUPLICATED = "DEDUPLICATED"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SENT, "Sent"),
        (STATUS_BATCHED, "Batched"),
        (STATUS_SUPPRESSED, "Suppressed"),
        (STATUS_FAILED, "Failed"),
        (STATUS_SKIPPED, "Skipped"),
        (STATUS_THROTTLED, "Throttled"),
        (STATUS_DEDUPLICATED, "Deduplicated"),
    ]
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="alerts")
    target = models.ForeignKey(
        "targets.Target", null=True, blank=True, on_delete=models.CASCADE, related_name="alerts"
    )
    objects = ConsistentTargetScopedManager()
    all_objects = ConsistentTargetScopedManager()
    channel = models.CharField(max_length=32, default="discord")
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True
    )
    payload_preview = models.TextField(default="", blank=True)
    response = models.TextField(default="", blank=True)  # discord response / delivery receipt
    error = models.TextField(default="", blank=True)  # failure reason
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    # P0-014: alert outcome must be recorded, not just attempted. These record
    # the *reason* a delivery stopped being retried and the final verdict.
    outcome_reason = models.CharField(max_length=32, default="", blank=True, db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    # P0-011: an alert about an event on target A must itself be on target A.
    RELATED_TARGET_FKS: ClassVar[dict[str, str]] = {"event": "Event"}
    REQUIRED_PARENT_FKS: ClassVar[tuple[str, ...]] = ("event",)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["target", "status"])]

    def __str__(self):
        return f"{self.channel}:{self.status} for event {self.event_id}"
