"""Target lifecycle model with kill-switch + authorization expiry."""
from django.db import models
from django.utils import timezone


class Target(models.Model):
    STATUS_ACTIVE = "ACTIVE"
    STATUS_PAUSED = "PAUSED"
    STATUS_DISABLED = "DISABLED"
    STATUS_CHOICES = [(STATUS_ACTIVE, "Active"), (STATUS_PAUSED, "Paused"), (STATUS_DISABLED, "Disabled")]

    AUTH_AUTHORIZED = "AUTHORIZED"
    AUTH_EXPIRED = "EXPIRED"
    AUTH_PENDING = "PENDING"
    AUTH_CHOICES = [
        (AUTH_AUTHORIZED, "Authorized"),
        (AUTH_EXPIRED, "Expired"),
        (AUTH_PENDING, "Pending"),
    ]

    name = models.CharField(max_length=255)
    root_domain = models.CharField(max_length=255, unique=True, db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True)
    authorization_status = models.CharField(max_length=16, choices=AUTH_CHOICES, default=AUTH_AUTHORIZED)
    authorization_expires_at = models.DateTimeField(null=True, blank=True)
    auth_warning_days = models.IntegerField(default=7)
    baseline_status = models.CharField(max_length=32, default="NOT_STARTED", db_index=True)
    # NOT_STARTED | INITIAL_BASELINE | BASELINE_COMPLETE
    baseline_started_at = models.DateTimeField(null=True, blank=True)
    baseline_completed_at = models.DateTimeField(null=True, blank=True)
    wildcard_detected = models.BooleanField(default=False)
    wildcard_ips = models.JSONField(default=list, blank=True)
    wildcard_cnames = models.JSONField(default=list, blank=True)
    scan_config = models.JSONField(default=dict, blank=True)
    scan_profile = models.CharField(max_length=16, default="balanced", db_index=True)
    verify_tls = models.BooleanField(default=True)
    notification_config = models.JSONField(default=dict, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    next_scan = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["root_domain"]

    def __str__(self):
        return self.root_domain

    @property
    def is_scannable(self):
        if self.status != self.STATUS_ACTIVE:
            return False
        if self.authorization_status == self.AUTH_EXPIRED:
            return False
        if self.authorization_expires_at and self.authorization_expires_at <= timezone.now():
            return False
        return True
