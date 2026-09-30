"""Target lifecycle model with kill-switch + authorization expiry."""

from django.db import models
from django.utils import timezone


class TargetQuerySet(models.QuerySet["Target"]):
    """QuerySet exposing the *authorized* projection for the current user.

    `for_user()` is the ONLY sanctioned way to build a user-facing Target
    queryset. `Target.objects.all()` is deliberately left unfiltered because
    background/celery code legitimately needs it — see FINAL-001 classification.
    """

    def for_user(self, user):
        """Return only the targets `user` is authorized to see.

        Superusers/staff with the global admin override see every target.
        Everyone else sees only targets they hold a membership row for.
        """
        from apps.core.authorization import global_admin_override

        if global_admin_override(user):
            return self
        if user is None or not getattr(user, "is_authenticated", False):
            return self.none()
        return self.filter(memberships__user_id=user.pk).distinct()

    def readable_by(self, user):
        return self.for_user(user)


class TargetMembership(models.Model):
    """Explicit target-level access control (P0-002).

    A user without a membership row (and without the global admin override)
    must never see ANY data belonging to that target — views, APIs, websockets
    and exports all resolve authorization through this model.
    """

    ROLE_OWNER = "OWNER"
    ROLE_OPERATOR = "OPERATOR"
    ROLE_VIEWER = "VIEWER"
    ROLE_CHOICES = [
        (ROLE_OWNER, "Owner"),
        (ROLE_OPERATOR, "Operator"),
        (ROLE_VIEWER, "Viewer"),
    ]
    # Capability matrix, consumed by apps.core.authorization. Higher rank wins.
    ROLE_RANK = {ROLE_VIEWER: 1, ROLE_OPERATOR: 2, ROLE_OWNER: 3}

    user = models.ForeignKey(
        "auth.User", on_delete=models.CASCADE, related_name="target_memberships"
    )
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_VIEWER, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["target_id", "user_id"]
        # P2-008: application validation alone is not sufficient for a
        # race-sensitive duplicate-prevention rule.
        constraints = [
            models.UniqueConstraint(fields=["user", "target"], name="uniq_membership_user_target"),
        ]
        indexes = [models.Index(fields=["target", "role"]), models.Index(fields=["user", "role"])]

    def __str__(self):
        return f"{self.user_id}@{self.target_id}:{self.role}"

    def clean(self):
        from django.core.exceptions import ValidationError

        if self.role not in self.ROLE_RANK:
            raise ValidationError({"role": f"Unknown role {self.role!r}"})

    @property
    def rank(self):
        return self.ROLE_RANK.get(self.role, 0)

    def can_read(self):
        return self.rank >= self.ROLE_RANK[self.ROLE_VIEWER]

    def can_operate(self):
        return self.rank >= self.ROLE_RANK[self.ROLE_OPERATOR]

    def can_manage(self):
        return self.rank >= self.ROLE_RANK[self.ROLE_OWNER]


class Target(models.Model):
    STATUS_ACTIVE = "ACTIVE"
    STATUS_PAUSED = "PAUSED"
    STATUS_DISABLED = "DISABLED"
    # P2-005: archive is a soft-delete so historical evidence (ScanRuns,
    # events, observations) survives. `archived_at is None` means "live".
    STATUS_ARCHIVED = "ARCHIVED"
    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_PAUSED, "Paused"),
        (STATUS_DISABLED, "Disabled"),
        (STATUS_ARCHIVED, "Archived"),
    ]

    AUTH_AUTHORIZED = "AUTHORIZED"
    AUTH_EXPIRED = "EXPIRED"
    AUTH_PENDING = "PENDING"
    AUTH_CHOICES = [
        (AUTH_AUTHORIZED, "Authorized"),
        (AUTH_EXPIRED, "Expired"),
        (AUTH_PENDING, "Pending"),
    ]

    # P2-007: centralize legal state transitions. Any code that flips these
    # fields must go through target_lifecycle.transition_to() so the required
    # side effects (job cancellation, lifecycle events, audit) always run.
    ALLOWED_STATUS_TRANSITIONS = {
        STATUS_ACTIVE: {STATUS_PAUSED, STATUS_DISABLED, STATUS_ARCHIVED},
        STATUS_PAUSED: {STATUS_ACTIVE, STATUS_DISABLED, STATUS_ARCHIVED},
        STATUS_DISABLED: {STATUS_ACTIVE, STATUS_ARCHIVED},
        STATUS_ARCHIVED: {STATUS_ACTIVE},
    }
    ALLOWED_AUTH_TRANSITIONS = {
        AUTH_PENDING: {AUTH_AUTHORIZED, AUTH_EXPIRED},
        AUTH_AUTHORIZED: {AUTH_EXPIRED, AUTH_PENDING},
        AUTH_EXPIRED: {AUTH_AUTHORIZED, AUTH_PENDING},
    }

    name = models.CharField(max_length=255)
    root_domain = models.CharField(max_length=255, unique=True, db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE, db_index=True
    )
    # Task 29: safe default — a freshly added target must NOT be scannable
    # until someone explicitly confirms authorization (see TargetForm).
    # Existing rows are untouched by the accompanying migration (Django only
    # changes the column default for new rows).
    authorization_status = models.CharField(
        max_length=16, choices=AUTH_CHOICES, default=AUTH_PENDING
    )
    authorization_expires_at = models.DateTimeField(null=True, blank=True)
    auth_warning_days = models.IntegerField(default=7)
    BASELINE_NOT_STARTED = "NOT_STARTED"
    BASELINE_INITIAL = "INITIAL_BASELINE"
    BASELINE_COMPLETE = "BASELINE_COMPLETE"
    BASELINE_PARTIAL = "BASELINE_PARTIAL"
    BASELINE_FAILED = "BASELINE_FAILED"
    baseline_status = models.CharField(max_length=32, default=BASELINE_NOT_STARTED, db_index=True)
    # NOT_STARTED | INITIAL_BASELINE | BASELINE_COMPLETE | BASELINE_PARTIAL | BASELINE_FAILED
    baseline_started_at = models.DateTimeField(null=True, blank=True)
    baseline_completed_at = models.DateTimeField(null=True, blank=True)
    wildcard_detected = models.BooleanField(default=False)
    wildcard_ips = models.JSONField(default=list, blank=True)
    wildcard_cnames = models.JSONField(default=list, blank=True)
    scan_config = models.JSONField(default=dict, blank=True)
    # Task 11: assets unseen for longer than this are reconciled as REMOVED.
    # Tuned per target instead of a hardcoded 14 days, so weekly/manual scans
    # and fresh targets don't get false REMOVED events.
    reconciliation_grace_days = models.PositiveIntegerField(default=14)
    scan_profile = models.CharField(max_length=16, default="balanced", db_index=True)
    verify_tls = models.BooleanField(default=True)
    notification_config = models.JSONField(default=dict, blank=True)
    last_scan = models.DateTimeField(null=True, blank=True)
    next_scan = models.DateTimeField(null=True, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # P0-014: cooperative kill switch. `Target.is_scannable` already blocks new
    # work; this is the *in-flight* signal that running jobs poll so they stop
    # promptly instead of finishing the stage they happen to be in.
    cancel_requested_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TargetQuerySet.as_manager()
    all_objects = models.Manager()

    class Meta:
        ordering = ["root_domain"]
        indexes = [models.Index(fields=["status", "archived_at"])]

    def __str__(self):
        return self.root_domain

    @property
    def is_archived(self):
        return self.status == self.STATUS_ARCHIVED or self.archived_at is not None

    @property
    def is_scannable(self):
        if self.is_archived:
            return False
        if self.status != self.STATUS_ACTIVE:
            return False
        # Task 29: only an explicit AUTHORIZED counts — PENDING/EXPIRED never scan.
        if self.authorization_status != self.AUTH_AUTHORIZED:
            return False
        if self.authorization_expires_at and self.authorization_expires_at <= timezone.now():
            return False
        if self.cancel_requested_at is not None:
            return False
        return True

    def authorization_expired(self, now=None):
        """True when the engagement authorization window has lapsed."""
        if not self.authorization_expires_at:
            return False
        return self.authorization_expires_at <= (now or timezone.now())

    def blocking_reason(self, now=None):
        """Human-readable reason this target may not run work (or None if it may)."""
        if self.is_archived:
            return "target archived"
        if self.status == self.STATUS_PAUSED:
            return "target paused"
        if self.status == self.STATUS_DISABLED:
            return "target disabled"
        if self.cancel_requested_at is not None:
            return "cancellation requested"
        if self.authorization_status == self.AUTH_PENDING:
            return "authorization pending"
        if self.authorization_status == self.AUTH_EXPIRED or self.authorization_expired(now):
            return "authorization expired"
        return None
