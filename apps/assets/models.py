"""Central asset inventory models (target-isolated, explicit lifecycle)."""

from django.db import models

from apps.core.target_scoping import TargetScopedManager

ASSET_STATES = [
    ("DISCOVERED", "Discovered"),
    ("ACTIVE", "Active"),
    ("SUSPECTED_INACTIVE", "Suspected inactive"),
    ("INACTIVE", "Inactive"),
    ("REMOVED", "Removed"),
    ("REACTIVATED", "Reactivated"),
    ("UNKNOWN", "Unknown"),
]
PRIORITY_CHOICES = [(s, s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]


class Asset(models.Model):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    PORT = "PORT"
    HTTP_SERVICE = "HTTP_SERVICE"
    URL = "URL"
    API_ENDPOINT = "API_ENDPOINT"
    JS_FILE = "JS_FILE"
    TECHNOLOGY = "TECHNOLOGY"
    CVE = "CVE"
    FINDING = "FINDING"
    TYPE_CHOICES = [
        (DOMAIN, "Domain"),
        (SUBDOMAIN, "Subdomain"),
        (IP, "IP"),
        (PORT, "Port"),
        (HTTP_SERVICE, "HTTP service"),
        (URL, "URL"),
        (API_ENDPOINT, "API endpoint"),
        (JS_FILE, "JS file"),
        (TECHNOLOGY, "Technology"),
        (CVE, "CVE candidate"),
        (FINDING, "Security finding"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="assets")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    asset_type = models.CharField(max_length=32, choices=TYPE_CHOICES, db_index=True)
    value = models.CharField(max_length=2048, db_index=True)
    discovered_by_job = models.ForeignKey(
        "jobs.ScanJob",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="discovered_assets",
    )
    is_active = models.BooleanField(default=True, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [models.Index(fields=["target", "asset_type"]), models.Index(fields=["value"])]
        # P2-008: the asset inventory is the deduplicated index of everything we
        # know about a target. `get_or_create` alone cannot prevent duplicates
        # under concurrency (two ingesters can both observe "no existing row"),
        # so the rule is enforced in the database like every other asset model.
        constraints = [
            models.UniqueConstraint(
                fields=["target", "asset_type", "value"], name="uniq_asset_per_target_type_value"
            ),
        ]

    def __str__(self):
        return f"{self.asset_type}:{self.value[:80]}"

    def get_absolute_url(self):
        from django.urls import reverse

        return reverse("asset-detail", args=[self.pk])


class Subdomain(models.Model):
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="subdomains"
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    hostname = models.CharField(max_length=512, db_index=True)
    sources = models.JSONField(default=list, blank=True)
    dns_status = models.CharField(max_length=32, default="unknown", db_index=True)
    ip_addresses = models.JSONField(default=list, blank=True)
    wildcard_suspect = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True, db_index=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    fingerprint = models.CharField(max_length=64, default="", blank=True, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("target", "hostname")]
        ordering = ["hostname"]
        indexes = [models.Index(fields=["target", "is_active"])]

    def __str__(self):
        return self.hostname


class DNSRecord(models.Model):
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="dns_records"
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    hostname = models.CharField(max_length=512, db_index=True)
    record_type = models.CharField(max_length=16, db_index=True)  # A/AAAA/CNAME/NS/MX/TXT
    value = models.CharField(max_length=1024, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("target", "hostname", "record_type", "value")]

    def __str__(self):
        return f"{self.hostname} {self.record_type} {self.value}"


class IPAddress(models.Model):
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="ips")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    ip = models.GenericIPAddressField(db_index=True)
    version = models.IntegerField(default=4)
    source_hostnames = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    # T5: shared-infrastructure guard. Set when the same IP is seen under a
    # different target (Cloudflare/ALB/shared hosting). Port-scanning such IPs
    # requires explicit confirmation (confirmed_dedicated=True) — see
    # process_new_ip()/scan_ports().
    shared_suspect = models.BooleanField(default=False, db_index=True)
    confirmed_dedicated = models.BooleanField(default=False)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("target", "ip")]

    def __str__(self):
        return self.ip


class Port(models.Model):
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="ports")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    ip = models.CharField(max_length=64, db_index=True)
    port = models.IntegerField(db_index=True)
    protocol = models.CharField(max_length=8, default="tcp")
    state = models.CharField(max_length=16, default="open", db_index=True)
    service = models.CharField(max_length=128, default="", blank=True)
    product = models.CharField(max_length=256, default="", blank=True)
    version = models.CharField(max_length=128, default="", blank=True)
    banner = models.TextField(default="", blank=True)
    # P3-003: `state` used to be declared twice here (identical definitions, so
    # no migration drift was visible). The duplicate is removed; the canonical
    # declaration is the one above, next to the other port attributes.
    lifecycle = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    fingerprint = models.CharField(max_length=64, default="", blank=True, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("target", "ip", "port", "protocol")]
        ordering = ["ip", "port"]

    def __str__(self):
        return f"{self.ip}:{self.port}/{self.protocol}"


class HTTPService(models.Model):
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="http_services"
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    url = models.URLField(max_length=2048, db_index=True)
    host = models.CharField(max_length=512, db_index=True)
    port = models.IntegerField(default=443)
    scheme = models.CharField(max_length=8, default="https")
    status_code = models.IntegerField(null=True, blank=True, db_index=True)
    title = models.CharField(max_length=512, default="", blank=True)
    server = models.CharField(max_length=512, default="", blank=True)
    content_type = models.CharField(max_length=256, default="", blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    tls_info = models.JSONField(default=dict, blank=True)
    redirect_chain = models.JSONField(default=list, blank=True)
    technologies = models.JSONField(default=list, blank=True)
    ip = models.CharField(max_length=64, default="", blank=True)
    fingerprint = models.CharField(max_length=64, default="", blank=True, db_index=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("target", "url")]

    def __str__(self):
        return self.url


class URLAsset(models.Model):
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="urls")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    raw_url = models.TextField()
    canonical_url = models.URLField(max_length=4096, db_index=True)
    host = models.CharField(max_length=512, db_index=True)
    path = models.CharField(max_length=2048, default="", blank=True)
    query = models.CharField(max_length=2048, default="", blank=True)
    status_code = models.IntegerField(null=True, blank=True, db_index=True)
    content_type = models.CharField(max_length=256, default="", blank=True)
    source = models.CharField(max_length=64, default="", blank=True, db_index=True)
    is_api = models.BooleanField(default=False, db_index=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    fingerprint = models.CharField(max_length=64, default="", blank=True, db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("target", "canonical_url")]
        ordering = ["-last_seen"]

    def __str__(self):
        return self.canonical_url[:120]


class APIEndpoint(models.Model):
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="api_endpoints"
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    url = models.URLField(max_length=4096, db_index=True)
    host = models.CharField(max_length=512, db_index=True)
    method = models.CharField(max_length=16, default="GET")
    api_type = models.CharField(max_length=32, default="REST", db_index=True)
    parameters = models.JSONField(default=list, blank=True)
    content_type = models.CharField(max_length=256, default="", blank=True)
    auth_indicators = models.JSONField(default=list, blank=True)
    source = models.CharField(max_length=64, default="", blank=True)
    path = models.CharField(max_length=2048, default="", blank=True)
    version = models.CharField(max_length=64, default="", blank=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    fingerprint = models.CharField(max_length=64, default="", blank=True, db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("target", "url", "method")]

    def __str__(self):
        return f"{self.method} {self.url[:100]}"


class JavaScriptAsset(models.Model):
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="js_assets")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    js_url = models.URLField(max_length=4096, db_index=True)
    host = models.CharField(max_length=512, db_index=True)
    discovered_from = models.CharField(
        max_length=2048, default="", blank=True
    )  # page URL that referenced it
    sha256 = models.CharField(max_length=64, db_index=True)
    size = models.IntegerField(default=0)
    content = models.TextField(default="", blank=True)  # latest beautified content (size-guarded)
    routes = models.JSONField(default=list, blank=True)
    dependencies = models.JSONField(default=list, blank=True)
    secret_candidates = models.IntegerField(default=0)
    # P2-003: the secret candidates present in the *current* version, as
    # {"<type>": "<sha256[:12]>"} of each distinct matched value. The finding
    # table is cumulative history, so removals can only be detected against
    # this snapshot of the live content (the value itself is never stored here,
    # only its digest).
    current_secret_keys = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("target", "js_url")]

    def __str__(self):
        return self.js_url[:120]


class JavaScriptVersion(models.Model):
    """Historical JS content for diff view."""

    js = models.ForeignKey(JavaScriptAsset, on_delete=models.CASCADE, related_name="versions")
    sha256 = models.CharField(max_length=64, db_index=True)
    size = models.IntegerField(default=0)
    content = models.TextField(default="", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class JavaScriptFinding(models.Model):
    STATUS_CANDIDATE = "candidate"
    STATUS_CONFIRMED = "confirmed"
    STATUS_FALSE_POSITIVE = "false_positive"
    STATUS_RESOLVED = "resolved"
    STATUS_UNKNOWN = "unknown"
    STATUS_CHOICES = [
        (STATUS_CANDIDATE, "Candidate"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STATUS_FALSE_POSITIVE, "False positive"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_UNKNOWN, "Unknown"),
    ]
    target = models.ForeignKey(
        "targets.Target",
        on_delete=models.CASCADE,
        related_name="js_findings",
        null=True,
        blank=True,
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    js = models.ForeignKey(JavaScriptAsset, on_delete=models.CASCADE, related_name="findings")
    finding_type = models.CharField(max_length=64, db_index=True)  # secret/route/dependency/sast
    location = models.CharField(max_length=512, default="", blank=True)
    evidence_preview = models.CharField(max_length=512, default="", blank=True)  # redacted
    evidence_full = models.TextField(default="", blank=True)  # internal only
    confidence = models.CharField(max_length=16, default=STATUS_UNKNOWN, db_index=True)
    source_tool = models.CharField(max_length=64, default="", blank=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_CANDIDATE, db_index=True
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        # P2-008/P2-003: a finding's identity is (asset, type, location). The
        # semantic diff reads this table to decide what was added/removed, so a
        # duplicate row would corrupt the delta.
        constraints = [
            models.UniqueConstraint(
                fields=["js", "finding_type", "location"],
                name="uniq_js_finding_per_js_type_location",
            ),
        ]

    def __str__(self):
        return f"{self.finding_type}@{self.js.js_url[:60]}"


class Technology(models.Model):
    target = models.ForeignKey(
        "targets.Target", on_delete=models.CASCADE, related_name="technologies"
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    asset_value = models.CharField(max_length=1024, db_index=True)
    product = models.CharField(max_length=256, db_index=True)
    vendor = models.CharField(max_length=256, default="", blank=True, db_index=True)
    version = models.CharField(max_length=128, default="", blank=True, db_index=True)
    confidence = models.FloatField(default=0.5)
    evidence = models.TextField(default="", blank=True)
    source = models.CharField(max_length=64, default="", blank=True)
    state = models.CharField(max_length=24, default="ACTIVE", db_index=True)
    priority = models.CharField(max_length=16, default="LOW", db_index=True)
    priority_reasons = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_changed = models.DateTimeField(null=True, blank=True)

    # P1-007: when this technology was last correlated against the CVE KB.
    # Enables incremental re-correlation (only new/changed technologies are
    # re-checked while the KB is unchanged) instead of a blind full sweep.
    cve_checked_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        unique_together = [("target", "asset_value", "product")]
        ordering = ["product"]

    def __str__(self):
        v = f" {self.version}" if self.version else ""
        return f"{self.product}{v} on {self.asset_value[:60]}"


class CVE(models.Model):
    STATUS_CANDIDATE = "candidate"
    STATUS_POTENTIALLY_AFFECTED = "potentially_affected"
    STATUS_VALIDATION_PENDING = "validation_pending"
    STATUS_VALIDATED = "validated"
    STATUS_NOT_AFFECTED = "not_affected"
    STATUS_EXPIRED = "expired"
    STATUS_RESOLVED = "resolved"
    STATUS_UNKNOWN = "unknown"
    STATUS_CHOICES = [
        (STATUS_CANDIDATE, "Candidate"),
        (STATUS_POTENTIALLY_AFFECTED, "Potentially affected"),
        (STATUS_VALIDATION_PENDING, "Validation pending"),
        (STATUS_VALIDATED, "Validated"),
        (STATUS_NOT_AFFECTED, "Not affected"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_UNKNOWN, "Unknown"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="cves")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    cve_id = models.CharField(max_length=32, db_index=True)
    product = models.CharField(max_length=256, db_index=True)
    vendor = models.CharField(max_length=256, default="", blank=True)
    detected_version = models.CharField(max_length=128, default="", blank=True)
    affected_range = models.CharField(max_length=512, default="", blank=True)
    asset_value = models.CharField(max_length=1024, default="", blank=True, db_index=True)
    confidence = models.CharField(max_length=16, default=STATUS_UNKNOWN)
    status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, default=STATUS_CANDIDATE, db_index=True
    )
    evidence = models.TextField(default="", blank=True)
    sources = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("target", "cve_id", "asset_value", "product")]

    def __str__(self):
        return self.cve_id


class SecurityFinding(models.Model):
    SEV_INFO = "INFO"
    SEV_LOW = "LOW"
    SEV_MEDIUM = "MEDIUM"
    SEV_HIGH = "HIGH"
    SEV_CRITICAL = "CRITICAL"
    SEV_CHOICES = [
        (SEV_INFO, "Info"),
        (SEV_LOW, "Low"),
        (SEV_MEDIUM, "Medium"),
        (SEV_HIGH, "High"),
        (SEV_CRITICAL, "Critical"),
    ]
    STATUS_NEW = "NEW"
    STATUS_OPEN = "OPEN"
    STATUS_CONFIRMED = "CONFIRMED"
    STATUS_VALIDATED = "VALIDATED"
    STATUS_REOPENED = "REOPENED"
    STATUS_FALSE_POSITIVE = "FALSE_POSITIVE"
    STATUS_RESOLVED = "RESOLVED"
    STATUS_UNKNOWN = "UNKNOWN"
    STATUS_CHOICES = [
        (STATUS_NEW, "New"),
        (STATUS_OPEN, "Open"),
        (STATUS_CONFIRMED, "Confirmed"),
        (STATUS_VALIDATED, "Validated"),
        (STATUS_REOPENED, "Reopened"),
        (STATUS_FALSE_POSITIVE, "False positive"),
        (STATUS_RESOLVED, "Resolved"),
        (STATUS_UNKNOWN, "Unknown"),
    ]
    target = models.ForeignKey("targets.Target", on_delete=models.CASCADE, related_name="findings")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    asset_value = models.CharField(max_length=1024, db_index=True)
    finding_type = models.CharField(max_length=128, db_index=True)
    title = models.CharField(max_length=512)
    severity = models.CharField(
        max_length=16, choices=SEV_CHOICES, default=SEV_MEDIUM, db_index=True
    )
    confidence = models.CharField(max_length=16, default=STATUS_UNKNOWN, db_index=True)
    template = models.CharField(max_length=256, default="", blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    source = models.CharField(max_length=64, default="nuclei", db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_NEW, db_index=True
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-first_seen"]

    def __str__(self):
        return f"[{self.severity}] {self.title[:80]}"


# --- Cross-target validation (TASK-003): impossible to link assets across targets ---
# E402: grouped here under a section header rather than hoisted to the top of
# the module; the import is only used by the helpers that follow it.
from django.core.exceptions import ValidationError as _VE  # noqa: E402


def _check_same_target(obj, other, name="reference"):
    if obj is None or other is None:
        return
    t1 = getattr(obj, "target_id", None)
    t2 = getattr(other, "target_id", None)
    if t1 is not None and t2 is not None and t1 != t2:
        raise _VE(f"Cross-target {name} rejected: target {t1} != target {t2}")


# Attach clean methods dynamically to keep migration-friendly
def _jsfinding_clean(self):
    if self.js_id and self.target_id and self.js.target_id != self.target_id:
        raise _VE("JavaScriptFinding target must match its JavaScriptAsset target")
    if not self.target_id and self.js_id:
        self.target = self.js.target


JavaScriptFinding.clean = _jsfinding_clean
