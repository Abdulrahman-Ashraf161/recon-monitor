"""Scope rules: allowed/excluded hosts, IPs, ports, rate limits."""

from django.conf import settings
from django.db import models

from apps.core.target_scoping import TargetScopedManager


class ScopeRule(models.Model):
    RULE_ALLOW_DOMAIN = "allow_domain"
    RULE_EXCLUDE_HOST = "exclude_host"
    RULE_ALLOW_IP = "allow_ip"
    RULE_EXCLUDE_IP = "exclude_ip"
    RULE_PORT = "port"
    RULE_RATE_LIMIT = "rate_limit"
    RULE_CONCURRENCY = "concurrency"
    RULE_CHOICES = [
        (RULE_ALLOW_DOMAIN, "Allowed domain"),
        (RULE_EXCLUDE_HOST, "Excluded host"),
        (RULE_ALLOW_IP, "Allowed IP/CIDR"),
        (RULE_EXCLUDE_IP, "Excluded IP/CIDR"),
        (RULE_PORT, "Port/range"),
        (RULE_RATE_LIMIT, "Rate limit"),
        (RULE_CONCURRENCY, "Concurrency"),
    ]
    target = models.ForeignKey(
        "targets.Target",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="scope_rules",
    )
    objects = TargetScopedManager()
    all_objects = models.Manager()
    rule_type = models.CharField(max_length=32, choices=RULE_CHOICES, db_index=True)
    value = models.CharField(max_length=512)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["rule_type", "value"]

    def __str__(self):
        scope = self.target.root_domain if self.target else "global"
        return f"{scope}: {self.rule_type}={self.value}"
