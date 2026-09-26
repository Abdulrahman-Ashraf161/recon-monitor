from django.conf import settings
from django.db import models

from apps.core.target_scoping import TargetScopedManager


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=128, db_index=True)
    object_type = models.CharField(max_length=128, default="", blank=True)
    object_id = models.CharField(max_length=128, default="", blank=True)
    old_value = models.TextField(default="", blank=True)
    new_value = models.TextField(default="", blank=True)
    target = models.ForeignKey("targets.Target", null=True, blank=True, on_delete=models.SET_NULL, related_name="audit_logs")
    objects = TargetScopedManager()
    all_objects = models.Manager()
    ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at} {self.user} {self.action} {self.object_type}:{self.object_id}"
