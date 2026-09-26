from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class Profile(models.Model):
    ROLE_ADMIN = "ADMIN"
    ROLE_OPERATOR = "OPERATOR"
    ROLE_VIEWER = "VIEWER"
    ROLE_CHOICES = [(ROLE_ADMIN, "Admin"), (ROLE_OPERATOR, "Operator"), (ROLE_VIEWER, "Viewer")]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_VIEWER)
    # Task 27: setup.sh-created admins must change their password on first login.
    must_change_password = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} ({self.role})"

    @property
    def is_admin(self):
        return self.user.is_superuser or self.role == self.ROLE_ADMIN

    @property
    def is_operator(self):
        return self.is_admin or self.role == self.ROLE_OPERATOR


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        role = Profile.ROLE_ADMIN if instance.is_superuser else Profile.ROLE_VIEWER
        Profile.objects.create(user=instance, role=role)
