"""Role helpers + audit helper."""

import logging
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

logger = logging.getLogger(__name__)


def role_of(user):
    if not user.is_authenticated:
        return "ANON"
    if user.is_superuser:
        return "ADMIN"
    profile = getattr(user, "profile", None)
    if profile is None:
        # No profile row yet: treat as least privilege, never as elevated.
        return "VIEWER"
    return profile.role


def require_roles(*roles):
    def deco(view):
        @wraps(view)
        @login_required
        def inner(request, *args, **kwargs):
            if role_of(request.user) not in roles and not request.user.is_superuser:
                if "ADMIN" in roles and role_of(request.user) == "ADMIN":
                    pass
                else:
                    raise PermissionDenied
            return view(request, *args, **kwargs)

        return inner

    return deco


require_admin = require_roles("ADMIN")
require_operator = require_roles("ADMIN", "OPERATOR")
require_viewer = require_roles("ADMIN", "OPERATOR", "VIEWER")


def audit(request, action, obj=None, old="", new=""):
    """Persist an audit record.

    Audit rows are security evidence: a write failure is logged loudly and
    re-raised to the caller, never swallowed. The previous bare
    ``except Exception: pass`` silently discarded every audit failure
    (P1-003 / P2 observability).
    """
    from apps.audit.models import AuditLog

    try:
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            action=action,
            object_type=type(obj).__name__ if obj else "",
            object_id=str(getattr(obj, "pk", "") or ""),
            old_value=str(old)[:2000],
            new_value=str(new)[:2000],
            ip=request.META.get("REMOTE_ADDR"),
        )
    except Exception:
        logger.exception("audit log write failed", extra={"operation": action, "status": "ERROR"})
        raise
