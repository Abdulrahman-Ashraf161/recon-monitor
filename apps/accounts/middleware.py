"""Force a password change for setup-created admins until it is cleared (Task 27)."""

import logging

from django.shortcuts import redirect
from django.urls import reverse


class MustChangePasswordMiddleware:
    EXEMPT_NAMES = {"logout", "password_change", "password_change_done"}
    EXEMPT_PREFIXES = ("/admin/", "/static/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            try:
                must = user.profile.must_change_password
            except Exception:
                must = False
            if must:
                path = request.path
                try:
                    exempt_urls = {
                        reverse(n)
                        for n in self.EXEMPT_NAMES
                        if n in ("logout", "password_change", "password_change_done")
                    }
                except Exception as exc:
                    # FINAL-001: a failure here would lock every user out of the
                    # logout/change-password routes, so it is logged, not silent.
                    exempt_urls = set()
                    logger.warning(
                        "forced-password-change exempt URLs could not be " "resolved: %s",
                        exc.__class__.__name__,
                    )
                if path not in exempt_urls and not path.startswith(self.EXEMPT_PREFIXES):
                    try:
                        return redirect(reverse("password_change"))
                    except Exception as exc:
                        # Do not silently fall through: the user would keep
                        # browsing with a password they were told to change.
                        logger.warning(
                            "password-change redirect failed (%s); " "allowing the request through",
                            exc.__class__.__name__,
                        )
        return self.get_response(request)


logger = logging.getLogger(__name__)
