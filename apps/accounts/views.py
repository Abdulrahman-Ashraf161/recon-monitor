"""Password-change view that clears the forced-change flag (Task 27)."""

import logging

from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy


class ClearingPasswordChangeView(PasswordChangeView):
    template_name = "accounts/password_change.html"
    success_url = reverse_lazy("password_change_done")

    def form_valid(self, form):
        resp = super().form_valid(form)
        try:
            profile = self.request.user.profile
            if profile.must_change_password:
                profile.must_change_password = False
                profile.save(update_fields=["must_change_password"])
        except Exception as exc:
            # FINAL-001: the flag would stay set, so the middleware would keep
            # redirecting the user to the change-password page forever.
            logger.error(
                "clearing must_change_password failed for user %s: %s",
                getattr(self.request.user, "pk", None),
                exc.__class__.__name__,
            )
        return resp


logger = logging.getLogger(__name__)
