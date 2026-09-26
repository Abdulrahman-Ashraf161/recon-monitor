"""Task 27: password-change view that clears the forced-change flag."""
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
        except Exception:
            pass
        return resp
