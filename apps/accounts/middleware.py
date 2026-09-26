"""Task 27: force password change for setup-created admins until cleared."""
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
                    exempt_urls = {reverse(n) for n in self.EXEMPT_NAMES
                                   if n in ("logout", "password_change", "password_change_done")}
                except Exception:
                    exempt_urls = set()
                if path not in exempt_urls and not path.startswith(self.EXEMPT_PREFIXES):
                    try:
                        return redirect(reverse("password_change"))
                    except Exception:
                        pass
        return self.get_response(request)
