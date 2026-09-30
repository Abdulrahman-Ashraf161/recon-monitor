"""Record IP + user on requests for audit middleware context."""

from django.utils.deprecation import MiddlewareMixin


class AuditMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.audit_ip = request.META.get("REMOTE_ADDR")
        return None
