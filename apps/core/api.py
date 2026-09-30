"""DRF API: paginated, filtered, and target-authorized (P0-007).

Every endpoint is **membership-scoped server-side**. The previous
implementation declared only ``IsAuthenticated`` and pointed every viewset at
``Model.objects.all()``, which meant:

* any authenticated user could list every target, every subdomain, every CVE
  and every job in the installation;
* omitting ``?target=`` returned the *entire* table, so the absence of a
  parameter widened the result set instead of narrowing it;
* supplying ``?target=<id>`` applied the id with no authorization check, so
  reading another tenant's assets was a single query parameter;
* the model-ownership path was inferred by string-matching class names
  (``model.__name__ == "JavaScriptFinding"``), which silently returned
  *unfiltered* data for any model it did not recognise.

Now each viewset declares its ownership path explicitly and
:meth:`AuthViewSet.get_queryset` resolves it through
:mod:`apps.core.authorization`.
"""

from rest_framework import serializers, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.assets.models import (
    CVE,
    APIEndpoint,
    HTTPService,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
    Technology,
    URLAsset,
)
from apps.core.authorization import (
    CAP_READ,
    authorized_target_ids,
    authorized_targets,
    get_authorized_target,
    global_admin_override,
)
from apps.events.models import Event
from apps.jobs.models import ScanJob
from apps.targets.models import Target


class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = [
            "id",
            "name",
            "root_domain",
            "status",
            "authorization_status",
            "authorization_expires_at",
            "baseline_status",
            "last_scan",
            "next_scan",
            "created_at",
            "updated_at",
        ]


class SubdomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = "__all__"


class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = "__all__"


class HTTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = HTTPService
        fields = "__all__"


class URLSerializer(serializers.ModelSerializer):
    class Meta:
        model = URLAsset
        fields = "__all__"


class APISerializer(serializers.ModelSerializer):
    class Meta:
        model = APIEndpoint
        fields = "__all__"


class JSSerializer(serializers.ModelSerializer):
    class Meta:
        model = JavaScriptAsset
        exclude = ["content"]


class TechSerializer(serializers.ModelSerializer):
    class Meta:
        model = Technology
        fields = "__all__"


class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = "__all__"


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityFinding
        fields = "__all__"


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = "__all__"


class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanJob
        # `command_redacted` is withheld: even a redacted command line is
        # needless exposure of tool paths and arguments through a read API.
        # (ScanJob has no raw `command` field; that column lives on
        # ToolExecution, which is not exposed by the API.)
        # `run_id_legacy` is migration bookkeeping for pre-ScanRun rows, not
        # part of the supported surface.
        exclude = ["command_redacted", "run_id_legacy"]


def _split_lookup(target_lookup):
    """('event__target' -> ('event__target', 'target_id')) for filtering."""
    head, _, tail = target_lookup.rpartition("__")
    if head:
        return f"{head}__{tail}_id", f"{head}__{tail}__in"
    return f"{tail}_id", f"{tail}__in"


class AuthViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only, membership-scoped base viewset.

    Subclasses set :attr:`target_lookup` to the ORM path from this model to its
    owning ``Target`` (``"target"``, ``"event__target"``, ``"js__target"``), or
    ``None`` when the model *is* a Target.
    """

    permission_classes = [IsAuthenticated]
    target_lookup = "target"
    # Default ordering. Without it DRF paginates an unordered queryset, which
    # can repeat or skip rows across pages (UnorderedObjectListWarning).
    # `?ordering=` still works via the configured OrderingFilter.
    ordering = ["-id"]

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        raw = self.request.query_params.get("target")

        # The Target model is scoped by membership directly.
        if self.target_lookup is None:
            if raw:
                # Still authoritative: an unowned id must be 403/404, never a
                # silent "here is your whole target list".
                return qs.filter(pk=get_authorized_target(user, raw, capability=CAP_READ).pk)
            return authorized_targets(user)

        # An explicit target is validated for everyone, administrators included,
        # so `?target=` always means "this target" and never "everything".
        if raw:
            target = get_authorized_target(user, raw, capability=CAP_READ)
            id_filter, _ = _split_lookup(self.target_lookup)
            return qs.filter(**{id_filter: target.pk})

        # Explicit global administrators keep full portfolio visibility.
        if global_admin_override(user):
            return qs

        ids = authorized_target_ids(user)
        if not ids:
            return qs.none()
        _, in_filter = _split_lookup(self.target_lookup)
        return qs.filter(**{in_filter: ids})


class TargetViewSet(AuthViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    target_lookup = None
    filterset_fields = ["status", "authorization_status"]
    search_fields = ["root_domain", "name"]


class SubdomainViewSet(AuthViewSet):
    queryset = Subdomain.objects.all()
    serializer_class = SubdomainSerializer
    filterset_fields = ["dns_status", "is_active"]
    search_fields = ["hostname"]


class PortViewSet(AuthViewSet):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    filterset_fields = ["state", "port"]
    search_fields = ["ip"]


class HTTPViewSet(AuthViewSet):
    queryset = HTTPService.objects.all()
    serializer_class = HTTPSerializer
    filterset_fields = ["status_code"]
    search_fields = ["url", "host", "title"]


class URLViewSet(AuthViewSet):
    queryset = URLAsset.objects.all()
    serializer_class = URLSerializer
    filterset_fields = ["source", "is_api"]
    search_fields = ["canonical_url", "host"]


class APIViewSet(AuthViewSet):
    queryset = APIEndpoint.objects.all()
    serializer_class = APISerializer
    filterset_fields = ["api_type"]
    search_fields = ["url", "host"]


class JSViewSet(AuthViewSet):
    queryset = JavaScriptAsset.objects.all()
    serializer_class = JSSerializer
    search_fields = ["js_url", "sha256"]


class TechViewSet(AuthViewSet):
    queryset = Technology.objects.all()
    serializer_class = TechSerializer
    filterset_fields = ["product"]
    search_fields = ["product", "asset_value"]


class CVEViewSet(AuthViewSet):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    filterset_fields = ["status"]
    search_fields = ["cve_id", "product"]


class FindingViewSet(AuthViewSet):
    queryset = SecurityFinding.objects.all()
    serializer_class = FindingSerializer
    filterset_fields = ["severity", "status"]
    search_fields = ["title", "asset_value"]


class EventViewSet(AuthViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    filterset_fields = ["event_type", "severity"]
    search_fields = ["asset_value"]


class JobViewSet(AuthViewSet):
    queryset = ScanJob.objects.all()
    serializer_class = JobSerializer
    filterset_fields = ["status", "job_type"]


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def api_health(request):
    """Deployment health, scoped: tool detail is only for administrators."""
    from apps.core.permissions import role_of
    from services.tool_adapters.adapters import tool_health

    tools = tool_health()
    ok_tools = sum(1 for t in tools if t["status"] == "OK")
    payload = {
        "status": "ok" if ok_tools == len(tools) else "degraded",
        "tools": {"ok": ok_tools, "total": len(tools)},
    }
    if role_of(request.user) == "ADMIN":
        payload["tools"]["detail"] = tools
    return Response(payload)
