"""DRF API: paginated, filtered, authenticated. No execution endpoints."""
import django_filters
from django.contrib.auth.models import User
from rest_framework import serializers, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.assets.models import (APIEndpoint, CVE, HTTPService, IPAddress, JavaScriptAsset,
                                Port, SecurityFinding, Subdomain, Technology, URLAsset)
from apps.events.models import Alert, Event
from apps.jobs.models import JobLog, ScanJob
from apps.targets.models import Target


class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = ["id", "name", "root_domain", "status", "authorization_status",
                  "authorization_expires_at", "baseline_status", "last_scan", "next_scan",
                  "created_at", "updated_at"]


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
        exclude = ["command_redacted"]


class AuthViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        # TASK-079: no unrestricted cross-target export; when target param is
        # supplied it is authoritative and validated server-side.
        target = self.request.query_params.get("target")
        if target:
            try:
                tid = int(target)
            except ValueError:
                from rest_framework.exceptions import ValidationError as _VE
                raise _VE("invalid target id")
            model = qs.model
            if any(f.name == "target" for f in model._meta.get_fields()):
                return qs.filter(target_id=tid)
            if model.__name__ == "JavaScriptFinding":
                return qs.filter(js__target_id=tid)
            if model.__name__ == "Alert":
                return qs.filter(event__target_id=tid)
        return qs


class TargetViewSet(AuthViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    filterset_fields = ["status", "authorization_status"]
    search_fields = ["root_domain", "name"]


class SubdomainViewSet(AuthViewSet):
    queryset = Subdomain.objects.all()
    serializer_class = SubdomainSerializer
    filterset_fields = ["target", "dns_status", "is_active"]
    search_fields = ["hostname"]


class PortViewSet(AuthViewSet):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    filterset_fields = ["target", "state", "port"]
    search_fields = ["ip"]


class HTTPViewSet(AuthViewSet):
    queryset = HTTPService.objects.all()
    serializer_class = HTTPSerializer
    filterset_fields = ["target", "status_code"]
    search_fields = ["url", "host", "title"]


class URLViewSet(AuthViewSet):
    queryset = URLAsset.objects.all()
    serializer_class = URLSerializer
    filterset_fields = ["target", "source", "is_api"]
    search_fields = ["canonical_url", "host"]


class APIViewSet(AuthViewSet):
    queryset = APIEndpoint.objects.all()
    serializer_class = APISerializer
    filterset_fields = ["target", "api_type"]
    search_fields = ["url", "host"]


class JSViewSet(AuthViewSet):
    queryset = JavaScriptAsset.objects.all()
    serializer_class = JSSerializer
    filterset_fields = ["target"]
    search_fields = ["js_url", "sha256"]


class TechViewSet(AuthViewSet):
    queryset = Technology.objects.all()
    serializer_class = TechSerializer
    filterset_fields = ["target", "product"]
    search_fields = ["product", "asset_value"]


class CVEViewSet(AuthViewSet):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    filterset_fields = ["target", "status"]
    search_fields = ["cve_id", "product"]


class FindingViewSet(AuthViewSet):
    queryset = SecurityFinding.objects.all()
    serializer_class = FindingSerializer
    filterset_fields = ["target", "severity", "status"]
    search_fields = ["title", "asset_value"]


class EventViewSet(AuthViewSet):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    filterset_fields = ["event_type", "severity", "target"]
    search_fields = ["asset_value"]


class JobViewSet(AuthViewSet):
    queryset = ScanJob.objects.all()
    serializer_class = JobSerializer
    filterset_fields = ["target", "status", "job_type"]
