from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .api import (
    APIViewSet,
    CVEViewSet,
    EventViewSet,
    FindingViewSet,
    HTTPViewSet,
    JobViewSet,
    JSViewSet,
    PortViewSet,
    SubdomainViewSet,
    TargetViewSet,
    TechViewSet,
    URLViewSet,
)

router = DefaultRouter()
router.register("targets", TargetViewSet, basename="api-targets")
router.register("subdomains", SubdomainViewSet, basename="api-subdomains")
router.register("ports", PortViewSet, basename="api-ports")
router.register("http", HTTPViewSet, basename="api-http")
router.register("urls", URLViewSet, basename="api-urls")
router.register("apis", APIViewSet, basename="api-apis")
router.register("javascript", JSViewSet, basename="api-js")
router.register("technologies", TechViewSet, basename="api-tech")
router.register("cves", CVEViewSet, basename="api-cves")
router.register("findings", FindingViewSet, basename="api-findings")
router.register("events", EventViewSet, basename="api-events")
router.register("jobs", JobViewSet, basename="api-jobs")

urlpatterns = [path("", include(router.urls))]
