"""Characterization tests for asset list views (Task 21).

Covers every list view's default response, scoping (?target=), each documented
filter param, and invalid params (?page=abc, ?target=not-an-int,
?page=99999). Written BEFORE the Task 20 DRY refactor; must pass identically
before and after it. Invalid-?target= behavior encodes the Task 22 contract
(empty page + notice, never 500).

P2-009: the viewer is now granted membership on BOTH targets. Previously this
user had no membership at all and the unpinned "All targets" pages returned
every asset in the installation -- these expectations therefore encoded the
cross-target leak. Cross-target isolation is asserted in
tests/test_security_regression.py and tests/test_target_isolation.py.
"""

from django.contrib.auth.models import User
from django.test import Client, TestCase

from apps.assets.models import (
    CVE,
    APIEndpoint,
    HTTPService,
    IPAddress,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
    Technology,
    URLAsset,
)
from apps.targets.models import Target, TargetMembership


def _vals(page):
    return list(page.object_list)


class AssetViewsTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("viewer", password="x")
        self.c = Client()
        self.c.force_login(self.u)
        self.a = Target.objects.create(name="a", root_domain="a.invalid")
        self.b = Target.objects.create(name="b", root_domain="b.invalid")
        # the viewer is a member of both targets: the list views must show both,
        # and must never show anything this user is not a member of (P2-009)
        for _t in (self.a, self.b):
            TargetMembership.objects.create(
                user=self.u, target=_t, role=TargetMembership.ROLE_VIEWER
            )
        Subdomain.objects.create(target=self.a, hostname="web.a.invalid", sources=["s"])
        Subdomain.objects.create(target=self.b, hostname="web.b.invalid", sources=["s"])
        IPAddress.objects.create(target=self.a, ip="192.0.2.1")
        IPAddress.objects.create(target=self.b, ip="192.0.2.2")
        Port.objects.create(target=self.a, ip="192.0.2.1", port=80, protocol="tcp", state="open")
        Port.objects.create(target=self.b, ip="192.0.2.2", port=22, protocol="tcp", state="open")
        HTTPService.objects.create(
            target=self.a,
            url="https://web.a.invalid/",
            host="web.a.invalid",
            status_code=200,
            title="A",
        )
        HTTPService.objects.create(
            target=self.b,
            url="https://web.b.invalid/",
            host="web.b.invalid",
            status_code=404,
            title="B",
        )
        URLAsset.objects.create(
            target=self.a,
            raw_url="https://web.a.invalid/x",
            canonical_url="https://web.a.invalid/x",
            host="web.a.invalid",
            source="gau",
        )
        URLAsset.objects.create(
            target=self.b,
            raw_url="https://web.b.invalid/x",
            canonical_url="https://web.b.invalid/x",
            host="web.b.invalid",
            source="katana",
        )
        APIEndpoint.objects.create(
            target=self.a,
            url="https://web.a.invalid/api/v1/u",
            host="web.a.invalid",
            method="GET",
            api_type="REST",
        )
        JavaScriptAsset.objects.create(
            target=self.a,
            js_url="https://web.a.invalid/a.js",
            host="web.a.invalid",
            sha256="a" * 64,
            size=10,
        )
        JavaScriptAsset.objects.create(
            target=self.b,
            js_url="https://web.b.invalid/b.js",
            host="web.b.invalid",
            sha256="b" * 64,
            size=10,
        )
        Technology.objects.create(
            target=self.a, asset_value="https://web.a.invalid/", product="nginx", version="1.0"
        )
        Technology.objects.create(
            target=self.b, asset_value="https://web.b.invalid/", product="apache", version="2.0"
        )
        CVE.objects.create(
            target=self.a,
            cve_id="CVE-2024-0001",
            product="nginx",
            asset_value="https://web.a.invalid/",
            status="candidate",
        )
        CVE.objects.create(
            target=self.b,
            cve_id="CVE-2024-0002",
            product="apache",
            asset_value="https://web.b.invalid/",
            status="validated",
        )
        SecurityFinding.objects.create(
            target=self.a,
            asset_value="https://web.a.invalid/",
            finding_type="t",
            title="FA",
            severity="HIGH",
            status="NEW",
        )
        SecurityFinding.objects.create(
            target=self.b,
            asset_value="https://web.b.invalid/",
            finding_type="t",
            title="FB",
            severity="LOW",
            status="RESOLVED",
        )

    # -- subdomain_list --
    def test_subdomain_default_and_target(self):
        r = self.c.get("/subdomains/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(_vals(r.context["page"])), 2)
        r = self.c.get(f"/subdomains/?target={self.a.id}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([s.hostname for s in _vals(r.context["page"])], ["web.a.invalid"])

    def test_subdomain_q_filter(self):
        r = self.c.get("/subdomains/?q=web.a")
        self.assertEqual([s.hostname for s in _vals(r.context["page"])], ["web.a.invalid"])

    # -- port_list (?state=, ?q=) --
    def test_port_state_and_q(self):
        r = self.c.get("/ports/?state=open")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(_vals(r.context["page"])), 2)
        r = self.c.get("/ports/?state=closed")
        self.assertEqual(len(_vals(r.context["page"])), 0)
        r = self.c.get("/ports/?q=192.0.2.1")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r = self.c.get(f"/ports/?target={self.b.id}")
        self.assertEqual([p.port for p in _vals(r.context["page"])], [22])

    # -- http_list (?status=, ?q=) --
    def test_http_status_and_q(self):
        r = self.c.get("/http/?status=200")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r = self.c.get("/http/?q=web.b.invalid")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r = self.c.get(f"/http/?target={self.a.id}&status=404")
        self.assertEqual(len(_vals(r.context["page"])), 0)

    # -- url_list (?source=, ?q=) --
    def test_url_source_and_q(self):
        r = self.c.get("/urls/?source=gau")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r = self.c.get("/urls/?q=web.b.invalid")
        self.assertEqual(len(_vals(r.context["page"])), 1)

    # -- api_list (?q=) --
    def test_api_q_and_target(self):
        r = self.c.get("/apis/?q=api/v1")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r = self.c.get(f"/apis/?target={self.b.id}")
        self.assertEqual(len(_vals(r.context["page"])), 0)

    # -- js_list (?q=) + scoped totals (Task 8) --
    def test_js_q_and_scoped_totals(self):
        r = self.c.get("/javascript/?q=a.js")
        self.assertEqual(len(_vals(r.context["page"])), 1)
        r_all = self.c.get("/javascript/")
        self.assertEqual(r_all.context["totals"]["total"], 2)
        r_a = self.c.get(f"/javascript/?target={self.a.id}")
        self.assertEqual(r_a.context["totals"]["total"], 1)
        self.assertEqual(len(_vals(r_a.context["page"])), 1)

    # -- tech_list (?q=) --
    def test_tech_q_and_target(self):
        r = self.c.get("/technologies/?q=nginx")
        self.assertEqual([t.product for t in _vals(r.context["page"])], ["nginx"])
        r = self.c.get(f"/technologies/?target={self.b.id}")
        self.assertEqual([t.product for t in _vals(r.context["page"])], ["apache"])

    # -- cve_list (?status=, ?q=) --
    def test_cve_status_and_q(self):
        r = self.c.get("/cves/?status=validated")
        self.assertEqual([c.cve_id for c in _vals(r.context["page"])], ["CVE-2024-0002"])
        r = self.c.get("/cves/?q=CVE-2024-0001")
        self.assertEqual(len(_vals(r.context["page"])), 1)

    # -- finding_list (?severity=, ?status=) --
    def test_finding_severity_and_status(self):
        r = self.c.get("/findings/?severity=HIGH")
        self.assertEqual([f.title for f in _vals(r.context["page"])], ["FA"])
        r = self.c.get("/findings/?status=RESOLVED")
        self.assertEqual([f.title for f in _vals(r.context["page"])], ["FB"])

    # -- ip_list --
    def test_ip_target(self):
        r = self.c.get(f"/assets/ips/?target={self.a.id}")
        self.assertEqual([i.ip for i in _vals(r.context["page"])], ["192.0.2.1"])

    # -- invalid params never 500 (Task 22 contract) --
    def test_invalid_page_param(self):
        for url in ("/subdomains/?page=abc", "/ports/?page=abc", "/javascript/?page=abc"):
            r = self.c.get(url)
            self.assertEqual(r.status_code, 200, url)

    def test_invalid_target_param(self):
        r = self.c.get("/subdomains/?target=not-an-int")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(_vals(r.context["page"])), 0)

    def test_nonexistent_target_param(self):
        r = self.c.get("/subdomains/?target=999999")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(_vals(r.context["page"])), 0)

    def test_page_overflow_clamps(self):
        r = self.c.get("/subdomains/?page=99999")
        self.assertEqual(r.status_code, 200)
