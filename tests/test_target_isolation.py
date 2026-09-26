"""Target isolation tests (TASK-064): A asset/event/scan/report/WS/alert never leaks to B."""
from django.test import TestCase

from apps.targets.models import Target


class TargetIsolationTests(TestCase):
    def setUp(self):
        self.a = Target.objects.create(name="a", root_domain="a.invalid")
        self.b = Target.objects.create(name="b", root_domain="b.invalid")

    def test_asset_never_in_other_query(self):
        from apps.assets.models import Subdomain
        Subdomain.objects.create(target=self.a, hostname="x.a.invalid")
        Subdomain.objects.create(target=self.b, hostname="x.b.invalid")
        self.assertEqual(Subdomain.objects.filter(target=self.a).count(), 1)
        self.assertFalse(Subdomain.objects.filter(target=self.a, hostname="x.b.invalid").exists())

    def test_event_never_in_other_dashboard(self):
        from apps.core.target_scoping import TargetEventService
        from services.event_engine.engine import emit_event
        emit_event("NEW_SUBDOMAIN", target=self.a, asset_value="x.a.invalid", source="t")
        emit_event("NEW_SUBDOMAIN", target=self.b, asset_value="x.b.invalid", source="t")
        recent_a = list(TargetEventService.recent(self.a, 10))
        self.assertTrue(all(e.target_id == self.a.id for e in recent_a))
        self.assertFalse(any(e.asset_value == "x.b.invalid" for e in recent_a))

    def test_scan_never_updates_other(self):
        from apps.assets.models import Subdomain
        from services.correlation.ingest import ingest_subdomains
        ingest_subdomains(self.a, [{"hostname": "n.a.invalid", "source": "t"}])
        self.assertFalse(Subdomain.objects.filter(target=self.b, hostname="n.a.invalid").exists())

    def test_report_single_target(self):
        from apps.assets.models import Subdomain
        from apps.core.target_scoping import TargetReportService
        s = Subdomain.objects.create(target=self.a, hostname="r.a.invalid")
        TargetReportService.assert_single_target([s], self.a)
        with self.assertRaises(Exception):
            TargetReportService.assert_single_target([s], self.b)

    def test_alert_contains_own_target(self):
        from apps.events.models import Alert
        from services.event_engine.engine import emit_event
        e, _ = emit_event("NEW_IP", target=self.a, asset_value="10.0.0.1", source="t", severity="HIGH")
        al = Alert.objects.filter(event=e).first()
        if al and al.target_id:
            self.assertEqual(al.target_id, self.a.id)

    def test_cross_target_reference_rejected(self):
        from apps.assets.models import JavaScriptAsset, JavaScriptFinding
        js = JavaScriptAsset.objects.create(target=self.a, js_url="https://a.example/x.js",
                                            host="a.example", sha256="a" * 64, size=1)
        f = JavaScriptFinding(js=js, target=self.b, finding_type="secret")
        with self.assertRaises(Exception):
            f.clean()

    def test_websocket_groups_isolated(self):
        # Consumer logic: target socket joins ONLY target_N (no global groups)
        import inspect

        from apps.events import consumers
        src = inspect.getsource(consumers.LiveConsumer.connect)
        self.assertIn("target_", src)

    # Task 1 regression: ingest_urls must reject out-of-scope hosts.
    def test_ingest_urls_rejects_out_of_scope_host(self):
        from apps.assets.models import URLAsset
        from services.correlation.ingest import ingest_urls
        ingest_urls(self.a, [{"url": "https://not-my-domain.example.org/a", "source": "gau"}])
        self.assertFalse(URLAsset.objects.filter(
            target=self.a, host="not-my-domain.example.org").exists())

    def test_ingest_urls_keeps_in_scope_host(self):
        from apps.assets.models import URLAsset
        from services.correlation.ingest import ingest_urls
        ingest_urls(self.a, [{"url": "https://web.a.invalid/app", "source": "gau"}])
        self.assertTrue(URLAsset.objects.filter(target=self.a, host="web.a.invalid").exists())


class DetailContextTests(TestCase):
    """Task 7: detail views enforce caller target context server-side."""

    def setUp(self):
        from django.contrib.auth.models import User
        from django.test import Client

        self.u = User.objects.create_user("viewer7", password="x")
        self.c = Client()
        self.c.force_login(self.u)
        self.a = Target.objects.create(name="a", root_domain="a.invalid")
        self.b = Target.objects.create(name="b", root_domain="b.invalid")

    def test_detail_view_without_target_param_on_fresh_session(self):
        """No context anywhere (fresh session) -> 200 under single-tenant design."""
        from apps.assets.models import Asset
        a = Asset.objects.create(target=self.a, asset_type="SUBDOMAIN", value="x.a.invalid")
        r = self.c.get(f"/assets/{a.pk}/")
        self.assertEqual(r.status_code, 200)

    def test_explicit_target_mismatch_denied(self):
        from apps.assets.models import Asset
        b = Asset.objects.create(target=self.b, asset_type="SUBDOMAIN", value="x.b.invalid")
        r = self.c.get(f"/assets/{b.pk}/?target={self.a.id}")
        self.assertEqual(r.status_code, 403)

    def test_session_context_mismatch_denied(self):
        """Picker context (session) for A + B object without param -> 403."""
        from apps.assets.models import Asset
        b = Asset.objects.create(target=self.b, asset_type="SUBDOMAIN", value="y.b.invalid")
        self.c.get(f"/subdomains/?target={self.a.id}")  # pins session to A
        r = self.c.get(f"/assets/{b.pk}/")
        self.assertEqual(r.status_code, 403)


class JsScopeTests(TestCase):
    """Task 2: out-of-scope <script src> hosts are never fetched."""

    def test_out_of_scope_script_not_fetched(self):
        import urllib.request
        from unittest.mock import patch
        from urllib.parse import urlparse

        from apps.assets.models import JavaScriptAsset
        from apps.jobs.tasks import host_url_discovery

        t = Target.objects.create(name="s", root_domain="scope.invalid",
                                  authorization_status=Target.AUTH_AUTHORIZED)

        class _FakeResp:
            def __init__(self, body):
                self._body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n=-1):
                return self._body[:n] if n and n > 0 else self._body

        calls = []

        def fake_urlopen(req, timeout=10, context=None):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            calls.append(url)
            host = urlparse(url).hostname or ""
            if host == "web.scope.invalid":
                return _FakeResp(b'<html><script src="https://evil.example.org/x.js">'
                                 b'</script><script src="/local.js"></script></html>')
            if url.endswith("/local.js"):
                return _FakeResp(b"var a=1;")
            raise AssertionError(f"unexpected outbound fetch: {url}")

        with patch.object(urllib.request, "urlopen", side_effect=fake_urlopen):
            host_url_discovery(t.id, "https://web.scope.invalid/", trigger="test")
        self.assertFalse(any("evil.example.org" in u for u in calls),
                         f"out-of-scope host was fetched: {calls}")
        self.assertTrue(JavaScriptAsset.objects.filter(
            target=t, js_url="https://web.scope.invalid/local.js").exists())
        self.assertFalse(JavaScriptAsset.objects.filter(
            target=t, js_url__icontains="evil.example.org").exists())
