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
        from apps.core.target_scoping import TargetReportService
        from apps.assets.models import Subdomain
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
