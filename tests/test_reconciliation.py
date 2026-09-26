"""Reconciliation + lifecycle tests (TASK-010..013, TASK-032, change scenarios A-K)."""
from django.test import TestCase

from apps.targets.models import Target


class SubdomainLifecycleTests(TestCase):
    def test_new_removed_reactivated_no_false_new(self):
        from apps.events.models import Event
        from services.correlation.ingest import ingest_subdomains
        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_subdomains(t, [{"hostname": "api.example.invalid", "source": "s"}])
        self.assertEqual(Event.objects.filter(event_type="NEW_SUBDOMAIN").count(), 1)
        # same again: no dup
        ingest_subdomains(t, [{"hostname": "api.example.invalid", "source": "s"}])
        self.assertEqual(Event.objects.filter(event_type="NEW_SUBDOMAIN").count(), 1)
        # simulate removal via reconcile path
        from apps.assets.models import Subdomain
        from services.event_engine.engine import emit_event
        sub = Subdomain.objects.get(target=t)
        sub.is_active = False
        sub.state = "REMOVED"
        sub.save()
        emit_event("SUBDOMAIN_REMOVED", target=t, asset_type="SUBDOMAIN", asset_id=sub.id,
                   asset_value=sub.hostname, source="reconcile")
        self.assertEqual(Event.objects.filter(event_type="SUBDOMAIN_REMOVED").count(), 1)
        self.assertEqual(Event.objects.filter(event_type="NEW_SUBDOMAIN").count(), 1)
        # returns -> reactivated, not new
        ingest_subdomains(t, [{"hostname": "api.example.invalid", "source": "s"}])
        self.assertEqual(Event.objects.filter(event_type="SUBDOMAIN_REACTIVATED").count(), 1)
        self.assertEqual(Event.objects.filter(event_type="NEW_SUBDOMAIN").count(), 1)


class DiffEngineTests(TestCase):
    def test_added_removed_changed(self):
        from services.diff_engine import diff_snapshots, normalize_snapshot
        prev = normalize_snapshot([{"k": "a", "v": 1}, {"k": "b", "v": 1}],
                                  lambda x: x["k"], lambda x: {"v": x["v"]})
        cur = normalize_snapshot([{"k": "a", "v": 2}, {"k": "c", "v": 1}],
                                 lambda x: x["k"], lambda x: {"v": x["v"]})
        d = diff_snapshots(prev, cur)
        self.assertIn("c", d["added"])
        self.assertIn("b", d["removed"])
        self.assertIn("a", d["changed"])
        self.assertEqual(d["changed"]["a"]["old_state"], {"v": 1})

    def test_http_fingerprint_stable(self):
        from services.http_fingerprint import http_fingerprint
        e = {"scheme": "https", "host": "x.com", "port": 443, "status_code": 200, "title": "t"}
        self.assertEqual(http_fingerprint(e), http_fingerprint(dict(e)))

    def test_event_fingerprint_state_aware(self):
        from services.event_engine.engine import make_fingerprint
        f1 = make_fingerprint("HTTP_SERVICE_CHANGED", "https://x", target_id=1,
                              old_state={"s": 200}, new_state={"s": 403})
        f2 = make_fingerprint("HTTP_SERVICE_CHANGED", "https://x", target_id=1,
                              old_state={"s": 200}, new_state={"s": 403})
        f3 = make_fingerprint("HTTP_SERVICE_CHANGED", "https://x", target_id=1,
                              old_state={"s": 403}, new_state={"s": 500})
        self.assertEqual(f1, f2)
        self.assertNotEqual(f1, f3)


class ChangeScenarioTests(TestCase):
    """Phase 27 scenarios: C-J spot checks."""

    def test_ip_change_old_new(self):
        from apps.events.models import Event
        from services.event_engine.engine import emit_event
        t = Target.objects.create(name="t", root_domain="example.invalid")
        emit_event("IP_CHANGED", target=t, asset_value="1.2.3.4", source="dns",
                   old_state={"ip": "1.2.3.4"}, new_state={"ip": "5.6.7.8"})
        e = Event.objects.get(event_type="IP_CHANGED")
        self.assertEqual(e.old_state["ip"], "1.2.3.4")

    def test_http_200_to_403(self):
        from services.correlation.ingest import ingest_http
        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_http(t, [{"url": "https://example.invalid/", "host": "example.invalid",
                         "status_code": 200, "title": "a"}])
        n, c = ingest_http(t, [{"url": "https://example.invalid/", "host": "example.invalid",
                                "status_code": 403, "title": "a"}])
        self.assertEqual(c, 1)

    def test_js_semantic_children(self):
        from apps.events.models import Event
        from services.correlation.ingest import ingest_js
        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_js(t, "https://example.invalid/a.js", b"var a='/api/v1/x';", source="t")
        ingest_js(t, "https://example.invalid/a.js", b"var a='/api/v1/x'; var b='/api/v2/admin';", source="t")
        self.assertTrue(Event.objects.filter(event_type="JS_CHANGED").exists())

    def test_url_normalization_dedup(self):
        from services.correlation.ingest import ingest_urls
        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_urls(t, [{"url": "HTTPS://Example.INVALID:443/A?b=2&a=1", "source": "gau"}])
        ingest_urls(t, [{"url": "https://example.invalid/A?a=1&b=2", "source": "katana"}])
        from apps.assets.models import URLAsset
        self.assertEqual(URLAsset.objects.filter(target=t).count(), 1)

    def test_cve_candidate_not_confirmed(self):
        from services.correlation.ingest import ingest_technology
        t = Target.objects.create(name="t", root_domain="example.invalid")
        tech, _ = ingest_technology(t, "https://example.invalid/", "nginx", "1.25.0", 0.9, "srv", "httpx")
        from apps.assets.models import CVE
        for c in CVE.objects.filter(target=t):
            self.assertNotEqual(c.status, "validated")


class IpApiReconciliationTests(TestCase):
    """Task 9: IPAddress + APIEndpoint lifecycle (IP_REMOVED/API_ENDPOINT_REMOVED)."""

    def _authorized_target(self, name):
        return Target.objects.create(name=name, root_domain=f"{name}.invalid",
                                     authorization_status=Target.AUTH_AUTHORIZED)

    def _stale(self, model, **kw):
        from datetime import timedelta

        from django.utils import timezone
        obj = model.objects.create(**kw)
        model.objects.filter(pk=obj.pk).update(
            last_seen=timezone.now() - timedelta(days=30))
        obj.refresh_from_db()
        return obj

    def test_ip_reconciliation_marks_removed(self):
        from apps.assets.models import IPAddress
        from apps.events.models import Event
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import reconcile_target
        t = self._authorized_target("iprec")
        ScanJob.objects.create(target=t, job_type="dns", status=ScanJob.STATUS_COMPLETED)
        ip = self._stale(IPAddress, target=t, ip="192.0.2.9")
        out = reconcile_target(t.id)
        self.assertEqual(out["status"], "COMPLETED")
        ip.refresh_from_db()
        self.assertFalse(ip.is_active)
        self.assertEqual(ip.state, "REMOVED")
        self.assertTrue(Event.objects.filter(event_type="IP_REMOVED", target=t).exists())

    def test_ip_with_live_dns_record_kept(self):
        """Task 9 edge: IP still referenced by a fresh DNS record is NOT removed."""
        from apps.assets.models import DNSRecord, IPAddress
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import reconcile_target
        t = self._authorized_target("ipkeep")
        ScanJob.objects.create(target=t, job_type="dns", status=ScanJob.STATUS_COMPLETED)
        ip = self._stale(IPAddress, target=t, ip="192.0.2.10")
        DNSRecord.objects.create(target=t, hostname="x.ipkeep.invalid",
                                 record_type="A", value="192.0.2.10")
        reconcile_target(t.id)
        ip.refresh_from_db()
        self.assertTrue(ip.is_active)

    def test_api_endpoint_reconciliation_marks_removed(self):
        from apps.assets.models import APIEndpoint
        from apps.events.models import Event
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import reconcile_target
        t = self._authorized_target("apirec")
        ScanJob.objects.create(target=t, job_type="urls", status=ScanJob.STATUS_COMPLETED)
        ep = self._stale(APIEndpoint, target=t, url="https://apirec.invalid/api/v1/x",
                         host="apirec.invalid", method="GET")
        reconcile_target(t.id)
        ep.refresh_from_db()
        self.assertEqual(ep.state, "REMOVED")
        self.assertTrue(Event.objects.filter(event_type="API_ENDPOINT_REMOVED", target=t).exists())


class ReconcileGraceTests(TestCase):
    """Task 11: configurable grace + no-baseline gate."""

    def test_no_baseline_yet_skipped(self):
        from apps.jobs.tasks import reconcile_target
        t = Target.objects.create(name="fresh", root_domain="fresh.invalid",
                                  authorization_status=Target.AUTH_AUTHORIZED)
        out = reconcile_target(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertEqual(out["reason"], "no_baseline_yet")

    def test_custom_grace_respected(self):
        from datetime import timedelta

        from django.utils import timezone

        from apps.assets.models import Subdomain
        from apps.events.models import Event
        from apps.jobs.models import ScanJob
        from apps.jobs.tasks import reconcile_target
        t = Target.objects.create(name="grace", root_domain="grace.invalid",
                                  authorization_status=Target.AUTH_AUTHORIZED,
                                  reconciliation_grace_days=30)
        ScanJob.objects.create(target=t, job_type="dns", status=ScanJob.STATUS_COMPLETED)
        Subdomain.objects.create(target=t, hostname="old.grace.invalid")
        Subdomain.objects.filter(target=t).update(
            last_seen=timezone.now() - timedelta(days=20))
        reconcile_target(t.id)
        sub = Subdomain.objects.get(target=t)
        self.assertTrue(sub.is_active)  # 20d < 30d grace
        self.assertFalse(Event.objects.filter(event_type="SUBDOMAIN_REMOVED").exists())
        t.reconciliation_grace_days = 14
        t.save(update_fields=["reconciliation_grace_days"])
        reconcile_target(t.id)
        sub.refresh_from_db()
        self.assertFalse(sub.is_active)  # 20d > 14d grace


class UrlLastSeenTests(TestCase):
    """Task 10: re-observed URLs/APIs get last_seen bumped."""

    def test_reingest_bumps_last_seen(self):
        from datetime import timedelta

        from django.utils import timezone

        from apps.assets.models import APIEndpoint, URLAsset
        from services.correlation.ingest import ingest_urls
        t = Target.objects.create(name="seen", root_domain="seen.invalid")
        ingest_urls(t, [{"url": "https://seen.invalid/api/v1/a", "source": "gau"}])
        past = timezone.now() - timedelta(hours=1)
        URLAsset.objects.filter(target=t).update(last_seen=past)
        APIEndpoint.objects.filter(target=t).update(last_seen=past)
        ingest_urls(t, [{"url": "https://seen.invalid/api/v1/a", "source": "katana"}])
        u = URLAsset.objects.get(target=t)
        self.assertGreater(u.last_seen, past)
        ep = APIEndpoint.objects.get(target=t)
        self.assertGreater(ep.last_seen, past)
