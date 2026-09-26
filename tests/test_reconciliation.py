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
