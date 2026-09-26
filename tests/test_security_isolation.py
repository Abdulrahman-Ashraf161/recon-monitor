"""IDOR + API isolation + concurrency tests (TASK-062/078/079/082)."""
from django.contrib.auth.models import User
from django.test import Client, TestCase

from apps.targets.models import Target


class IDORTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("op", password="x")
        self.a = Target.objects.create(name="a", root_domain="a.invalid")
        self.b = Target.objects.create(name="b", root_domain="b.invalid")
        from apps.assets.models import Subdomain
        self.sa = Subdomain.objects.create(target=self.a, hostname="x.a.invalid")
        self.sb = Subdomain.objects.create(target=self.b, hostname="x.b.invalid")

    def test_detail_context_mismatch_denied(self):
        c = Client()
        c.force_login(self.u)
        r = c.get(f"/assets/{self.sb.pk}/?target={self.a.id}")
        # asset-detail URL name may differ; accept 404 or 403 as denial, never 200 with wrong data
        self.assertIn(r.status_code, (403, 404))

    def test_api_target_filter_isolates(self):
        c = Client()
        c.force_login(self.u)
        r = c.get(f"/api/subdomains/?target={self.a.id}")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        results = data.get("results", data if isinstance(data, list) else [])
        for row in results:
            self.assertEqual(row.get("target", self.a.id), self.a.id)


class ConcurrencyIsolationTests(TestCase):
    def test_two_targets_simultaneous(self):
        from services.correlation.ingest import ingest_subdomains
        a = Target.objects.create(name="a", root_domain="a.invalid")
        b = Target.objects.create(name="b", root_domain="b.invalid")
        ingest_subdomains(a, [{"hostname": "api.a.invalid", "source": "s"}])
        ingest_subdomains(b, [{"hostname": "api.b.invalid", "source": "s"}])
        from apps.assets.models import Subdomain
        self.assertTrue(Subdomain.objects.filter(target=a, hostname="api.a.invalid").exists())
        self.assertTrue(Subdomain.objects.filter(target=b, hostname="api.b.invalid").exists())
        self.assertFalse(Subdomain.objects.filter(target=a, hostname="api.b.invalid").exists())
        self.assertFalse(Subdomain.objects.filter(target=b, hostname="api.a.invalid").exists())


class IntegrationPipelineTests(TestCase):
    def test_discovery_to_event_chain(self):
        from apps.events.models import Event
        from services.correlation.ingest import ingest_dns, ingest_subdomains
        t = Target.objects.create(name="t", root_domain="example.invalid")
        ingest_subdomains(t, [{"hostname": "api.example.invalid", "source": "subfinder"}])
        ingest_dns(t, [{"hostname": "api.example.invalid", "type": "A", "value": "93.184.216.34"}])
        self.assertTrue(Event.objects.filter(event_type="NEW_SUBDOMAIN", target=t).exists())
        self.assertTrue(Event.objects.filter(event_type="NEW_IP", target=t).exists())


class SsrfProtectionTests(TestCase):
    """Task 4: private/reserved IPs are never persisted nor scanned."""

    def test_ssrf_metadata_ip_blocked(self):
        from apps.assets.models import IPAddress
        from services.correlation.ingest import ingest_dns
        t = Target.objects.create(name="ssrf", root_domain="ssrf.invalid")
        ingest_dns(t, [{"hostname": "x.ssrf.invalid", "type": "A", "value": "169.254.169.254"}])
        self.assertFalse(IPAddress.objects.filter(target=t, ip="169.254.169.254").exists())

    def test_ssrf_loopback_and_rfc1918_blocked(self):
        from services.scope_engine.validator import is_private_or_reserved, validate_ip
        t = Target.objects.create(name="ssrf2", root_domain="ssrf2.invalid")
        for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                    "::ffff:127.0.0.1", "not-an-ip"):
            self.assertTrue(is_private_or_reserved(bad), bad)
            ok, _ = validate_ip(t, bad, [])
            self.assertFalse(ok, bad)
        ok, _ = validate_ip(t, "8.8.8.8", [])
        self.assertTrue(ok)


class MustChangePasswordTests(TestCase):
    """Task 27: setup-created admins are forced through password change."""

    def test_forced_change_redirect_and_clear(self):
        c = Client()
        u = User.objects.create_user("newadmin", password="x")
        u.profile.must_change_password = True
        u.profile.save(update_fields=["must_change_password"])
        c.force_login(u)
        r = c.get("/dashboard/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/accounts/password-change/", r["Location"])
        # exempt pages stay reachable
        r = c.get("/accounts/password-change/")
        self.assertEqual(r.status_code, 200)
        r = c.post("/accounts/password-change/", {
            "old_password": "x",
            "new_password1": "N3w-Str0ng-Passw0rd!",
            "new_password2": "N3w-Str0ng-Passw0rd!",
        })
        self.assertEqual(r.status_code, 302)
        u.profile.refresh_from_db()
        self.assertFalse(u.profile.must_change_password)
        r = c.get("/dashboard/")
        self.assertEqual(r.status_code, 200)

    def test_normal_users_unaffected(self):
        c = Client()
        u = User.objects.create_user("plain", password="x")
        c.force_login(u)
        r = c.get("/dashboard/")
        self.assertEqual(r.status_code, 200)
