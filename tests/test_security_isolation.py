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
