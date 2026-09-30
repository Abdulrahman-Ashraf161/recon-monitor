"""P0-007: every API endpoint enforces target membership server-side.

Before this task the DRF layer used ``IsAuthenticated`` only with
``Model.objects.all()`` querysets, so any logged-in user could dump the whole
database. These tests pin the corrected contract:

* list endpoints return ONLY the caller's authorized targets' rows;
* omitting ``?target=`` narrows to the caller's targets (it must never widen);
* ``?target=<unauthorized id>`` is 403 and ``?target=<missing id>`` is 404;
* retrieve-by-id cannot be used to bypass the membership filter;
* ``/api/targets/`` discloses only targets the caller belongs to;
* a global administrator retains full visibility;
* the search endpoint and the health probe leak nothing.
"""

import json

from django.test import TestCase
from django.urls import reverse

from tests.fixtures import (
    grant,
    make_admin,
    make_event,
    make_target,
    make_user,
    seed_assets_for,
)


class _WorldMixin:
    """Shared two-tenant world. A plain mixin, NOT a TestCase: pytest collects
    every ``unittest.TestCase`` subclass regardless of its name, so a TestCase
    base would itself be collected and re-run for every subclass."""

    def setUp(self):
        self.user_a = make_user(username="api-user-a")
        self.outsider = make_user(username="api-outsider")
        self.target_a = make_target(root_domain="api-alpha.example.com")
        self.target_b = make_target(root_domain="api-beta.example.com")
        grant(self.user_a, self.target_a, "OWNER")

        self.assets_a = seed_assets_for(self.target_a, "ALPHA")
        self.assets_b = seed_assets_for(self.target_b, "BETA")
        # An event on each target so the event endpoints have data.
        make_event(self.target_a, asset_value="a.api-alpha.example.com")
        make_event(self.target_b, asset_value="a.api-beta.example.com")
        self.client.force_login(self.user_a)

    def json(self, url):
        resp = self.client.get(url, HTTP_ACCEPT="application/json")
        return resp, json.loads(resp.content.decode())


class APIListScopingTests(_WorldMixin, TestCase):
    """Without an explicit target, results are limited to authorized targets."""

    def test_subdomains_exclude_other_tenants(self):
        resp, data = self.json("/api/subdomains/")
        self.assertEqual(resp.status_code, 200)
        values = {r["hostname"] for r in data["results"]}
        self.assertTrue(any("ALPHA" in v for v in values), values)
        self.assertFalse(any("BETA" in v for v in values), f"leak: {values}")

    def test_findings_exclude_other_tenants(self):
        resp, data = self.json("/api/findings/")
        self.assertEqual(resp.status_code, 200)
        titles = {r["title"] for r in data["results"]}
        self.assertIn("finding-ALPHA", titles)
        self.assertNotIn("finding-BETA", titles)

    def test_cves_exclude_other_tenants(self):
        resp, data = self.json("/api/cves/")
        self.assertEqual(resp.status_code, 200)
        ids = {r["cve_id"] for r in data["results"]}
        self.assertEqual(ids, {"CVE-2024-ALPH"})

    def test_events_exclude_other_tenants(self):
        resp, data = self.json("/api/events/")
        self.assertEqual(resp.status_code, 200)
        targets = {r["target"] for r in data["results"]}
        self.assertEqual(targets, {self.target_a.id})

    def test_targets_endpoint_lists_only_authorized_targets(self):
        resp, data = self.json("/api/targets/")
        self.assertEqual(resp.status_code, 200)
        ids = {r["id"] for r in data["results"]}
        self.assertEqual(ids, {self.target_a.id})

    def test_every_registered_endpoint_is_scoped(self):
        """No endpoint may return the other tenant's row without a target param."""
        for endpoint in [
            "subdomains",
            "ports",
            "http",
            "urls",
            "apis",
            "javascript",
            "technologies",
            "cves",
            "findings",
            "events",
            "jobs",
            "targets",
        ]:
            with self.subTest(endpoint=endpoint):
                resp, data = self.json(f"/api/{endpoint}/")
                self.assertEqual(resp.status_code, 200)
                blob = json.dumps(data)
                self.assertNotIn("BETA", blob, f"{endpoint} leaked target B data")


class APIExplicitTargetTests(_WorldMixin, TestCase):
    def test_authorized_target_param_returns_that_target(self):
        resp, data = self.json(f"/api/subdomains/?target={self.target_a.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(all("ALPHA" in r["hostname"] for r in data["results"]))

    def test_unauthorized_target_param_is_403(self):
        resp = self.client.get(
            f"/api/subdomains/?target={self.target_b.id}", HTTP_ACCEPT="application/json"
        )
        self.assertEqual(resp.status_code, 403, resp.content)

    def test_missing_target_param_is_404(self):
        resp = self.client.get("/api/subdomains/?target=987654", HTTP_ACCEPT="application/json")
        self.assertEqual(resp.status_code, 404, resp.content)

    def test_unauthorized_target_param_is_403_on_every_endpoint(self):
        for endpoint in [
            "subdomains",
            "ports",
            "http",
            "urls",
            "apis",
            "javascript",
            "technologies",
            "cves",
            "findings",
            "events",
            "jobs",
            "targets",
        ]:
            with self.subTest(endpoint=endpoint):
                resp = self.client.get(
                    f"/api/{endpoint}/?target={self.target_b.id}", HTTP_ACCEPT="application/json"
                )
                self.assertEqual(resp.status_code, 403, f"{endpoint}: {resp.content}")

    def test_non_integer_target_is_rejected(self):
        resp = self.client.get("/api/subdomains/?target=not-an-int", HTTP_ACCEPT="application/json")
        self.assertEqual(resp.status_code, 404, resp.content)


class APIObjectRetrievalTests(_WorldMixin, TestCase):
    """Detail routes must not bypass the membership filter."""

    def test_retrieve_own_object_succeeds(self):
        url = reverse("api-subdomains-detail", args=[self.assets_a["subdomain"].id])
        resp, data = self.json(url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(data["id"], self.assets_a["subdomain"].id)

    def test_retrieve_other_tenant_object_is_404(self):
        url = reverse("api-subdomains-detail", args=[self.assets_b["subdomain"].id])
        resp = self.client.get(url, HTTP_ACCEPT="application/json")
        self.assertEqual(resp.status_code, 404, resp.content)

    def test_retrieve_other_tenant_object_is_404_across_models(self):
        pairs = [
            ("api-findings-detail", self.assets_b["finding"].id),
            ("api-cves-detail", self.assets_b["cve"].id),
            ("api-tech-detail", self.assets_b["technology"].id),
        ]
        for name, pk in pairs:
            with self.subTest(name=name):
                resp = self.client.get(reverse(name, args=[pk]), HTTP_ACCEPT="application/json")
                self.assertEqual(resp.status_code, 404, resp.content)

    def test_retrieve_other_tenant_target_is_404(self):
        resp = self.client.get(
            reverse("api-targets-detail", args=[self.target_b.id]), HTTP_ACCEPT="application/json"
        )
        self.assertEqual(resp.status_code, 404, resp.content)

    def test_writes_are_rejected(self):
        """The API is read-only; POST must not create tenant data."""
        resp = self.client.post(
            "/api/subdomains/",
            data=json.dumps({"hostname": "evil.example.com"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 405, resp.content)


class APIAnonymousTests(_WorldMixin, TestCase):
    def test_anonymous_is_rejected(self):
        self.client.logout()
        for endpoint in ["subdomains", "targets", "events", "jobs"]:
            with self.subTest(endpoint=endpoint):
                resp = self.client.get(f"/api/{endpoint}/", HTTP_ACCEPT="application/json")
                self.assertIn(resp.status_code, (401, 403), resp.content)


class APIGlobalAdminTests(_WorldMixin, TestCase):
    def test_admin_sees_all_targets(self):
        self.client.force_login(make_admin(username="api-admin"))
        resp, data = self.json("/api/targets/")
        self.assertEqual(resp.status_code, 200)
        ids = {r["id"] for r in data["results"]}
        self.assertIn(self.target_a.id, ids)
        self.assertIn(self.target_b.id, ids)

    def test_admin_may_select_any_target(self):
        self.client.force_login(make_admin(username="api-admin2"))
        resp, data = self.json(f"/api/subdomains/?target={self.target_b.id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(data["results"])
        self.assertTrue(all("BETA" in r["hostname"] for r in data["results"]))


class APIJobSerializerTests(_WorldMixin, TestCase):
    def test_command_line_is_not_exposed(self):
        from apps.jobs.models import ScanJob
        from tests.fixtures import make_scan_job

        job = make_scan_job(self.target_a, job_type="http")
        ScanJob.objects.filter(pk=job.pk).update(
            command_redacted="nuclei -u secret-target -H 'Authorization: Bearer SUPERSECRET'"
        )
        resp, data = self.json("/api/jobs/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("SUPERSECRET", json.dumps(data))
        self.assertNotIn("command_redacted", data["results"][0])

    def test_legacy_run_id_is_not_exposed(self):
        """`run_id_legacy` is a migration artifact, not part of the API surface."""
        from tests.fixtures import make_scan_job

        make_scan_job(self.target_a, job_type="http")
        resp, data = self.json("/api/jobs/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("run_id_legacy", data["results"][0])


class CoreViewIsolationTests(_WorldMixin, TestCase):
    """The non-DRF JSON endpoints obey the same rules."""

    def test_global_search_is_scoped_to_authorized_targets(self):
        resp = self.client.get("/search/?q=example.com", HTTP_ACCEPT="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content.decode())
        blob = json.dumps(data)
        self.assertNotIn("BETA", blob, f"search leaked: {blob}")

    def test_global_search_finds_own_assets(self):
        resp = self.client.get("/search/?q=ALPHA", HTTP_ACCEPT="application/json")
        data = json.loads(resp.content.decode())
        self.assertTrue(data["results"], data)

    def test_health_hides_tool_detail_from_anonymous(self):
        self.client.logout()
        resp = self.client.get("/health/", HTTP_ACCEPT="application/json")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content.decode())
        self.assertNotIn("detail", data["tools"], "tool inventory leaked to anonymous")

    def test_health_hides_tool_detail_from_non_admin(self):
        resp = self.client.get("/health/", HTTP_ACCEPT="application/json")
        data = json.loads(resp.content.decode())
        self.assertNotIn("detail", data["tools"], "tool inventory leaked to viewer")

    def test_health_shows_detail_to_admin(self):
        self.client.force_login(make_admin(username="health-admin"))
        resp = self.client.get("/health/", HTTP_ACCEPT="application/json")
        data = json.loads(resp.content.decode())
        self.assertIn("detail", data["tools"])
