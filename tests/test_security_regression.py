"""P2-009 — Security regression suite.

A single, navigable suite covering the security properties the taskbook
requires, so a reviewer can confirm the whole security posture from one file.
Each class names its area and asserts the property end to end (real models,
views, tasks, channels) rather than a mock.

Areas: cross-target views/APIs/websockets/exports; object-ID guessing; SSRF and
redirects; DNS rebinding; TLS; pause/cancellation; authorization expiry;
cross-target model relationships; duplicate ScanRuns; duplicate events.
"""

from datetime import timedelta
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.assets.models import Subdomain
from apps.core.consistency import ExecutionConsistencyError
from apps.core.execution_context import ScanContext, record_observation, scan_context
from apps.events.models import Event
from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun
from apps.targets.models import Target

from .fixtures import make_target, make_world


class _FakeRequest:
    def __init__(self, url):
        self.full_url = url
        self.headers = {}


class SEC01_CrossTargetViews(TestCase):
    def setUp(self):
        self.w = make_world()
        self.client.force_login(self.w["user_a"])

    def test_asset_views_do_not_leak_across_targets(self):
        Subdomain.objects.create(target=self.w["target_b"], hostname="secret.beta.example.com")
        Subdomain.objects.create(target=self.w["target_a"], hostname="mine.alpha.example.com")
        r = self.client.get("/subdomains/")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("secret.beta.example.com", r.content.decode())


class SEC02_CrossTargetApis(TestCase):
    def setUp(self):
        self.w = make_world()
        self.client.force_login(self.w["user_a"])

    def test_events_and_jobs_api_are_membership_scoped(self):
        Event.objects.create(
            target=self.w["target_b"],
            event_type="NEW_SUBDOMAIN",
            asset_value="b.beta.example.com",
            fingerprint="sec2-b",
        )
        Event.objects.create(
            target=self.w["target_a"],
            event_type="NEW_SUBDOMAIN",
            asset_value="a.alpha.example.com",
            fingerprint="sec2-a",
        )
        body = self.client.get("/api/events/").content.decode()
        self.assertIn("a.alpha.example.com", body)
        self.assertNotIn("b.beta.example.com", body)


class SEC03_CrossTargetWebsockets(TestCase):
    def test_membership_is_checked_before_joining_a_target_group(self):
        import inspect

        from apps.events.consumers import LiveConsumer

        connect_src = inspect.getsource(LiveConsumer.connect)
        authorize_src = inspect.getsource(LiveConsumer._authorize)
        # the consumer authorizes through the membership guard ...
        self.assertIn("require_websocket_target_access", authorize_src)
        # ... before it ever joins the channel group
        self.assertIn("_authorize", connect_src)
        self.assertIn("group_add", connect_src)
        self.assertLess(connect_src.index("_authorize"), connect_src.index("group_add"))
        # and re-validates on every delivery (revocation stops the stream)
        self.assertIn("_authorize", inspect.getsource(LiveConsumer.event_message))


class SEC04_CrossTargetExports(TestCase):
    def test_export_download_requires_target_membership(self):
        from apps.monitoring.models import ExportJob

        w = make_world()
        job = ExportJob.objects.create(
            target=w["target_b"], export_type="subdomains", status=ExportJob.STATUS_QUEUED
        )
        self.client.force_login(w["user_a"])
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertIn(r.status_code, (403, 404))  # not another target's export


class SEC05_ObjectIdGuessing(TestCase):
    def test_guessed_ids_never_cross_targets(self):
        w = make_world()
        job_b = ScanJob.objects.create(target=w["target_b"], job_type="ports", status="COMPLETED")
        self.client.force_login(w["user_a"])
        for pk in range(1, job_b.pk + 2):
            r = self.client.get(reverse("job-detail", args=[pk]))
            self.assertNotEqual(r.status_code, 200, f"id {pk} guessed across targets")


class SEC06_SsrfAndRedirects(TestCase):
    def test_out_of_scope_and_private_targets_are_refused(self):
        t = make_target(root_domain="sec6.example.com")
        for url in (
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://[::1]/",
            "file:///etc/passwd",
            "http://other.example.org/",
        ):
            ok, _reason, _h = tasks._url_allowed_for_fetch(t, url)
            self.assertFalse(ok, f"{url} was allowed")

    def test_in_scope_url_is_allowed(self):
        t = make_target(root_domain="sec6c.example.com")
        ok, reason, _h = tasks._url_allowed_for_fetch(t, "https://app.sec6c.example.com/x")
        self.assertTrue(ok, reason)

    def test_redirect_hop_is_revalidated(self):
        t = make_target(root_domain="sec6b.example.com")
        handler = tasks._ScopedRedirectHandler(t)
        req = _FakeRequest("https://app.sec6b.example.com/")

        class _Resp:
            headers = {}

            def close(self):
                pass

        for hop in ("http://169.254.169.254/latest/meta-data/", "http://evil.example.org/"):
            with self.assertRaises(tasks._ReconFetchSkipped):
                handler.redirect_request(req, _Resp(), 302, "Found", {}, hop)


class SEC07_DnsRebinding(TestCase):
    def test_allowed_hostname_resolving_to_private_ip_is_refused(self):
        t = make_target(root_domain="sec7.example.com")
        with patch(
            "services.scope_engine.validator.host_resolves_to_blocked",
            return_value=(True, "rebind"),
        ):
            ok, reason, _h = tasks._url_allowed_for_fetch(t, "https://in-scope.sec7.example.com/")
        self.assertFalse(ok)
        self.assertIn("rebind", reason)


class SEC08_Tls(TestCase):
    def test_certificate_is_verified_by_default(self):
        import ssl

        ctx = tasks._ssl_context_for(make_target(root_domain="sec8.example.com"), None, "t")
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


class SEC09_PauseCancellation(TestCase):
    def test_paused_target_cannot_start_work(self):
        t = make_target(root_domain="sec9.example.com", status=Target.STATUS_PAUSED)
        out = tasks.probe_http(t.id)
        self.assertEqual(out["status"], "SKIPPED")

    def test_pause_halts_a_live_run(self):
        t = make_target(root_domain="sec9b.example.com")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        ScanJob.objects.create(target=t, job_type="ports", status=ScanJob.STATUS_RUNNING)
        from apps.targets.target_lifecycle import transition_to

        transition_to(
            t, new_status=Target.STATUS_PAUSED, reason="test", halt_reason="TARGET_PAUSED"
        )
        run.refresh_from_db()
        self.assertNotEqual(run.status, "RUNNING")


class SEC10_AuthorizationExpiry(TestCase):
    def test_expired_target_cannot_start_work(self):
        t = make_target(
            root_domain="sec10.example.com",
            authorization_expires_at=timezone.now() - timedelta(minutes=1),
        )
        out = tasks.discover_subdomains(t.id)
        self.assertEqual(out["status"], "SKIPPED")

    def test_expiry_emits_and_halts(self):
        t = make_target(root_domain="sec10b.example.com")
        from apps.targets.target_lifecycle import transition_to

        transition_to(t, new_auth=Target.AUTH_EXPIRED, reason="test")
        t.refresh_from_db()
        self.assertFalse(t.is_scannable)
        self.assertTrue(Event.objects.filter(target=t, event_type="AUTHORIZATION_EXPIRED").exists())


class SEC11_CrossTargetRelationships(TestCase):
    def test_run_job_and_observation_cannot_cross_targets(self):
        a = make_target(root_domain="sec11a.example.com")
        b = make_target(root_domain="sec11b.example.com")
        run_b = ScanRun.objects.create(target=b, scan_type="DISCOVERY", status="RUNNING")
        with self.assertRaises(ExecutionConsistencyError):
            ScanJob(target=a, job_type="ports", scan_run=run_b).save()
        with scan_context(ScanContext(target_id=a.pk, scan_run=run_b)):
            # the ambient context is re-checked against the row's own target
            record_observation("PORT", "1.2.3.4:80")
        # the observation is refused because the run belongs to another target
        # (consistency guard raises on save)
        from apps.jobs.models import AssetObservation

        self.assertEqual(AssetObservation.all_objects.filter(target=a, scan_run=run_b).count(), 0)


class SEC12_DuplicateScanRuns(TestCase):
    def test_only_one_live_run_per_type(self):
        t = make_target(root_domain="sec12.example.com")
        ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")


class SEC13_DuplicateEvents(TestCase):
    def test_duplicate_fingerprint_is_rejected(self):
        t = make_target(root_domain="sec13.example.com")
        Event.objects.create(
            target=t, event_type="NEW_SUBDOMAIN", asset_value="x", fingerprint="s13"
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            Event.objects.create(
                target=t, event_type="NEW_SUBDOMAIN", asset_value="y", fingerprint="s13"
            )

    def test_emit_event_dedups_concurrently(self):
        t = make_target(root_domain="sec13b.example.com")
        from services.event_engine.engine import emit_event

        _e, created = emit_event("NEW_SUBDOMAIN", target=t, asset_value="z.example.com")
        self.assertTrue(created)
        _e2, created2 = emit_event("NEW_SUBDOMAIN", target=t, asset_value="z.example.com")
        self.assertFalse(created2)
        self.assertEqual(Event.objects.filter(target=t, event_type="NEW_SUBDOMAIN").count(), 1)


class UnscopedDefaultManagerTests(TestCase):
    """P0-003: a user-facing list may never use an unfiltered default manager.

    `TargetScopedManager.get_queryset()` returns the queryset with **no** filter
    applied -- membership scoping only happens when `.for_user()` is called
    explicitly. So `Model.objects.all()` in a view is an unfiltered cross-tenant
    read, and it is easy to write by accident because the manager *looks*
    scoped.

    This was a live bug: `/targets/` and `/scope/` both leaked every target's
    domain to any logged-in viewer who held no membership. The object *detail*
    pages correctly returned 403, which is why the API isolation tests (which do
    cover `/api/targets/`) passed and the leak survived.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model

        from apps.targets.models import Target

        U = get_user_model()
        self.owner = U.objects.create_user(username="p0003_owner", password="Owner-Pw1!x")
        self.outsider = U.objects.create_user(username="p0003_out", password="Out-Pw1!x")
        self.victim = Target.objects.create(
            root_domain="p0003-victim.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )
        self.victim.memberships.create(user=self.owner, role="OWNER")

    def test_default_manager_is_not_automatically_scoped(self):
        """Documents the trap: the default manager applies no filter on its own."""
        from apps.targets.models import Target

        self.assertIn(
            self.victim,
            Target.objects.all(),
            "if this ever becomes false the default manager started filtering, "
            "and this test's premise (and the P0-003 fix) must be revisited",
        )

    def test_target_list_hides_other_tenants_targets(self):

        self.client.force_login(self.outsider)
        body = self.client.get("/targets/").content.decode()
        self.assertNotIn(
            "p0003-victim.invalid",
            body,
            "P0-003 regression: /targets/ leaked another tenant's target domain",
        )

    def test_target_list_still_shows_the_users_own_targets(self):
        self.client.force_login(self.owner)
        body = self.client.get("/targets/").content.decode()
        self.assertIn("p0003-victim.invalid", body)

    def test_scope_index_hides_other_tenants_targets_and_rules(self):
        from apps.scope.models import ScopeRule

        ScopeRule.objects.create(
            target=self.victim, rule_type="INCLUDE", value="*.p0003-victim.invalid"
        )
        self.client.force_login(self.outsider)
        body = self.client.get("/scope/").content.decode()
        self.assertNotIn("p0003-victim.invalid", body, "/scope/ leaked a target domain")
        self.assertNotIn("*.p0003-victim.invalid", body, "/scope/ leaked a scope rule")

    def test_scope_index_rejects_an_unauthorized_target_filter(self):
        self.client.force_login(self.outsider)
        r = self.client.get(f"/scope/?target={self.victim.id}")
        self.assertIn(r.status_code, (403, 404))
        self.assertNotIn("p0003-victim.invalid", r.content.decode())

    def test_scope_index_shows_own_scope_rules(self):
        from apps.scope.models import ScopeRule

        ScopeRule.objects.create(
            target=self.victim, rule_type="INCLUDE", value="*.p0003-victim.invalid"
        )
        self.client.force_login(self.owner)
        body = self.client.get("/scope/").content.decode()
        self.assertIn("*.p0003-victim.invalid", body)

    def test_object_detail_pages_still_deny_the_outsider(self):
        self.client.force_login(self.outsider)
        for url in (
            f"/targets/{self.victim.id}/",
            f"/targets/{self.victim.id}/edit/",
            f"/targets/{self.victim.id}/changes/",
            f"/targets/{self.victim.id}/exports/",
        ):
            with self.subTest(url=url):
                self.assertIn(self.client.get(url).status_code, (403, 404))


class AllPagesLeakSweepTests(TestCase):
    """Sweep every user-facing page for cross-tenant content.

    The P0-003 regression was missed because the isolation tests asserted on
    specific endpoints and on *detail* pages (which were correctly 403) while
    two *list* pages leaked. A whitelist of tested URLs cannot catch a page
    nobody thought to test, so this enumerates the live URL conf instead and
    fails if any victim-owned value appears in a non-member's response.
    """

    def test_no_user_facing_page_leaks_another_tenants_data(self):
        from django.contrib.auth import get_user_model
        from django.test import Client
        from django.urls import get_resolver

        from apps.assets.models import HTTPService, IPAddress, Port, Subdomain, Technology, URLAsset
        from apps.events.models import Event
        from apps.jobs.models import ScanJob
        from apps.scope.models import ScopeRule
        from apps.targets.models import Target

        U = get_user_model()
        owner = U.objects.create_user(username="sweep_owner", password="Owner-Pw1!x")
        outsider = U.objects.create_user(username="sweep_outsider", password="Out-Pw1!x")

        V, SUB, IP = "sweep-victim.invalid", "api.sweep-victim.invalid", "203.0.113.99"
        t = Target.objects.create(root_domain=V, authorization_status=Target.AUTH_AUTHORIZED)
        t.memberships.create(user=owner, role="OWNER")
        Subdomain.objects.create(target=t, hostname=SUB)
        IPAddress.objects.create(target=t, ip=IP, version=4)
        Port.objects.create(target=t, ip=IP, port=8443, protocol="tcp", state="open")
        HTTPService.objects.create(
            target=t, url=f"https://{V}", host=V, port=443, status_code=200, state="alive"
        )
        URLAsset.objects.create(
            target=t,
            raw_url=f"https://{V}/sweepsecret",
            canonical_url=f"https://{V}/sweepsecret",
            host=V,
            path="/sweepsecret",
            status_code=200,
        )
        Technology.objects.create(target=t, asset_value=f"https://{V}", product="SweepTech")
        ScopeRule.objects.create(target=t, rule_type="INCLUDE", value=f"*.{V}")
        ScanJob.objects.create(target=t, job_type="probe_http", status="COMPLETED")
        Event.objects.create(
            target=t, event_type="NEW_SUBDOMAIN", asset_type="subdomain", asset_value=SUB
        )

        # Enumerate the URL conf so a newly added page is covered automatically.
        found = []

        def walk(resolver, prefix=""):
            for p in resolver.url_patterns:
                pat = prefix + str(p.pattern)
                if hasattr(p, "url_patterns"):
                    walk(p, pat)
                else:
                    found.append(pat)

        walk(get_resolver())

        needles = {
            "target domain": V,
            "victim subdomain": SUB,
            "victim ip": IP,
            "victim port": "8443",
            "victim path": "sweepsecret",
            "victim tech": "SweepTech",
            "victim scope rule": f"*.{V}",
        }
        c = Client()
        c.force_login(outsider)
        # Substitute the victim-owned ids into any <int:...> segment so the
        # detail pages are exercised too.
        subs = {"pk": str(t.id), "target_id": str(t.id)}
        leaks = []
        for pat in found:
            if pat.startswith("admin/") or pat.startswith("api/^") or "format" in pat:
                continue
            url = pat
            for name, val in subs.items():
                url = url.replace(f"<int:{name}>", val)
            url = url.replace("^", "").replace("$", "").replace("?", "")
            if "<" in url or "(" in url:
                continue
            # The top-level patterns are registered without a leading slash
            # ("targets/"), so normalise before probing -- an earlier version
            # required a leading "/" and silently skipped every list page, which
            # is exactly the shape of the bug it was written to catch.
            if not url.startswith("/"):
                url = "/" + url
            try:
                r = c.get(url)
            except Exception:
                continue
            if r.status_code >= 500:
                leaks.append((url, r.status_code, ["5xx server error"]))
                continue
            if r.status_code in (301, 302, 404):
                continue
            body = r.content.decode("utf-8", "ignore")
            hit = sorted(k for k, v in needles.items() if v in body)
            if hit:
                leaks.append((url, r.status_code, hit))
        self.assertEqual(
            leaks, [], f"cross-tenant leak(s): {leaks}; the outsider was denied nothing here"
        )


class AlertsViewScopingTests(TestCase):
    """P0-003/P0-005: /alerts/ must be membership-scoped.

    Found by an independent 32-page sweep with two users and two targets. The
    view used `Alert.objects.select_related(...)` with no scoping: the default
    manager applies no filter of its own, so this was an unfiltered cross-tenant
    read. An Alert carries its event, and through the event the target domain
    and the asset value, so the page disclosed another tenant's target names and
    asset inventory.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model

        from apps.events.models import Alert, Event
        from apps.targets.models import Target

        U = get_user_model()
        self.owner = U.objects.create_user(username="alert_owner", password="Ow-Pw1!x")
        self.outsider = U.objects.create_user(username="alert_out", password="Ao-Pw1!x")
        self.victim = Target.objects.create(
            root_domain="alert-victim.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )
        self.victim.memberships.create(user=self.owner, role="OWNER")
        ev = Event.objects.create(
            target=self.victim,
            event_type="NEW_SUBDOMAIN",
            asset_type="subdomain",
            asset_value="api.alert-victim.invalid",
            fingerprint="alert-fp-1",
        )
        Alert.objects.create(target=self.victim, event=ev)

    def test_alerts_page_hides_other_tenants_alerts(self):
        self.client.force_login(self.outsider)
        body = self.client.get("/alerts/").content.decode()
        self.assertNotIn("alert-victim.invalid", body)
        self.assertNotIn("api.alert-victim.invalid", body)

    def test_alerts_page_shows_the_users_own_alerts(self):
        self.client.force_login(self.owner)
        self.assertIn("alert-victim.invalid", self.client.get("/alerts/").content.decode())


class TargetCreationGrantsOwnershipTests(TestCase):
    """P0-002: creating a target must grant the creator an OWNER membership.

    Without it the create flow produced an orphaned target: it had zero
    memberships, so nobody could read it, and the creator was redirected to a
    page that returned 403.
    """

    def setUp(self):
        from django.contrib.auth import get_user_model

        from apps.accounts.models import Profile

        U = get_user_model()
        self.op = U.objects.create_user(username="creator_op", password="Co-Pw1!x")
        Profile.objects.update_or_create(user=self.op, defaults={"role": "OPERATOR"})

    def _payload(self, domain):
        return {
            "name": "New",
            "root_domain": domain,
            "status": "ACTIVE",
            "authorization_status": "AUTHORIZED",
            "auth_warning_days": 14,
            "scan_profile": "standard",
            "confirm_authorized": "on",
        }

    def test_creator_gets_owner_membership_and_can_open_the_target(self):
        from apps.targets.models import Target

        self.client.force_login(self.op)
        r = self.post_creation("createme.invalid")
        self.assertEqual(r.status_code, 302, r.content[:200])
        t = Target.all_objects.get(root_domain="createme.invalid")
        self.assertEqual(t.memberships.count(), 1, "creator must hold exactly one membership")
        self.assertEqual(t.memberships.first().role, "OWNER")
        self.assertEqual(self.client.get(f"/targets/{t.pk}/").status_code, 200)
        self.assertIn("createme.invalid", self.client.get("/targets/").content.decode())

    def post_creation(self, domain):
        from unittest.mock import patch

        with patch("apps.jobs.tasks.baseline_target.delay"):
            return self.client.post("/targets/add/", self._payload(domain))
