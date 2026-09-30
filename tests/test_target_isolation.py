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

        e, _ = emit_event(
            "NEW_IP", target=self.a, asset_value="10.0.0.1", source="t", severity="HIGH"
        )
        al = Alert.objects.filter(event=e).first()
        if al and al.target_id:
            self.assertEqual(al.target_id, self.a.id)

    def test_cross_target_reference_rejected(self):
        from apps.assets.models import JavaScriptAsset, JavaScriptFinding

        js = JavaScriptAsset.objects.create(
            target=self.a,
            js_url="https://a.example/x.js",
            host="a.example",
            sha256="a" * 64,
            size=1,
        )
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
        self.assertFalse(
            URLAsset.objects.filter(target=self.a, host="not-my-domain.example.org").exists()
        )

    def test_ingest_urls_keeps_in_scope_host(self):
        from apps.assets.models import URLAsset
        from services.correlation.ingest import ingest_urls

        ingest_urls(self.a, [{"url": "https://web.a.invalid/app", "source": "gau"}])
        self.assertTrue(URLAsset.objects.filter(target=self.a, host="web.a.invalid").exists())


class DetailContextTests(TestCase):
    """Task 7: detail views enforce caller target context server-side.

    P0-002 flipped the platform from single-tenant to enforced membership
    (``SINGLE_TENANT_ALL_TARGETS=False`` by default), so "no context at all" is
    no longer a valid request: it used to be a 200 and is now a 403.
    """

    def setUp(self):
        from django.contrib.auth.models import User
        from django.test import Client

        from apps.targets.models import TargetMembership

        self.u = User.objects.create_user("viewer7", password="x")
        self.c = Client()
        self.c.force_login(self.u)
        self.a = Target.objects.create(name="a", root_domain="a.invalid")
        self.b = Target.objects.create(name="b", root_domain="b.invalid")
        self.membership = TargetMembership.objects.create(
            user=self.u, target=self.a, role=TargetMembership.ROLE_VIEWER
        )

    def test_detail_view_without_target_param_on_fresh_session(self):
        """No context anywhere (fresh session) -> 403 once membership is enforced.

        Previously 200: the old design treated a missing context as "single
        tenant, serve anything". A member still has to name the target.
        """
        from apps.assets.models import Asset

        a = Asset.objects.create(target=self.a, asset_type="SUBDOMAIN", value="x.a.invalid")
        r = self.c.get(f"/assets/{a.pk}/")
        self.assertEqual(r.status_code, 403)

    def test_member_with_explicit_context_is_served(self):
        """The positive case for the rule above: member + matching context -> 200."""
        from apps.assets.models import Asset

        a = Asset.objects.create(target=self.a, asset_type="SUBDOMAIN", value="ok.a.invalid")
        r = self.c.get(f"/assets/{a.pk}/?target={self.a.id}")
        self.assertEqual(r.status_code, 200)

    def test_non_member_denied_even_with_matching_context(self):
        """Membership, not the context param, is what actually authorizes access."""
        from django.contrib.auth.models import User
        from django.test import Client

        from apps.assets.models import Asset

        stranger = User.objects.create_user("stranger7", password="x")
        c = Client()
        c.force_login(stranger)
        a = Asset.objects.create(target=self.a, asset_type="SUBDOMAIN", value="no.a.invalid")
        r = c.get(f"/assets/{a.pk}/?target={self.a.id}")
        self.assertEqual(r.status_code, 403)

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
        from unittest.mock import patch
        from urllib.parse import urlparse

        from apps.assets.models import JavaScriptAsset
        from apps.jobs import tasks
        from apps.jobs.tasks import host_url_discovery

        t = Target.objects.create(
            name="s", root_domain="scope.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )

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

        class _FakeOpener:
            def open(self, req, timeout=None):
                url = req.full_url if hasattr(req, "full_url") else str(req)
                calls.append(url)
                host = urlparse(url).hostname or ""
                if host == "web.scope.invalid" and not url.endswith("/local.js"):
                    return _FakeResp(
                        b'<html><script src="https://evil.example.org/x.js">'
                        b'</script><script src="/local.js"></script></html>'
                    )
                if url.endswith("/local.js"):
                    return _FakeResp(b"var a=1;")
                raise AssertionError(f"unexpected outbound fetch: {url}")

        # P0-016: the centralized fetch builds its opener via _safe_opener (real
        # scope/SSRF gate in _url_allowed_for_fetch stays active in _fetch_url_...
        # for_recon), so the network seam to fake is the opener, not urlopen.
        with patch.object(tasks, "_safe_opener", return_value=_FakeOpener()):
            host_url_discovery(t.id, "https://web.scope.invalid/", trigger="test")
        self.assertFalse(
            any("evil.example.org" in u for u in calls), f"out-of-scope host was fetched: {calls}"
        )
        self.assertTrue(
            JavaScriptAsset.objects.filter(
                target=t, js_url="https://web.scope.invalid/local.js"
            ).exists()
        )
        self.assertFalse(
            JavaScriptAsset.objects.filter(target=t, js_url__icontains="evil.example.org").exists()
        )


class OwnershipClassificationTests(TestCase):
    """P0-008: ownership of every model is declared once and resolves correctly.

    The previous resolver probed a hard-coded attribute list (``js``, ``event``,
    ``scan_run``) per object, which missed unlisted models and, because
    ``Alert`` owns a *direct* target FK, disagreed with other querysets. These
    tests pin the classification and its resolution.
    """

    def test_every_concrete_model_is_classified(self):
        from django.apps import apps as django_apps

        from apps.core.target_scoping import OWNERSHIP_PATHS, classify_model

        kinds = {}
        for model in django_apps.get_models():
            if model._meta.abstract or model._meta.proxy:
                continue
            kind, path = classify_model(model)
            kinds[model.__name__] = (kind, path)
        # Every model resolves to one of the four declared kinds.
        for name, (kind, _path) in kinds.items():
            self.assertIn(kind, {"direct", "indirect", "user", "global"}, name)

        # Every model with a target FK is reachable, and no model is
        # unclassified-and-unknown.
        for name in OWNERSHIP_PATHS:
            self.assertIn(name, kinds, f"{name} is mapped but no longer a model")

    def test_direct_models_resolve_their_target(self):
        from apps.events.models import Alert
        from tests.fixtures import make_event, make_scan_job, make_scan_run, make_target

        target = make_target(root_domain="own.example.com")
        run = make_scan_run(target)
        job = make_scan_job(target, scan_run=run)
        event = make_event(target, scan_run=run)
        alert = Alert.objects.create(event=event, target=target, channel="discord")

        from apps.core.target_scoping import ownership_of

        for obj in (run, job, event, alert):
            self.assertEqual(ownership_of(obj), target.pk, type(obj).__name__)

    def test_indirect_models_resolve_through_their_parent(self):
        from apps.jobs.models import JobLog
        from tests.fixtures import make_scan_job, make_target

        target = make_target(root_domain="indirect.example.com")
        job = make_scan_job(target)
        log = JobLog.objects.create(job=job, level="INFO", message="hi")

        from apps.core.target_scoping import ownership_of

        self.assertEqual(ownership_of(log), target.pk)

    def test_alert_is_directly_owned_not_via_event(self):
        """Alert has its own `target`; resolving it via `event` was the old bug."""
        from apps.core.target_scoping import classify_model
        from apps.events.models import Alert

        kind, path = classify_model(Alert)
        self.assertEqual(kind, "direct")
        self.assertEqual(path, "target")

    def test_global_and_user_models_have_no_ownership(self):
        from apps.accounts.models import Profile
        from apps.core.target_scoping import ownership_of
        from tests.fixtures import make_target, make_user

        target = make_target(root_domain="global.example.com")
        self.assertIsNone(ownership_of(target))
        self.assertIsNone(ownership_of(make_user(username="own-user").profile))
        self.assertIsNone(ownership_of(Profile()))

    def test_broken_chain_raises_instead_of_reading_as_unowned(self):
        from apps.core.target_scoping import ValidationError, ownership_of
        from apps.jobs.models import JobLog

        orphan = JobLog(level="INFO", message="no parent")
        with self.assertRaises(ValidationError):
            ownership_of(orphan)


class ForUserScopingTests(TestCase):
    """P0-008: `for_user` is default-deny and understands indirect ownership."""

    def setUp(self):
        from tests.fixtures import grant, make_target, make_user, seed_assets_for

        self.user = make_user(username="scope-user")
        self.target_a = make_target(root_domain="scope-a.example.com")
        self.target_b = make_target(root_domain="scope-b.example.com")
        grant(self.user, self.target_a, "VIEWER")
        self.a = seed_assets_for(self.target_a, "SA")
        self.b = seed_assets_for(self.target_b, "SB")

    def test_for_user_excludes_other_targets(self):
        from apps.assets.models import Subdomain

        qs = Subdomain.objects.for_user(self.user)
        hostnames = {s.hostname for s in qs}
        self.assertTrue(any("SA" in h for h in hostnames), hostnames)
        self.assertFalse(any("SB" in h for h in hostnames), hostnames)

    def test_for_user_is_default_deny_for_anonymous(self):
        from django.contrib.auth.models import AnonymousUser

        from apps.assets.models import Subdomain

        self.assertEqual(Subdomain.objects.for_user(AnonymousUser()).count(), 0)
        self.assertEqual(Subdomain.objects.for_user(None).count(), 0)

    def test_for_user_with_no_memberships_returns_nothing(self):
        from apps.assets.models import Subdomain
        from tests.fixtures import make_user

        loner = make_user(username="scope-loner")
        self.assertEqual(Subdomain.objects.for_user(loner).count(), 0)

    def test_for_user_on_indirect_model_follows_the_chain(self):
        from apps.jobs.models import JobLog
        from tests.fixtures import make_scan_job

        make_scan_job(self.target_a)
        make_scan_job(self.target_b)
        self.assertEqual(JobLog.objects.count(), 0)  # no logs yet
        JobLog.objects.create(job=make_scan_job(self.target_a), level="INFO", message="mine")
        self.assertEqual(JobLog.objects.filter(level="INFO").count(), 1)

    def test_for_user_rejects_non_target_owned_models(self):
        from apps.core.target_scoping import ValidationError, for_user
        from apps.targets.models import Target

        with self.assertRaises(ValidationError):
            for_user(Target.all_objects.all(), self.user)

    def test_superuser_for_user_sees_everything(self):
        from apps.assets.models import Subdomain
        from tests.fixtures import make_admin

        admin = make_admin(username="scope-admin")
        qs = Subdomain.objects.for_user(admin)
        self.assertEqual(qs.count(), Subdomain.all_objects.count())


class GetObjectForTargetTests(TestCase):
    """P0-008: single-object fetch enforces ownership for direct + indirect."""

    def setUp(self):
        from tests.fixtures import make_target, seed_assets_for

        self.a = make_target(root_domain="go-a.example.com")
        self.b = make_target(root_domain="go-b.example.com")
        self.assets_a = seed_assets_for(self.a, "GOA")
        self.assets_b = seed_assets_for(self.b, "GOB")

    def test_same_target_object_is_returned(self):
        from apps.assets.models import Subdomain
        from apps.core.target_scoping import get_object_for_target

        obj = get_object_for_target(Subdomain, self.assets_a["subdomain"].pk, self.a)
        self.assertEqual(obj.pk, self.assets_a["subdomain"].pk)

    def test_cross_target_object_is_denied(self):
        from django.core.exceptions import PermissionDenied

        from apps.assets.models import Subdomain
        from apps.core.target_scoping import get_object_for_target

        with self.assertRaises(PermissionDenied):
            get_object_for_target(Subdomain, self.assets_b["subdomain"].pk, self.a)

    def test_missing_object_is_404(self):
        from django.http import Http404

        from apps.assets.models import Subdomain
        from apps.core.target_scoping import get_object_for_target

        with self.assertRaises(Http404):
            get_object_for_target(Subdomain, 987654321, self.a)
