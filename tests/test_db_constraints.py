"""P2-008: database constraints, not just application validation.

These tests assert at the *database* level: a duplicate insert must raise
IntegrityError even when the application code does nothing clever, because
race-sensitive rules cannot be enforced by application checks alone.
"""

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.test import TransactionTestCase

from apps.assets.models import Asset, JavaScriptAsset, JavaScriptFinding
from apps.events.models import Event
from apps.jobs.models import JSAnalysisJob, ScanJob, ScanRun, ToolExecution
from apps.targets.models import Target, TargetMembership


class EventFingerprintConstraintTests(TransactionTestCase):
    def test_duplicate_fingerprint_is_rejected_by_the_database(self):
        t = Target.objects.create(name="fp.invalid", root_domain="fp.invalid")
        Event.objects.create(
            target=t,
            event_type="NEW_SUBDOMAIN",
            asset_value="a.fp.invalid",
            fingerprint="uniq-fp-1",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Event.objects.create(
                    target=t,
                    event_type="NEW_SUBDOMAIN",
                    asset_value="other.fp.invalid",
                    fingerprint="uniq-fp-1",
                )

    def test_distinct_fingerprints_are_allowed(self):
        t = Target.objects.create(name="fp2.invalid", root_domain="fp2.invalid")
        for i in range(3):
            Event.objects.create(
                target=t,
                event_type="NEW_SUBDOMAIN",
                asset_value=f"h{i}.fp2.invalid",
                fingerprint=f"uniq-fp2-{i}",
            )
        self.assertEqual(Event.objects.filter(target=t).count(), 3)


class MembershipConstraintTests(TransactionTestCase):
    def test_duplicate_membership_is_rejected(self):
        u = User.objects.create_user(username="m1", password="x", email="m1@x.invalid")
        t = Target.objects.create(name="mb.invalid", root_domain="mb.invalid")
        TargetMembership.objects.create(user=u, target=t, role=TargetMembership.ROLE_VIEWER)
        with self.assertRaises(IntegrityError), transaction.atomic():
            TargetMembership.objects.create(user=u, target=t, role=TargetMembership.ROLE_OWNER)

    def test_membership_for_another_target_is_allowed(self):
        u = User.objects.create_user(username="m2", password="x", email="m2@x.invalid")
        a = Target.objects.create(name="ma.invalid", root_domain="ma.invalid")
        b = Target.objects.create(name="mc.invalid", root_domain="mc.invalid")
        TargetMembership.objects.create(user=u, target=a, role=TargetMembership.ROLE_VIEWER)
        TargetMembership.objects.create(user=u, target=b, role=TargetMembership.ROLE_VIEWER)
        self.assertEqual(TargetMembership.objects.filter(user=u).count(), 2)


class LiveScanRunConstraintTests(TransactionTestCase):
    def test_second_live_run_of_the_same_type_is_rejected(self):
        t = Target.objects.create(name="lr.invalid", root_domain="lr.invalid")
        ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        with self.assertRaises(IntegrityError), transaction.atomic():
            ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")

    def test_terminal_runs_accumulate(self):
        t = Target.objects.create(name="lr2.invalid", root_domain="lr2.invalid")
        for status in ("COMPLETED", "FAILED", "PARTIAL", "CANCELLED"):
            ScanRun.objects.create(target=t, scan_type="DISCOVERY", status=status)
        self.assertEqual(ScanRun.objects.filter(target=t).count(), 4)

    def test_different_scan_types_coexist(self):
        t = Target.objects.create(name="lr3.invalid", root_domain="lr3.invalid")
        ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="RUNNING")
        ScanRun.objects.create(target=t, scan_type="MONITORING", status="RUNNING")
        self.assertEqual(ScanRun.objects.filter(target=t, status="RUNNING").count(), 2)


class AssetConstraintTests(TransactionTestCase):
    def test_duplicate_asset_is_rejected(self):
        t = Target.objects.create(name="as.invalid", root_domain="as.invalid")
        Asset.objects.create(target=t, asset_type=Asset.SUBDOMAIN, value="a.as.invalid")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Asset.objects.create(target=t, asset_type=Asset.SUBDOMAIN, value="a.as.invalid")

    def test_same_value_under_a_different_type_is_allowed(self):
        t = Target.objects.create(name="as2.invalid", root_domain="as2.invalid")
        Asset.objects.create(target=t, asset_type=Asset.SUBDOMAIN, value="x.as2.invalid")
        Asset.objects.create(target=t, asset_type=Asset.URL, value="x.as2.invalid")
        self.assertEqual(Asset.objects.filter(target=t).count(), 2)

    def test_same_value_on_another_target_is_allowed(self):
        a = Target.objects.create(name="as3.invalid", root_domain="as3.invalid")
        b = Target.objects.create(name="as4.invalid", root_domain="as4.invalid")
        Asset.objects.create(target=a, asset_type=Asset.SUBDOMAIN, value="shared.invalid")
        Asset.objects.create(target=b, asset_type=Asset.SUBDOMAIN, value="shared.invalid")
        self.assertEqual(
            Asset.objects.filter(asset_type=Asset.SUBDOMAIN, value="shared.invalid").count(), 2
        )

    def test_get_or_create_is_idempotent_under_the_constraint(self):
        t = Target.objects.create(name="as5.invalid", root_domain="as5.invalid")
        a1, c1 = Asset.objects.get_or_create(target=t, asset_type=Asset.PORT, value="1.2.3.4:80")
        a2, c2 = Asset.objects.get_or_create(target=t, asset_type=Asset.PORT, value="1.2.3.4:80")
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(a1.pk, a2.pk)


class JsFindingConstraintTests(TransactionTestCase):
    def _js(self, t):
        return JavaScriptAsset.objects.create(
            target=t, js_url="https://x.invalid/a.js", host="x.invalid", sha256="a" * 64
        )

    def test_duplicate_finding_is_rejected(self):
        t = Target.objects.create(name="jf.invalid", root_domain="jf.invalid")
        js = self._js(t)
        JavaScriptFinding.objects.create(
            js=js, target=t, finding_type="aws_key", location="body@abc"
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            JavaScriptFinding.objects.create(
                js=js, target=t, finding_type="aws_key", location="body@abc"
            )

    def test_distinct_values_for_one_type_coexist(self):
        t = Target.objects.create(name="jf2.invalid", root_domain="jf2.invalid")
        js = self._js(t)
        JavaScriptFinding.objects.create(
            js=js, target=t, finding_type="aws_key", location="body@aaa"
        )
        JavaScriptFinding.objects.create(
            js=js, target=t, finding_type="aws_key", location="body@bbb"
        )
        self.assertEqual(JavaScriptFinding.objects.filter(js=js).count(), 2)


class LiveJsAnalysisConstraintTests(TransactionTestCase):
    def test_second_live_analysis_for_one_asset_is_rejected(self):
        t = Target.objects.create(name="ja.invalid", root_domain="ja.invalid")
        js = JavaScriptAsset.objects.create(
            target=t, js_url="https://x.invalid/b.js", host="x.invalid", sha256="b" * 64
        )
        JSAnalysisJob.objects.create(target=t, js=js, trigger="NEW_JS", status="QUEUED")
        with self.assertRaises(IntegrityError), transaction.atomic():
            JSAnalysisJob.objects.create(target=t, js=js, trigger="JS_CHANGED", status="RUNNING")

    def test_finished_analyses_accumulate(self):
        t = Target.objects.create(name="ja2.invalid", root_domain="ja2.invalid")
        js = JavaScriptAsset.objects.create(
            target=t, js_url="https://x.invalid/c.js", host="x.invalid", sha256="c" * 64
        )
        for status in ("COMPLETED", "PARTIAL", "FAILED"):
            JSAnalysisJob.objects.create(target=t, js=js, trigger="manual", status=status)
        self.assertEqual(JSAnalysisJob.objects.filter(js=js).count(), 3)

    def test_different_assets_coexist(self):
        t = Target.objects.create(name="ja3.invalid", root_domain="ja3.invalid")
        js1 = JavaScriptAsset.objects.create(
            target=t, js_url="https://x.invalid/d.js", host="x.invalid", sha256="d" * 64
        )
        js2 = JavaScriptAsset.objects.create(
            target=t, js_url="https://x.invalid/e.js", host="x.invalid", sha256="e" * 64
        )
        JSAnalysisJob.objects.create(target=t, js=js1, status="QUEUED")
        JSAnalysisJob.objects.create(target=t, js=js2, status="QUEUED")
        self.assertEqual(JSAnalysisJob.objects.filter(status="QUEUED").count(), 2)


class DedupeMigrationBehaviourTests(TransactionTestCase):
    """The P2-008 data steps are safe, idempotent, and preserve data.

    The dedupe functions are what make the constraint addition possible on a
    real database that may already contain duplicates. On SQLite the constraint
    is backed by a unique *index* that cannot be dropped, so instead of
    manipulating the schema the functions are exercised against a model-shaped
    stand-in: the logic under test (keep the oldest, fold the rest, never drop
    a row's provenance) is what matters, and the constraint's enforcement is
    covered by the tests above.
    """

    def _apps_stub(self, asset_model, finding_model):

        class _Apps:
            def get_model(self, app, model):
                return {"Asset": asset_model, "JavaScriptFinding": finding_model}[model]

        return _Apps()

    def test_asset_dedupe_keeps_the_oldest_of_each_group(self):
        import importlib

        mod = importlib.import_module(
            "apps.assets.migrations." "0010_asset_uniq_asset_per_target_type_value_and_more"
        )

        class Row:
            def __init__(
                self, pk, target_id, asset_type, value, first_seen, discovered_by_job_id=None
            ):
                self.pk = pk
                self.target_id = target_id
                self.asset_type = asset_type
                self.value = value
                self.first_seen = first_seen
                self.discovered_by_job_id = discovered_by_job_id
                self.saved = []
                self.deleted = False

            def save(self, update_fields=None):
                self.saved.append(update_fields)

            def delete(self):
                self.deleted = True

        class Query:
            def __init__(self, rows):
                self.rows = rows

            def order_by(self, *a):
                return self

            def iterator(self):
                return iter(self.rows)

        rows = [
            Row(1, 7, "SUBDOMAIN", "a.invalid", 10, discovered_by_job_id=None),
            Row(2, 7, "SUBDOMAIN", "a.invalid", 20, discovered_by_job_id=99),
            Row(3, 7, "SUBDOMAIN", "b.invalid", 30),
            Row(4, 8, "SUBDOMAIN", "a.invalid", 40),  # different target: kept
        ]

        class Assets:
            class objects:
                pass

        Assets.objects = Query(rows)
        mod._dedupe_assets(self._apps_stub(Assets, None), None)

        self.assertFalse(rows[0].deleted)  # oldest survives
        self.assertTrue(rows[1].deleted)  # duplicate folded away
        self.assertFalse(rows[2].deleted)  # distinct value kept
        self.assertFalse(rows[3].deleted)  # distinct target kept
        # the survivor inherited the duplicate's provenance
        self.assertEqual(rows[0].discovered_by_job_id, 99)
        self.assertIn("discovered_by_job", rows[0].saved[0])

    def test_js_finding_dedupe_keeps_one_per_identity(self):
        import importlib

        mod = importlib.import_module(
            "apps.assets.migrations." "0010_asset_uniq_asset_per_target_type_value_and_more"
        )

        class Row:
            def __init__(self, js_id, finding_type, location):
                self.js_id = js_id
                self.finding_type = finding_type
                self.location = location
                self.deleted = False

            def delete(self):
                self.deleted = True

        rows = [
            Row(1, "aws_key", "body@aa"),
            Row(1, "aws_key", "body@aa"),  # duplicate
            Row(1, "aws_key", "body@bb"),  # distinct value
            Row(2, "aws_key", "body@aa"),  # distinct asset
        ]

        class Query:
            def __init__(self, rows):
                self.rows = rows

            def order_by(self, *a):
                return self

            def iterator(self):
                return iter(self.rows)

        class Findings:
            pass

        Findings.objects = Query(rows)
        mod._dedupe_js_findings(self._apps_stub(None, Findings), None)

        self.assertFalse(rows[0].deleted)
        self.assertTrue(rows[1].deleted)  # duplicate
        self.assertFalse(rows[2].deleted)  # different value kept
        self.assertFalse(rows[3].deleted)  # different asset kept

    def test_live_js_job_dedupe_fails_extras_with_a_reason(self):
        import importlib

        mod = importlib.import_module(
            "apps.jobs.migrations.0009_jsanalysisjob_uniq_live_js_analysis_per_asset"
        )

        class Row:
            def __init__(self, js_id, status, created_at, finished_at=None):
                self.js_id = js_id
                self.status = status
                self.created_at = created_at
                self.finished_at = finished_at
                self.error = ""
                self.saved = []

            def save(self, update_fields=None):
                self.saved.append(update_fields)

        rows = [
            Row(1, "QUEUED", 10),
            Row(1, "RUNNING", 20),  # duplicate live analysis for the same asset
            Row(2, "QUEUED", 30),  # different asset
        ]

        class Query:
            def __init__(self, rows):
                self.rows = rows

            def filter(self, **kw):
                return self

            def order_by(self, *a):
                return self

            def iterator(self):
                return iter(self.rows)

        class Jobs:
            pass

        Jobs.objects = Query(rows)

        class _Apps:
            def get_model(self, app, model):
                return Jobs

        mod._dedupe_live_js_jobs(_Apps(), None)
        self.assertEqual(rows[0].status, "QUEUED")  # oldest kept
        self.assertEqual(rows[1].status, "FAILED")  # extra failed loudly
        self.assertIn("superseded", rows[1].error)
        self.assertEqual(rows[2].status, "QUEUED")  # other asset untouched


class CrossTableUniquenessTests(TransactionTestCase):
    """Asset models that already relied on unique_together keep working."""

    def test_subdomain_port_and_url_uniqueness(self):
        from apps.assets.models import Port, Subdomain, URLAsset

        t = Target.objects.create(name="xt.invalid", root_domain="xt.invalid")
        Subdomain.objects.create(target=t, hostname="a.xt.invalid")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Subdomain.objects.create(target=t, hostname="a.xt.invalid")

        Port.objects.create(target=t, ip="1.2.3.4", port=80, protocol="tcp", state="open")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Port.objects.create(target=t, ip="1.2.3.4", port=80, protocol="tcp", state="open")

        URLAsset.objects.create(
            target=t,
            raw_url="https://a.xt.invalid",
            canonical_url="https://a.xt.invalid",
            host="a.xt.invalid",
        )
        with self.assertRaises(IntegrityError), transaction.atomic():
            URLAsset.objects.create(
                target=t,
                raw_url="https://a.xt.invalid",
                canonical_url="https://a.xt.invalid",
                host="a.xt.invalid",
            )

    def test_tool_execution_and_scan_job_allow_many_rows(self):
        t = Target.objects.create(name="many.invalid", root_domain="many.invalid")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", status="COMPLETED")
        for _ in range(3):
            ScanJob.objects.create(target=t, job_type="ports", status="COMPLETED")
            ToolExecution.objects.create(
                target=t, scan_run=run, tool_name="naabu", status="COMPLETED"
            )
        self.assertEqual(ScanJob.objects.filter(target=t).count(), 3)
        self.assertEqual(ToolExecution.objects.filter(target=t).count(), 3)
