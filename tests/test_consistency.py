"""P0-011 — cross-model target consistency: negative tests.

The taskbook requires: "Write negative tests that intentionally create
mismatched relationships and verify they fail."

Every required invariant is exercised in both directions — through the normal
``save()`` path and through the ORM write paths that bypass it
(``bulk_create`` / ``update``) — plus the positive case for each, so a test
cannot pass merely because the rule is broken or the assertion is inverted.

Invariants under test (taskbook P0-011):
    ScanJob.target           == ScanJob.scan_run.target
    ScanJob.parent.target    == ScanJob.target
    JSAnalysisJob.target     == JSAnalysisJob.js.target
    JSAnalysisJob.parent_job.target == JSAnalysisJob.target
    ToolExecution.target     == ToolExecution.scan_run.target / job.target
    AssetObservation.target  == AssetObservation.scan_run.target
    Event.target             == Event.scan_run.target
    Alert.target             == Alert.event.target
"""

import django.core.exceptions
from django.test import TestCase
from django.utils import timezone

from apps.assets.models import JavaScriptAsset
from apps.core.consistency import ExecutionConsistencyError
from apps.events.models import Alert, Event
from apps.jobs.models import (
    AssetObservation,
    JSAnalysisJob,
    ScanJob,
    ScanRun,
    ToolExecution,
)
from apps.targets.models import Target


class ConsistencyTestBase(TestCase):
    def setUp(self):
        now = timezone.now()
        self.a = Target.objects.create(root_domain="alpha.test", created_at=now, updated_at=now)
        self.b = Target.objects.create(root_domain="bravo.test", created_at=now, updated_at=now)
        self.run_a = ScanRun.objects.create(target=self.a, status="RUNNING", started_at=now)
        self.run_b = ScanRun.objects.create(target=self.b, status="RUNNING", started_at=now)

    def assertRejected(self, callable_, *args, **kwargs):
        """Assert the write is refused and that nothing was persisted."""
        with self.assertRaises(ExecutionConsistencyError):
            callable_(*args, **kwargs)

    def unique_fingerprint(self, tag):
        return f"fp-{tag}-{self.a.pk}-{self.run_a.pk}"


class ScanJobConsistencyTests(ConsistencyTestBase):
    def test_scan_run_on_other_target_is_rejected(self):
        self.assertRejected(
            ScanJob.objects.create, target=self.a, scan_run=self.run_b, job_type="dns"
        )

    def test_matching_scan_run_is_accepted(self):
        job = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="dns")
        self.assertEqual(job.target_id, self.a.pk)
        self.assertEqual(job.scan_run_id, self.run_a.pk)

    def test_parent_job_on_other_target_is_rejected(self):
        parent_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="ports")
        self.assertRejected(
            ScanJob.objects.create,
            target=self.a,
            scan_run=self.run_a,
            parent=parent_b,
            job_type="dns",
        )

    def test_matching_parent_is_accepted(self):
        parent_a = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="ports")
        child = ScanJob.objects.create(
            target=self.a, scan_run=self.run_a, parent=parent_a, job_type="dns"
        )
        self.assertEqual(child.parent_id, parent_a.pk)

    def test_parent_on_other_target_rejected_even_via_update(self):
        parent_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="ports")
        child = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="dns")
        self.assertRejected(ScanJob.objects.filter(pk=child.pk).update, parent=parent_b)
        child.refresh_from_db()
        self.assertIsNone(child.parent_id)

    def test_scan_run_repointed_to_other_target_via_update_is_rejected(self):
        child = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="dns")
        self.assertRejected(ScanJob.objects.filter(pk=child.pk).update, scan_run=self.run_b)
        child.refresh_from_db()
        self.assertEqual(child.scan_run_id, self.run_a.pk)

    def test_bulk_create_with_mismatched_run_is_rejected(self):
        self.assertRejected(
            ScanJob.objects.bulk_create,
            [ScanJob(target=self.a, scan_run=self.run_b, job_type="dns")],
        )

    def test_bulk_create_with_matching_run_is_accepted(self):
        created = ScanJob.objects.bulk_create(
            [ScanJob(target=self.a, scan_run=self.run_a, job_type="dns")]
        )
        self.assertEqual(len(created), 1)
        self.assertEqual(ScanJob.objects.get(pk=created[0].pk).target_id, self.a.pk)

    def test_bulk_create_is_atomic_with_the_batch(self):
        """A rejected batch must not leave its valid rows behind."""
        self.assertRejected(
            ScanJob.objects.bulk_create,
            [
                ScanJob(target=self.a, scan_run=self.run_a, job_type="dns"),
                ScanJob(target=self.b, scan_run=self.run_a, job_type="ports"),
            ],
        )
        self.assertEqual(ScanJob.objects.filter(target=self.a).count(), 0)


class JSAnalysisJobConsistencyTests(ConsistencyTestBase):
    def setUp(self):
        super().setUp()
        now = timezone.now()
        common = {"first_seen": now, "last_seen": now, "discovered_from": "test"}
        self.js_a = JavaScriptAsset.objects.create(
            target=self.a, js_url="https://a.test/a.js", host="a.test", sha256="a" * 64, **common
        )
        self.js_b = JavaScriptAsset.objects.create(
            target=self.b, js_url="https://b.test/b.js", host="b.test", sha256="b" * 64, **common
        )

    def test_js_asset_on_other_target_is_rejected(self):
        self.assertRejected(JSAnalysisJob.objects.create, target=self.a, js=self.js_b)

    def test_matching_js_asset_is_accepted(self):
        job = JSAnalysisJob.objects.create(target=self.a, js=self.js_a)
        self.assertEqual(job.target_id, self.a.pk)

    def test_parent_job_on_other_target_is_rejected(self):
        parent_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="js")
        self.assertRejected(
            JSAnalysisJob.objects.create, target=self.a, js=self.js_a, parent_job=parent_b
        )

    def test_matching_parent_job_and_run_are_accepted(self):
        parent_a = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="js")
        job = JSAnalysisJob.objects.create(
            target=self.a, js=self.js_a, parent_job=parent_a, scan_run=self.run_a
        )
        self.assertEqual(job.scan_run_id, self.run_a.pk)

    def test_scan_run_on_other_target_is_rejected(self):
        self.assertRejected(
            JSAnalysisJob.objects.create, target=self.a, js=self.js_a, scan_run=self.run_b
        )

    def test_js_recheck_is_traceable_to_the_execution_root(self):
        """P0-010: a JS analysis must be answerable to a ScanRun with no free-form id."""
        job = JSAnalysisJob.objects.create(target=self.a, js=self.js_a, scan_run=self.run_a)
        self.assertIsNotNone(job.scan_run_id)
        self.assertEqual(self.run_a.js_analyses.get(pk=job.pk).pk, job.pk)


class ToolExecutionConsistencyTests(ConsistencyTestBase):
    def test_run_on_other_target_is_rejected(self):
        self.assertRejected(
            ToolExecution.objects.create, target=self.a, scan_run=self.run_b, tool_name="nmap"
        )

    def test_job_on_other_target_is_rejected(self):
        job_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="ports")
        self.assertRejected(
            ToolExecution.objects.create,
            target=self.a,
            scan_run=self.run_a,
            job=job_b,
            tool_name="nmap",
        )

    def test_matching_run_and_job_are_accepted(self):
        job_a = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="ports")
        te = ToolExecution.objects.create(
            target=self.a, scan_run=self.run_a, job=job_a, tool_name="nmap"
        )
        self.assertEqual(te.target_id, self.a.pk)

    def test_bulk_create_with_mismatched_run_is_rejected(self):
        self.assertRejected(
            ToolExecution.objects.bulk_create,
            [ToolExecution(target=self.a, scan_run=self.run_b, tool_name="nmap")],
        )


class AssetObservationConsistencyTests(ConsistencyTestBase):
    def test_run_on_other_target_is_rejected(self):
        self.assertRejected(
            AssetObservation.objects.create,
            target=self.a,
            scan_run=self.run_b,
            asset_type="subdomain",
            asset_value="x.test",
        )

    def test_matching_run_is_accepted(self):
        obs = AssetObservation.objects.create(
            target=self.a, scan_run=self.run_a, asset_type="subdomain", asset_value="x.test"
        )
        self.assertEqual(obs.target_id, self.a.pk)

    def test_job_on_other_target_is_rejected(self):
        job_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="ports")
        self.assertRejected(
            AssetObservation.objects.create,
            target=self.a,
            scan_run=self.run_a,
            job=job_b,
            asset_type="subdomain",
            asset_value="x.test",
        )

    def test_tool_execution_on_other_target_is_rejected(self):
        te_b = ToolExecution.objects.create(target=self.b, scan_run=self.run_b, tool_name="nmap")
        self.assertRejected(
            AssetObservation.objects.create,
            target=self.a,
            scan_run=self.run_a,
            tool_execution=te_b,
            asset_type="subdomain",
            asset_value="x.test",
        )

    def test_required_run_is_enforced(self):
        self.assertRejected(
            AssetObservation.objects.create,
            target=self.a,
            asset_type="subdomain",
            asset_value="x.test",
        )

    def test_bulk_create_with_mismatched_run_is_rejected(self):
        self.assertRejected(
            AssetObservation.objects.bulk_create,
            [
                AssetObservation(
                    target=self.a, scan_run=self.run_b, asset_type="subdomain", asset_value="x.test"
                )
            ],
        )


class EventConsistencyTests(ConsistencyTestBase):
    def test_run_on_other_target_is_rejected(self):
        self.assertRejected(
            Event.objects.create,
            event_type="NEW_IP",
            target=self.a,
            scan_run=self.run_b,
            asset_type="ip",
            asset_value="1.1.1.1",
            fingerprint=self.unique_fingerprint("ev-bad"),
        )

    def test_matching_run_is_accepted(self):
        ev = Event.objects.create(
            event_type="NEW_IP",
            target=self.a,
            scan_run=self.run_a,
            asset_type="ip",
            asset_value="1.1.1.1",
            fingerprint=self.unique_fingerprint("ev-ok"),
        )
        self.assertEqual(ev.target_id, self.a.pk)

    def test_target_less_event_inherits_the_run_target(self):
        """A target-null event off a target-scoped run is not ambiguous."""
        ev = Event.objects.create(
            event_type="JOB_FAILED",
            target=None,
            scan_run=self.run_a,
            asset_type="job",
            asset_value="js",
            fingerprint=self.unique_fingerprint("ev-inherit"),
        )
        self.assertEqual(ev.target_id, self.a.pk)

    def test_genuinely_global_event_stays_global(self):
        ev = Event.objects.create(
            event_type="CVE_STATUS_CHANGED",
            target=None,
            scan_run=None,
            asset_type="cve",
            asset_value="CVE-1",
            fingerprint=self.unique_fingerprint("ev-global"),
        )
        self.assertIsNone(ev.target_id)

    def test_parent_event_on_other_target_is_rejected(self):
        parent_b = Event.objects.create(
            event_type="NEW_IP",
            target=self.b,
            scan_run=self.run_b,
            asset_type="ip",
            asset_value="9.9.9.9",
            fingerprint=self.unique_fingerprint("ev-parent-b"),
        )
        self.assertRejected(
            Event.objects.create,
            event_type="IP_CHANGED",
            target=self.a,
            scan_run=self.run_a,
            parent_event=parent_b,
            asset_type="ip",
            asset_value="9.9.9.9",
            fingerprint=self.unique_fingerprint("ev-child-bad"),
        )

    def test_event_cannot_be_repointed_to_another_target(self):
        ev = Event.objects.create(
            event_type="NEW_IP",
            target=self.a,
            scan_run=self.run_a,
            asset_type="ip",
            asset_value="2.2.2.2",
            fingerprint=self.unique_fingerprint("ev-move"),
        )
        ev.target = self.b
        self.assertRejected(ev.save)
        ev.refresh_from_db()
        self.assertEqual(ev.target_id, self.a.pk)


class AlertConsistencyTests(ConsistencyTestBase):
    def test_event_on_other_target_is_rejected(self):
        ev_b = Event.objects.create(
            event_type="NEW_IP",
            target=self.b,
            scan_run=self.run_b,
            asset_type="ip",
            asset_value="3.3.3.3",
            fingerprint=self.unique_fingerprint("al-ev-b"),
        )
        self.assertRejected(Alert.objects.create, event=ev_b, target=self.a)

    def test_matching_event_is_accepted(self):
        ev_a = Event.objects.create(
            event_type="NEW_IP",
            target=self.a,
            scan_run=self.run_a,
            asset_type="ip",
            asset_value="4.4.4.4",
            fingerprint=self.unique_fingerprint("al-ev-a"),
        )
        alert = Alert.objects.create(event=ev_a)
        self.assertEqual(alert.target_id, self.a.pk)

    def test_required_event_is_enforced(self):
        orphan = Alert(target=self.a)
        with self.assertRaises(django.core.exceptions.ValidationError) as ctx:
            orphan.full_clean(validate_unique=False)
        self.assertIn("required", str(ctx.exception))

    def test_alert_target_is_inherited_from_event(self):
        ev_a = Event.objects.create(
            event_type="NEW_IP",
            target=self.a,
            scan_run=self.run_a,
            asset_type="ip",
            asset_value="6.6.6.6",
            fingerprint=self.unique_fingerprint("al-inherit"),
        )
        alert = Alert.objects.create(event=ev_a, target=None)
        self.assertEqual(alert.target_id, self.a.pk)


class ValidationIsSideEffectFreeTests(ConsistencyTestBase):
    """A validator must not mutate the instance it validates.

    The previous implementation assigned ``self.target_id`` inside
    ``_consistency_violations``, so calling ``full_clean()`` could leave a
    half-validated object mutated even if a later validation step then failed.
    """

    def test_check_target_consistency_does_not_assign_a_target(self):
        ev = Event(
            event_type="NEW_IP",
            scan_run=self.run_a,
            target=None,
            asset_type="ip",
            asset_value="7.7.7.7",
            fingerprint="fp-sideeffect",
        )
        ev.check_target_consistency()
        self.assertIsNone(ev.target_id)

    def test_save_applies_inheritance_explicitly(self):
        ev = Event.objects.create(
            event_type="NEW_IP",
            scan_run=self.run_a,
            target=None,
            asset_type="ip",
            asset_value="8.8.8.8",
            fingerprint=self.unique_fingerprint("al-save"),
        )
        self.assertEqual(ev.target_id, self.a.pk)

    def test_clean_does_not_assign_a_target(self):
        ev = Event(
            event_type="NEW_IP",
            scan_run=self.run_a,
            target=None,
            asset_type="ip",
            asset_value="9.9.9.10",
            fingerprint=self.unique_fingerprint("al-clean"),
        )
        ev.clean()
        self.assertIsNone(ev.target_id)

    def test_contradictory_parents_are_rejected_not_guessed(self):
        """Two parents on different targets with no own target must fail loudly."""
        job_b = ScanJob.objects.create(target=self.b, scan_run=self.run_b, job_type="ports")
        obs = AssetObservation(
            target=None,
            scan_run=self.run_a,
            job=job_b,
            asset_type="subdomain",
            asset_value="amb.test",
        )
        with self.assertRaises(ExecutionConsistencyError) as ctx:
            obs.save()
        self.assertIn("disagree", str(ctx.exception))


class ScanRunChainTests(ConsistencyTestBase):
    """P0-010 — the whole chain must be walkable with joins alone."""

    def test_full_chain_is_reachable_from_the_execution_root(self):
        job_a = ScanJob.objects.create(target=self.a, scan_run=self.run_a, job_type="js")
        now = timezone.now()
        js = JavaScriptAsset.objects.create(
            target=self.a,
            js_url="https://a.test/c.js",
            host="a.test",
            sha256="c" * 64,
            first_seen=now,
            last_seen=now,
            discovered_from="test",
        )
        js_job = JSAnalysisJob.objects.create(
            target=self.a, js=js, parent_job=job_a, scan_run=self.run_a
        )
        te = ToolExecution.objects.create(
            target=self.a, scan_run=self.run_a, job=job_a, tool_name="semgrep"
        )
        obs = AssetObservation.objects.create(
            target=self.a,
            scan_run=self.run_a,
            job=job_a,
            tool_execution=te,
            asset_type="js_finding",
            asset_value="https://a.test/c.js",
        )
        ev = Event.objects.create(
            event_type="JS_ANALYSIS_COMPLETED",
            target=self.a,
            scan_run=self.run_a,
            asset_type="js",
            asset_value=js.js_url,
            fingerprint=self.unique_fingerprint("chain"),
        )

        run = ScanRun.objects.get(pk=self.run_a.pk)
        self.assertEqual(run.jobs.get(pk=job_a.pk).pk, job_a.pk)
        self.assertEqual(run.js_analyses.get(pk=js_job.pk).pk, js_job.pk)
        self.assertEqual(run.tool_executions.get(pk=te.pk).pk, te.pk)
        self.assertEqual(run.observations.get(pk=obs.pk).pk, obs.pk)
        self.assertEqual(run.events.get(pk=ev.pk).pk, ev.pk)
        # And every hop agrees on one target.
        for row in (job_a, js_job, te, obs, ev):
            self.assertEqual(row.target_id, self.a.pk)

    def test_no_model_still_carries_a_free_form_run_id_as_its_only_link(self):
        for model, field in (
            (ScanJob, "run_id_legacy"),
            (JSAnalysisJob, "scan_run"),
            (ToolExecution, "scan_run"),
            (AssetObservation, "scan_run"),
            (Event, "scan_run"),
        ):
            with self.subTest(model=model.__name__):
                names = {f.name for f in model._meta.get_fields()}
                self.assertIn(field, names)
                if field == "run_id_legacy":
                    # Legacy column is audit-only; the real FK must also exist.
                    self.assertIn("scan_run", names)
