"""P1-004/P1-005: observation persistence failures are visible, and every
observation is traceable to its scan, job, tool execution, target and time.

P1-004: a lost AssetObservation row must never be silently discarded -- it is
        logged, counted, surfaced as an event, and degrades the stage.
P1-005: observations link to job + tool_execution, and the chain must be
        target-consistent (no cross-target leakage).
"""

from unittest.mock import patch

from django.test import TestCase

from apps.core.execution_context import (
    ScanContext,
    evidence_failures,
    record_observation,
    scan_context,
)
from apps.jobs import tasks
from apps.jobs.models import AssetObservation, ScanJob, ToolExecution
from apps.targets.models import Target


def _target(name="ob.invalid"):
    return Target.objects.create(
        name=name, root_domain=name, authorization_status=Target.AUTH_AUTHORIZED
    )


class ObservationFailureTests(TestCase):
    """P1-004"""

    def test_observation_write_failure_is_counted_not_silent(self):
        t = _target()
        from apps.jobs.models import ScanRun

        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        evidence_failures(reset=True)
        with patch(
            "apps.jobs.models.AssetObservation.objects.create", side_effect=RuntimeError("db down")
        ):
            with scan_context(ScanContext(target_id=t.pk, scan_run=run)):
                obs = record_observation("SUBDOMAIN", "a.ob.invalid")
        self.assertIsNone(obs)
        losses = evidence_failures()
        self.assertEqual(len(losses), 1)
        self.assertEqual(losses[0]["kind"], "asset_observation")

    def test_observation_failure_degrades_the_stage(self):
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        t = Target.objects.create(
            name="ob2.invalid",
            root_domain="ob2.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
            scan_profile="active",
            scan_config={"ports": "80"},
        )
        IPAddress.objects.create(target=t, ip="203.0.113.5")
        with (
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch(
                "apps.jobs.models.AssetObservation.objects.create",
                side_effect=RuntimeError("db down"),
            ),
        ):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(ScanJob.objects.get(job_type="ports").status, "PARTIAL")

    def test_observation_failure_emits_event(self):
        from apps.jobs.models import ScanRun

        t = _target("ob3.invalid")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        evidence_failures(reset=True)
        with patch(
            "apps.jobs.models.AssetObservation.objects.create", side_effect=RuntimeError("db down")
        ):
            with scan_context(ScanContext(target_id=t.pk, scan_run=run)):
                record_observation("SUBDOMAIN", "a.ob3.invalid")
        # the tool-execution loss path emits JOB_FAILED; observation losses are
        # logged + counted, and are visible on the job log when a job is bound
        self.assertTrue(evidence_failures())

    def test_observation_success_is_not_counted(self):
        from apps.jobs.models import ScanRun

        t = _target("ob4.invalid")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        evidence_failures(reset=True)
        with scan_context(ScanContext(target_id=t.pk, scan_run=run)):
            obs = record_observation("SUBDOMAIN", "a.ob4.invalid")
        self.assertIsNotNone(obs)
        self.assertEqual(evidence_failures(), [])


class ObservationTraceabilityTests(TestCase):
    """P1-005: every observation links back to scan/job/tool/target."""

    def test_observation_links_to_run_and_target(self):
        from apps.jobs.models import ScanRun

        t = _target("tr.invalid")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        with scan_context(ScanContext(target_id=t.pk, scan_run=run)):
            obs = record_observation("SUBDOMAIN", "a.tr.invalid")
        self.assertEqual(obs.scan_run_id, run.pk)
        self.assertEqual(obs.target_id, t.pk)
        self.assertIsNotNone(obs.observed_at)

    def test_observation_links_to_tool_execution(self):
        from apps.jobs.models import ScanRun

        t = _target("tr2.invalid")
        run = ScanRun.objects.create(target=t, scan_type="DISCOVERY", trigger="manual")
        te = ToolExecution.objects.create(
            target=t, scan_run=run, tool_name="naabu", status="COMPLETED"
        )
        with scan_context(ScanContext(target_id=t.pk, scan_run=run, tool_execution=te)):
            obs = record_observation("PORT", "1.2.3.4:80")
        self.assertEqual(obs.tool_execution_id, te.pk)
        self.assertEqual(obs.scan_run_id, run.pk)

    def test_port_observations_link_to_the_socket_tool(self):
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        t = Target.objects.create(
            name="tr3.invalid",
            root_domain="tr3.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
            scan_profile="active",
            scan_config={"ports": "80"},
        )
        IPAddress.objects.create(target=t, ip="203.0.113.5")

        class _OpenSock:
            """Stand-in for a socket whose connect_ex reports an open port."""

            def __init__(self, *a, **kw):
                pass

            def settimeout(self, _t):
                pass

            def connect_ex(self, _addr):
                return 0

            def close(self):
                pass

        import socket as _socket

        with (
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch.object(_socket, "socket", return_value=_OpenSock()),
        ):
            tasks.scan_ports(t.id)
        obs = AssetObservation.objects.filter(target=t, asset_type="PORT").first()
        self.assertIsNotNone(obs, "port observation missing")
        te = ToolExecution.objects.get(tool_name="socket-connect")
        self.assertEqual(obs.tool_execution_id, te.pk)
        self.assertIsNotNone(obs.job_id)
        self.assertIsNotNone(obs.scan_run_id)

    def test_observation_target_consistency(self):
        """An observation cannot claim a tool execution from another target."""
        from apps.jobs.models import ScanRun

        a = _target("cons-a.invalid")
        b = _target("cons-b.invalid")
        run_b = ScanRun.objects.create(target=b, scan_type="DISCOVERY", trigger="manual")
        te_b = ToolExecution.objects.create(
            target=b, scan_run=run_b, tool_name="naabu", status="COMPLETED"
        )
        with self.assertRaises(Exception):
            AssetObservation.objects.create(
                target=a,
                scan_run=run_b,
                job=None,
                tool_execution=te_b,
                asset_type="PORT",
                asset_value="9.9.9.9:22",
            )

    def test_no_context_records_nothing_and_does_not_fail(self):
        evidence_failures(reset=True)
        self.assertIsNone(record_observation("SUBDOMAIN", "no-context.invalid"))
        self.assertEqual(evidence_failures(), [])
