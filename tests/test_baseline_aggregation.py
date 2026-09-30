"""P0-017: baseline final status must aggregate stages explicitly.

A baseline is only BASELINE_COMPLETE when every required stage fully
succeeded. Reduced coverage (fallback tools, partial results, skipped stages)
is PARTIAL. A failed required stage, or no record at all, is FAILED.
"""

from unittest.mock import patch

from django.test import TestCase

from apps.jobs import tasks
from apps.jobs.models import ScanRun
from apps.monitoring.models import Baseline
from apps.targets.models import Target

REQ = {
    "discover_subdomains": {"status": "COMPLETED", "new": 3},
    "resolve_dns": {"status": "COMPLETED", "new": 2},
    "scan_ports": {"status": "COMPLETED", "new": 1},
    "probe_http": {"status": "COMPLETED", "new": 1},
}
OPT = {"discover_urls": {"status": "COMPLETED", "new": 4}}


class AggregateBaselineTests(TestCase):
    def test_all_required_and_optional_ok_is_complete(self):
        self.assertEqual(tasks._aggregate_baseline({**REQ, **OPT}), "COMPLETE")

    def test_optional_skipped_is_complete(self):
        self.assertEqual(
            tasks._aggregate_baseline({**REQ, "discover_urls": {"status": "SKIPPED"}}), "COMPLETE"
        )

    def test_required_partial_is_partial(self):
        st = {**REQ, **OPT, "scan_ports": {"status": "PARTIAL", "new": 0}}
        self.assertEqual(tasks._aggregate_baseline(st), "PARTIAL")

    def test_required_skipped_is_partial(self):
        st = {**REQ, **OPT, "scan_ports": {"status": "SKIPPED", "reason": "burst budget reached"}}
        self.assertEqual(tasks._aggregate_baseline(st), "PARTIAL")

    def test_required_skipped_for_profile_exclusion_is_complete(self):
        # balanced profile has no port_scan by design -> not a coverage failure.
        st = {
            **REQ,
            **OPT,
            "scan_ports": {"status": "SKIPPED", "reason": "profile excludes port_scan"},
        }
        self.assertEqual(tasks._aggregate_baseline(st), "COMPLETE")

    def test_optional_failed_is_partial(self):
        st = {**REQ, "discover_urls": {"status": "FAILED", "error": "boom"}}
        self.assertEqual(tasks._aggregate_baseline(st), "PARTIAL")

    def test_optional_partial_is_partial(self):
        st = {**REQ, "discover_urls": {"status": "PARTIAL"}}
        self.assertEqual(tasks._aggregate_baseline(st), "PARTIAL")

    def test_optional_missing_is_partial(self):
        # URL crawl left no record -> cannot verify, honest label is PARTIAL.
        self.assertEqual(tasks._aggregate_baseline(REQ.copy()), "PARTIAL")

    def test_required_failed_is_failed(self):
        st = {**REQ, **OPT, "discover_subdomains": {"status": "FAILED", "error": "no source"}}
        self.assertEqual(tasks._aggregate_baseline(st), "FAILED")

    def test_required_missing_record_is_failed(self):
        st = {**OPT, "resolve_dns": {"status": "COMPLETED"}}
        self.assertEqual(tasks._aggregate_baseline(st), "FAILED")

    def test_no_work_at_all_is_failed(self):
        self.assertEqual(tasks._aggregate_baseline({}), "FAILED")


class BaselineTargetOutcomeTests(TestCase):
    def _target(self):
        return Target.objects.create(
            name="agg.invalid",
            root_domain="agg.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )

    def _patch_stages(
        self,
        subsmo_domains="COMPLETED",
        dns="COMPLETED",
        ports="COMPLETED",
        http="COMPLETED",
        urls="COMPLETED",
    ):
        def _patches():
            return [
                patch.object(
                    tasks.discover_subdomains,
                    "run",
                    return_value={"status": subsmo_domains, "new": 1},
                ),
                patch.object(tasks.resolve_dns, "run", return_value={"status": dns, "new": 1}),
                patch.object(tasks.scan_ports, "run", return_value={"status": ports, "new": 1}),
                patch.object(tasks.probe_http, "run", return_value={"status": http, "new": 1}),
                patch.object(tasks.discover_urls, "run", return_value={"status": urls, "new": 1}),
            ]

        return _patches()

    def test_all_success_becomes_baseline_complete(self):
        t = self._target()
        with __import__("contextlib").ExitStack() as stack:
            for p in self._patch_stages():
                stack.enter_context(p)
            out = tasks.baseline_target(t.id)
        t.refresh_from_db()
        self.assertEqual(out["status"], "COMPLETED")
        self.assertEqual(t.baseline_status, "BASELINE_COMPLETE")
        self.assertIsNotNone(t.last_scan)
        self.assertEqual(Baseline.objects.get(target=t).status, "COMPLETE")
        run = ScanRun.objects.get(target=t, scan_type="DISCOVERY", trigger="baseline")
        self.assertEqual(run.status, "COMPLETED")
        from apps.events.models import Event

        self.assertTrue(Event.objects.filter(target=t, event_type="BASELINE_COMPLETED").exists())
        self.assertFalse(Event.objects.filter(target=t, event_type="BASELINE_FAILED").exists())

    def test_required_partial_becomes_baseline_partial(self):
        t = self._target()
        with __import__("contextlib").ExitStack() as stack:
            for p in self._patch_stages(ports="PARTIAL"):
                stack.enter_context(p)
            out = tasks.baseline_target(t.id)
        t.refresh_from_db()
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(t.baseline_status, "BASELINE_PARTIAL")
        self.assertEqual(Baseline.objects.get(target=t).status, "PARTIAL")
        run = ScanRun.objects.get(target=t, scan_type="DISCOVERY", trigger="baseline")
        self.assertEqual(run.status, "PARTIAL")
        from apps.events.models import Event

        self.assertTrue(Event.objects.filter(target=t, event_type="BASELINE_PARTIAL").exists())
        self.assertFalse(Event.objects.filter(target=t, event_type="BASELINE_COMPLETED").exists())

    def test_optional_failure_is_still_partial_not_complete(self):
        t = self._target()
        with __import__("contextlib").ExitStack() as stack:
            for p in self._patch_stages(urls="FAILED"):
                stack.enter_context(p)
            out = tasks.baseline_target(t.id)
        t.refresh_from_db()
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(t.baseline_status, "BASELINE_PARTIAL")

    def test_required_failure_becomes_baseline_failed(self):
        t = self._target()
        with __import__("contextlib").ExitStack() as stack:
            for p in self._patch_stages(subsmo_domains="FAILED"):
                stack.enter_context(p)
            out = tasks.baseline_target(t.id)
        t.refresh_from_db()
        self.assertEqual(out["status"], "FAILED")
        self.assertEqual(t.baseline_status, "BASELINE_FAILED")
        self.assertEqual(Baseline.objects.get(target=t).status, "FAILED")
        run = ScanRun.objects.get(target=t, scan_type="DISCOVERY", trigger="baseline")
        self.assertEqual(run.status, "FAILED")
        from apps.events.models import Event

        self.assertTrue(Event.objects.filter(target=t, event_type="BASELINE_FAILED").exists())
        self.assertFalse(Event.objects.filter(target=t, event_type="BASELINE_COMPLETED").exists())

    def test_stage_exception_is_a_required_failure(self):
        t = self._target()
        with __import__("contextlib").ExitStack() as stack:
            for i, p in enumerate(self._patch_stages()):
                if i == 2:  # scan_ports raises -> treated as FAILED
                    p = patch.object(tasks.scan_ports, "run", side_effect=RuntimeError("scan died"))
                stack.enter_context(p)
            out = tasks.baseline_target(t.id)
        self.assertEqual(out["status"], "FAILED")


class StageHonestyTests(TestCase):
    """Missing/unavailable tools degrade the stage, never a silent COMPLETED."""

    def test_scan_ports_missing_tool_reports_partial_and_closes_run(self):
        from apps.assets.models import IPAddress
        from apps.jobs.tasks import scan_ports
        from services.tool_adapters.adapters import NaabuAdapter

        t = Target.objects.create(
            name="p.invalid",
            root_domain="p.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
            scan_profile="active",
            scan_config={"ports": "80"},
        )
        IPAddress.objects.create(target=t, ip="203.0.113.5")
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            out = scan_ports(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        run = ScanRun.objects.get(target=t, scan_type="DISCOVERY")
        self.assertEqual(run.status, "PARTIAL")
        from apps.jobs.models import ToolExecution

        self.assertTrue(
            ToolExecution.objects.filter(tool_name="socket-connect", fallback_used=True).exists()
        )

    def test_probe_http_missing_tool_reports_partial(self):
        from apps.assets.models import Subdomain
        from apps.jobs.tasks import probe_http
        from services.tool_adapters.adapters import HttpxAdapter

        t = Target.objects.create(
            name="h.invalid", root_domain="h.invalid", authorization_status=Target.AUTH_AUTHORIZED
        )
        Subdomain.objects.create(target=t, hostname="www.h.invalid")
        with patch.object(HttpxAdapter, "is_available", return_value=False):
            out = probe_http(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        run = ScanRun.objects.get(target=t, scan_type="DISCOVERY")
        self.assertEqual(run.status, "PARTIAL")
