"""P1-011/P1-012: fallback coverage must be explicit, recorded and never overstated.

If a tool is missing and a lower-fidelity path runs, the run must:
  * record the fallback,
  * record the reduced coverage (configured vs attempted),
  * mark the stage/job PARTIAL or DEGRADED,
  * never claim coverage equivalent to the primary tool.
"""

from unittest.mock import patch

from django.test import TestCase

from apps.jobs import tasks
from apps.jobs.models import ScanJob, ScanRun, ToolExecution
from apps.targets.models import Target

ACTIVE = "active"


def _target(**kw):
    return Target.objects.create(
        name="fb.invalid",
        root_domain="fb.invalid",
        authorization_status=Target.AUTH_AUTHORIZED,
        scan_profile=ACTIVE,
        **kw,
    )


def _ip(target, ip="203.0.113.9"):
    from apps.assets.models import IPAddress

    return IPAddress.objects.create(target=target, ip=ip)


def _sub(target, hostname="www.fb.invalid"):
    from apps.assets.models import Subdomain

    return Subdomain.objects.create(target=target, hostname=hostname)


class CoverageNoteTests(TestCase):
    def test_full_coverage_is_not_reduced(self):
        note = tasks._coverage_note(100, 100, dimension="port_probes")
        self.assertFalse(note["reduced"])
        self.assertEqual(note["coverage_ratio"], 1.0)

    def test_partial_coverage_is_flagged_with_ratio(self):
        note = tasks._coverage_note(500, 100, dimension="port_probes")
        self.assertTrue(note["reduced"])
        self.assertEqual(note["coverage_ratio"], 0.2)
        self.assertEqual(note["configured"], 500)
        self.assertEqual(note["attempted"], 100)


class PortFallbackCoverageTests(TestCase):
    """P1-012: the limited socket fallback is reported as partial coverage."""

    def test_missing_naabu_is_recorded_and_coverage_is_reduced(self):
        from services.tool_adapters.adapters import NaabuAdapter

        t = _target(scan_config={"ports": ",".join(str(p) for p in range(80, 130))})
        _ip(t)
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        # the absent primary scanner is in the audit trail, marked as fallback
        naabu = ToolExecution.objects.get(tool_name="naabu")
        self.assertEqual(naabu.status, "SKIPPED")
        self.assertTrue(naabu.fallback_used)
        self.assertTrue(naabu.coverage["reduced"])
        self.assertEqual(naabu.coverage["configured"], 50)
        self.assertEqual(naabu.coverage["attempted"], 0)
        self.assertIn("not installed", naabu.coverage["reason"])
        # the fallback itself reports capped coverage, not full coverage
        sock = ToolExecution.objects.get(tool_name="socket-connect")
        self.assertTrue(sock.fallback_used)
        self.assertTrue(sock.coverage["reduced"])
        self.assertEqual(sock.coverage["ports_configured"], 50)
        self.assertEqual(sock.coverage["ports_attempted"], tasks.PORT_FALLBACK_MAX_PORTS)
        self.assertLess(sock.coverage["coverage_ratio"], 1.0)

    def test_limited_coverage_is_never_labelled_complete(self):
        from services.tool_adapters.adapters import NaabuAdapter

        t = _target(scan_config={"ports": ",".join(str(p) for p in range(80, 130))})
        _ip(t)
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            tasks.scan_ports(t.id)
        job = ScanJob.objects.get(job_type="ports")
        self.assertEqual(job.status, "PARTIAL")
        self.assertEqual(job.progress, 100)  # work finished, just reduced
        run = ScanRun.objects.get(target=t)
        self.assertEqual(run.status, "PARTIAL")

    def test_shared_suspect_ip_reduction_is_recorded(self):
        from apps.assets.models import IPAddress
        from services.tool_adapters.adapters import NaabuAdapter

        t = _target(scan_config={"ports": "80,443"})
        shared = IPAddress.objects.create(
            target=t, ip="198.51.100.7", shared_suspect=True, confirmed_dedicated=False
        )
        _ip(t, "203.0.113.9")
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            tasks.scan_ports(t.id)
        self.assertIsNotNone(shared.pk)
        sock = ToolExecution.objects.get(tool_name="socket-connect")
        self.assertEqual(sock.coverage["hosts_skipped_shared_suspect"], 1)
        self.assertEqual(sock.coverage["hosts_configured"], 1)

    def test_naabu_available_full_coverage_not_reduced(self):
        from services.tool_adapters.adapters import NaabuAdapter
        from services.tool_adapters.base import AdapterResult

        t = _target(scan_config={"ports": "80,443"})
        _ip(t)
        result = AdapterResult(
            "naabu",
            status="COMPLETED",
            data=[{"ip": "203.0.113.9", "port": 443, "protocol": "tcp"}],
        )
        with (
            patch.object(NaabuAdapter, "is_available", return_value=True),
            patch.object(NaabuAdapter, "run", return_value=result),
        ):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "COMPLETED")
        sock = ToolExecution.objects.get(tool_name="socket-connect")
        self.assertFalse(sock.fallback_used)
        self.assertFalse(sock.coverage["reduced"])


class HttpFallbackCoverageTests(TestCase):
    """P1-011: missing httpx is recorded; the urllib fallback is reduced."""

    def test_missing_httpx_recorded_and_stage_partial(self):
        from services.tool_adapters.adapters import HttpxAdapter

        t = _target()
        _sub(t)
        with patch.object(HttpxAdapter, "is_available", return_value=False):
            out = tasks.probe_http(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        httpx = ToolExecution.objects.get(tool_name="httpx")
        self.assertEqual(httpx.status, "SKIPPED")
        self.assertTrue(httpx.fallback_used)
        self.assertTrue(httpx.coverage["degraded"])
        self.assertEqual(httpx.coverage["configured"], 2)  # http + https candidate
        self.assertIn("not installed", httpx.coverage["reason"])

    def test_urllib_fallback_reports_capped_coverage(self):
        from services.tool_adapters.adapters import HttpxAdapter

        t = _target()
        for i in range(120):
            _sub(t, f"h{i}.fb.invalid")
        with patch.object(HttpxAdapter, "is_available", return_value=False):
            tasks.probe_http(t.id)
        urllib_te = ToolExecution.objects.get(tool_name="urllib")
        self.assertTrue(urllib_te.fallback_used)
        self.assertEqual(urllib_te.coverage["configured"], 240)  # 120 hosts x 2 schemes
        self.assertEqual(urllib_te.coverage["attempted"], tasks.HTTP_FALLBACK_MAX_URLS)
        self.assertTrue(urllib_te.coverage["reduced"])
        self.assertAlmostEqual(
            urllib_te.coverage["coverage_ratio"], tasks.HTTP_FALLBACK_MAX_URLS / 240, places=3
        )


class SubdomainSourceFallbackTests(TestCase):
    """Missing passive sources degrade the stage, per-source."""

    def test_all_sources_missing_yields_partial(self):
        from services.tool_adapters.adapters import (
            AmassAdapter,
            AssetfinderAdapter,
            CrtshAdapter,
            FindomainAdapter,
            SubfinderAdapter,
        )

        t = _target()
        with (
            patch.object(SubfinderAdapter, "is_available", return_value=False),
            patch.object(AmassAdapter, "is_available", return_value=False),
            patch.object(FindomainAdapter, "is_available", return_value=False),
            patch.object(AssetfinderAdapter, "is_available", return_value=False),
            patch.object(CrtshAdapter, "is_available", return_value=False),
        ):
            out = tasks.discover_subdomains(t.id)
        self.assertEqual(out["status"], "PARTIAL")
        # every source is individually recorded as skipped
        recorded = {te.tool_name: te for te in ToolExecution.objects.all()}
        for name in ("subfinder", "amass", "findomain", "assetfinder"):
            self.assertIn(name, recorded)
            self.assertEqual(recorded[name].status, "SKIPPED")


class NucleiFallbackTests(TestCase):
    """Missing nuclei never validates, and the gap is recorded."""

    def test_target_nuclei_records_missing_tool(self):
        from services.tool_adapters.adapters import NucleiAdapter

        t = _target()
        with patch.object(NucleiAdapter, "is_available", return_value=False):
            out = tasks.run_nuclei(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        te = ToolExecution.objects.get(tool_name="nuclei")
        self.assertEqual(te.status, "SKIPPED")
        self.assertTrue(te.coverage["degraded"])
        self.assertFalse(te.coverage["validated"])

    def test_single_url_nuclei_records_missing_tool(self):
        from services.tool_adapters.adapters import NucleiAdapter

        t = _target()
        with patch.object(NucleiAdapter, "is_available", return_value=False):
            out = tasks.nuclei_for_url(t.id, "https://www.fb.invalid/app.js")
        self.assertEqual(out["status"], "SKIPPED")
        te = ToolExecution.objects.filter(tool_name="nuclei").last()
        self.assertEqual(te.status, "SKIPPED")
        self.assertFalse(te.coverage["validated"])


class UrlDiscoveryFallbackTests(TestCase):
    def test_missing_katana_records_reduced_crawl(self):
        from services.tool_adapters.adapters import KatanaAdapter

        t = _target()
        with (
            patch.object(KatanaAdapter, "is_available", return_value=False),
            patch.object(tasks, "_fetch_url_for_recon", return_value=b""),
        ):
            out = tasks.host_url_discovery(t.id, "https://www.fb.invalid/")
        self.assertEqual(out["status"], "PARTIAL")
        te = ToolExecution.objects.get(tool_name="katana")
        self.assertEqual(te.status, "SKIPPED")
        self.assertTrue(te.fallback_used)
        self.assertTrue(te.coverage["reduced"])


class PerIpFallbackTests(TestCase):
    def test_process_new_ip_records_naabu_and_fallback(self):
        from services.tool_adapters.adapters import NaabuAdapter

        t = _target(scan_config={"ports": "80,443"})
        _ip(t)
        with patch.object(NaabuAdapter, "is_available", return_value=False):
            out = tasks.process_new_ip(t.id, "203.0.113.9")
        self.assertEqual(out["status"], "COMPLETED")
        naabu = ToolExecution.objects.filter(tool_name="naabu").last()
        sock = ToolExecution.objects.filter(tool_name="socket-connect").last()
        self.assertIsNotNone(naabu)
        self.assertIsNotNone(sock)
        # single-IP fallback covers the full capped list -> not reduced
        self.assertFalse(sock.coverage["reduced"])
        self.assertIn("naabu unavailable", sock.coverage["reason"])


class JsAnalyzerFallbackTests(TestCase):
    """A JS analysis with missing analyzers is degraded, never COMPLETE."""

    def _js_job(self):
        from apps.assets.models import JavaScriptAsset
        from apps.jobs.models import JSAnalysisJob

        t = _target()
        js = JavaScriptAsset.objects.create(target=t, js_url="https://www.fb.invalid/app.js")
        return t, JSAnalysisJob.objects.create(target=t, js=js, trigger="NEW_JS")

    def test_all_analyzers_missing_reports_partial(self):
        from services.correlation.jsanalysis import run_analysis
        from services.tool_adapters.adapters import (
            JsluiceAdapter,
            LinkfinderAdapter,
            RetirejsAdapter,
            SecretfinderAdapter,
            SemgrepAdapter,
        )

        _t, job = self._js_job()
        with (
            patch.object(tasks, "_fetch_url_for_recon", return_value=b"var x = 1;"),
            patch.object(JsluiceAdapter, "is_available", return_value=False),
            patch.object(LinkfinderAdapter, "is_available", return_value=False),
            patch.object(SecretfinderAdapter, "is_available", return_value=False),
            patch.object(SemgrepAdapter, "is_available", return_value=False),
            patch.object(RetirejsAdapter, "is_available", return_value=False),
        ):
            status = run_analysis(job.pk)
        self.assertEqual(status, "PARTIAL")
        job.refresh_from_db()
        self.assertIn("degraded coverage", job.error)
        for name in ("jsluice", "linkfinder", "secretfinder", "semgrep", "retire"):
            te = ToolExecution.objects.filter(tool_name=name).last()
            self.assertIsNotNone(te, f"{name} missing from audit trail")
            self.assertEqual(te.status, "SKIPPED")
            self.assertFalse(te.coverage["analyzed"])
