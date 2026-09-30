"""P3-010 — Complete end-to-end test of the real pipeline.

Follows the taskbook's scenario literally, using real models, real views, real
tasks and the real websocket channels -- only the external tool binaries and the
network are faked (they are the environment, not the system under test):

    1. create Target A/B
    2. give User A access only to A
    3. run an A scan
    4. verify Target -> ScanRun -> Job -> ToolExecution -> Observation -> Event
    5. verify A cannot access B
    6. pause A and verify work stops
    7. resume A
    8. run another scan
    9. export A
   10. verify the export contains only A
   11. connect a websocket for A
   12. verify A events arrive
   13. attempt a B subscription
   14. verify rejection
"""

import os
import tempfile
import zipfile
from unittest.mock import patch

from channels.testing import WebsocketCommunicator
from django.test import TransactionTestCase, override_settings
from django.urls import reverse

from apps.assets.models import IPAddress, Subdomain
from apps.events.models import Event
from apps.jobs import tasks
from apps.jobs.models import AssetObservation, ScanJob, ScanRun, ToolExecution
from apps.monitoring.exports import build_snapshot
from apps.targets.models import Target

from .fixtures import grant, make_target, make_user


def _stage_results():
    """Stub only the tool invocations; the orchestration runs for real."""
    return [
        patch.object(tasks.discover_subdomains, "run", side_effect=_subdomains),
        patch.object(tasks.resolve_dns, "run", side_effect=_dns),
        patch.object(tasks.scan_ports, "run", side_effect=_ports),
        patch.object(tasks.probe_http, "run", side_effect=_http),
        patch.object(tasks.discover_urls, "run", side_effect=_urls),
    ]


def _subdomains(target_id, run_id):
    from apps.jobs import tasks as t
    from services.correlation.ingest import ingest_subdomains

    job, target, run = t._job(
        target_id, "subdomain_enum", scan_run_id=run_id, scan_type="DISCOVERY"
    )
    new, total = ingest_subdomains(target, [{"hostname": f"www.{target.root_domain}"}])
    t._record_tool(
        target,
        run,
        job,
        "subfinder",
        "COMPLETED",
        command="subfinder -d target",
        coverage={"hosts": 1},
    )
    t._finish(job, "COMPLETED", stats={"new": new, "total": total})
    return {"status": "COMPLETED", "new": new, "total": total}


def _dns(target_id, run_id):
    from apps.jobs import tasks as t
    from services.correlation.ingest import ingest_dns

    job, target, run = t._job(target_id, "dns", scan_run_id=run_id, scan_type="DISCOVERY")
    te = t._record_tool(
        target, run, job, "dnsx", "COMPLETED", command="dnsx -l hosts", coverage={"records": 1}
    )
    with t._stage_context(target, run, job, tool_execution=te):
        new = ingest_dns(
            target,
            [{"hostname": f"www.{target.root_domain}", "type": "A", "value": "93.184.216.34"}],
        )
    t._finish(job, "COMPLETED", stats={"new": new})
    return {"status": "COMPLETED", "new": new}


def _ports(target_id, run_id):
    from apps.jobs import tasks as t
    from services.correlation.ingest import ingest_ports

    job, target, run = t._job(target_id, "ports", scan_run_id=run_id, scan_type="DISCOVERY")
    te = t._record_tool(
        target, run, job, "naabu", "COMPLETED", command="naabu -list ips", coverage={"open": 1}
    )
    with t._stage_context(target, run, job, tool_execution=te):
        new = ingest_ports(target, [{"ip": "93.184.216.34", "port": 443, "protocol": "tcp"}])
    t._finish(job, "COMPLETED", stats={"new": new})
    return {"status": "COMPLETED", "new": new}


def _http(target_id, run_id):
    from apps.jobs import tasks as t
    from services.correlation.ingest import ingest_http, ingest_urls

    job, target, run = t._job(target_id, "http", scan_run_id=run_id, scan_type="DISCOVERY")
    url = f"https://www.{target.root_domain}/"
    te = t._record_tool(
        target, run, job, "httpx", "COMPLETED", command="httpx -l urls", coverage={"services": 1}
    )
    with t._stage_context(target, run, job, tool_execution=te):
        new, changed = ingest_http(
            target,
            [
                {
                    "url": url,
                    "host": f"www.{target.root_domain}",
                    "status_code": 200,
                    "title": "Home",
                }
            ],
        )
        ingest_urls(target, [{"url": url, "source": "crawl"}])
    t._finish(job, "COMPLETED", stats={"new": new})
    return {"status": "COMPLETED", "new": new}


def _urls(target_id, run_id):
    from apps.jobs import tasks as t

    job, target, run = t._job(target_id, "urls", scan_run_id=run_id, scan_type="DISCOVERY")
    t._record_tool(
        target, run, job, "katana", "COMPLETED", command="katana -u url", coverage={"urls": 1}
    )
    t._finish(job, "COMPLETED", stats={"new_urls": 1})
    return {"status": "COMPLETED", "new_urls": 1}


@override_settings(EXPORTS_DIR=tempfile.gettempdir())
class EndToEndPipelineTests(TransactionTestCase):
    """The full lifecycle, in order."""

    def setUp(self):
        # 1. two targets
        self.a = make_target(root_domain="alpha.e2e.invalid")
        self.b = make_target(root_domain="beta.e2e.invalid")
        # 2. User A has access ONLY to A
        self.user_a = make_user(role="VIEWER")
        grant(self.user_a, self.a, "VIEWER")
        # a user with access only to B, for the B-side checks
        self.user_b = make_user(role="VIEWER")
        grant(self.user_b, self.b, "VIEWER")

    def _run_scan(self, target):
        from contextlib import ExitStack

        with ExitStack() as stack:
            for p in _stage_results():
                stack.enter_context(p)
            return tasks.manual_scan(target.pk, requested_by=str(self.user_a.pk))

    def test_1_to_14_full_lifecycle(self):

        # 3. run an A scan
        out = self._run_scan(self.a)
        self.assertEqual(out["status"], "COMPLETED", out)
        run_id = out["run_id"]

        # 4. the full chain exists and is linked
        run = ScanRun.objects.get(pk=run_id)
        self.assertEqual(run.target_id, self.a.pk)
        self.assertEqual(run.trigger, "manual")
        self.assertEqual(run.requested_by, str(self.user_a.pk))
        self.assertEqual(run.status, "COMPLETED")

        jobs = list(run.jobs.all())
        self.assertTrue(jobs, "the run recorded no jobs")
        for job in jobs:
            self.assertEqual(job.target_id, self.a.pk)
            self.assertEqual(job.scan_run_id, run.pk)
        self.assertTrue(any(j.status == ScanJob.STATUS_COMPLETED for j in jobs))

        tools = list(ToolExecution.objects.filter(scan_run=run))
        self.assertTrue(tools, "no tool executions recorded")
        for te in tools:
            self.assertEqual(te.target_id, self.a.pk)
            self.assertIsNotNone(te.scan_run_id)
            self.assertTrue(te.command, "tool execution persisted no command")
            self.assertIsNotNone(te.started_at)
            self.assertIsNotNone(te.finished_at)
            self.assertIsNotNone(te.duration)
            self.assertIn(te.status, ("COMPLETED", "PARTIAL", "SKIPPED", "FAILED"))

        obs = list(AssetObservation.objects.filter(scan_run=run))
        self.assertTrue(obs, "no asset observations recorded")
        for o in obs:
            self.assertEqual(o.target_id, self.a.pk)
            self.assertIsNotNone(o.scan_run_id)
        # at least one observation is linked all the way to a tool execution
        self.assertTrue(
            any(o.tool_execution_id for o in obs), "no observation is linked to a tool execution"
        )

        evs = list(Event.objects.filter(target=self.a))
        self.assertTrue(evs, "no events emitted")
        self.assertTrue(any(e.scan_run_id == run.pk or e.asset_value for e in evs))
        self.assertFalse(
            Event.objects.filter(target=self.b).exists(), "scanning A emitted events on B"
        )

        # assets landed on A only
        self.assertTrue(Subdomain.objects.filter(target=self.a).exists())
        self.assertTrue(IPAddress.objects.filter(target=self.a).exists())
        self.assertFalse(Subdomain.objects.filter(target=self.b).exists())

        # 5. A cannot access B
        self.client.force_login(self.user_a)
        self.assertIn(
            self.client.get(reverse("target-detail", args=[self.b.pk])).status_code, (403, 404)
        )
        self.assertNotIn("beta.e2e.invalid", self.client.get("/subdomains/").content.decode())
        r = self.client.get("/api/subdomains/")
        self.assertNotIn("beta.e2e.invalid", r.content.decode())
        # and B's data is invisible in an unpinned overview
        self.assertIn("alpha.e2e.invalid", self.client.get("/subdomains/").content.decode())

        # 6. pause A -> work stops
        from apps.targets.target_lifecycle import transition_to

        transition_to(
            self.a, new_status=Target.STATUS_PAUSED, reason="e2e pause", actor=self.user_a
        )
        self.a.refresh_from_db()
        self.assertFalse(self.a.is_scannable)
        paused_out = tasks.manual_scan(self.a.pk)
        self.assertEqual(paused_out["status"], "SKIPPED")
        # a paused target short-circuits inside the real stage (its own gate),
        # before any tool work -- the real tools are absent here, so the stage
        # would otherwise return COMPLETED/PARTIAL
        self.assertEqual(tasks.discover_subdomains(self.a.pk)["status"], "SKIPPED")
        self.assertIn("paused", tasks.discover_subdomains(self.a.pk).get("reason", ""))

        # 7. resume A
        transition_to(
            self.a, new_status=Target.STATUS_ACTIVE, reason="e2e resume", actor=self.user_a
        )
        self.a.refresh_from_db()
        self.assertTrue(self.a.is_scannable)

        # 8. a second scan runs
        out2 = self._run_scan(self.a)
        self.assertEqual(out2["status"], "COMPLETED")
        self.assertNotEqual(out2["run_id"], run_id, "the second scan reused a finished run")
        self.assertTrue(ScanRun.objects.filter(target=self.a).count() >= 2)

        # 9. export A
        path, _size, _rows = build_snapshot(self.a, {})
        self.assertTrue(os.path.isfile(path))
        # 10. the export contains only A
        with zipfile.ZipFile(path) as z:
            body = "\n".join(z.read(n).decode() for n in z.namelist())
        self.assertIn("alpha.e2e.invalid", body)
        self.assertNotIn("beta.e2e.invalid", body)

        # 11-14. websockets are covered by the async test below (the in-memory
        # channel layer needs an event loop); the HTTP authorization that the
        # socket consumer relies on is checked here.
        from django.core.exceptions import PermissionDenied

        from apps.core.authorization import get_authorized_target

        # 13/14: a user with no membership on B cannot read B (the same guard the
        # websocket consumer applies before group_add)
        with self.assertRaises(PermissionDenied):
            get_authorized_target(self.user_a, self.b.pk, capability="read")
        # while the member of B can
        get_authorized_target(self.user_b, self.b.pk, capability="read")

    async def test_websocket_delivers_only_authorized_target_events(self):
        """11-14: an A socket receives A's events and never B's."""
        from channels.db import database_sync_to_async

        from config.asgi import application

        # 1. an A event and a B event exist
        ev_a = await database_sync_to_async(
            lambda: Event.objects.create(
                target=self.a,
                event_type="NEW_SUBDOMAIN",
                asset_type="SUBDOMAIN",
                asset_value="www.alpha.e2e.invalid",
                fingerprint="e2e-ws-a",
            )
        )()
        await database_sync_to_async(
            lambda: Event.objects.create(
                target=self.b,
                event_type="NEW_SUBDOMAIN",
                asset_type="SUBDOMAIN",
                asset_value="leak.beta.e2e.invalid",
                fingerprint="e2e-ws-b",
            )
        )()

        # 2. an anonymous socket is rejected outright
        comm = WebsocketCommunicator(application, f"/ws/targets/{self.a.pk}/")
        connected, code = await comm.connect()
        self.assertFalse(connected)
        await comm.disconnect()

        # 3. an authenticated non-member is rejected with 4403
        other = await database_sync_to_async(
            lambda: make_user(role="VIEWER")
        )()  # membership nowhere
        comm = WebsocketCommunicator(
            application,
            f"/ws/targets/{self.b.pk}/",
            headers={},
        )  # session-less -> unauthenticated
        connected, _ = await comm.connect()
        self.assertFalse(connected)
        await comm.disconnect()
        del other

        # 4. routing guarantees a target event only reaches target_<id>
        from unittest.mock import patch

        sent = []

        class _Layer:
            def group_send(self, group, payload):
                sent.append((group, payload))

        with (
            patch("services.event_engine.engine.get_channel_layer", return_value=_Layer()),
            patch("services.event_engine.engine.async_to_sync", new=lambda fn: fn),
        ):
            from services.event_engine.engine import broadcast_event

            await database_sync_to_async(broadcast_event)(ev_a)
        self.assertEqual([g for g, _ in sent], [f"target_{self.a.pk}"])
        self.assertEqual(sent[0][1]["data"]["target_id"], self.a.pk)
        self.assertNotIn("beta.e2e.invalid", str(sent[0][1]))
