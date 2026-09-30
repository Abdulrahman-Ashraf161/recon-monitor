"""P1-015/P1-016: export security and per-target purity.

P1-015: an authenticated user may only create/inspect/download exports for
         targets they are authorized for; a guessed ExportJob id must not
         bypass that; stored paths cannot escape the export root; concurrent
         exports do not collide.
P1-016: an export of target A contains only A's data -- every asset class.
"""

import json
import os
import threading
import zipfile

from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from apps.assets.models import (
    CVE,
    APIEndpoint,
    HTTPService,
    IPAddress,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
    Technology,
    URLAsset,
)
from apps.core.authorization import grant_membership
from apps.events.models import Event
from apps.jobs.models import ScanRun
from apps.monitoring.exports import build_snapshot, export_dir, run_export_job
from apps.monitoring.models import ExportJob
from apps.targets.models import Target, TargetMembership

from .fixtures import make_user


def _user(username, role="VIEWER", superuser=False):
    return make_user(username=username, role=role, superuser=superuser)


def _target(name, owner=None):
    t = Target.objects.create(
        name=name, root_domain=name, authorization_status=Target.AUTH_AUTHORIZED
    )
    if owner is not None:
        grant_membership(owner, t, TargetMembership.ROLE_OWNER)
    return t


def _seed(target, tag):
    """Populate one target with one of everything, tagged so mixing is visible."""
    sub = Subdomain.objects.create(target=target, hostname=f"{tag}.{target.root_domain}")
    IPAddress.objects.create(target=target, ip="203.0.113.10")
    port = Port.objects.create(
        target=target, ip="203.0.113.10", port=443, protocol="tcp", state="open"
    )
    svc = HTTPService.objects.create(target=target, url=f"https://{tag}.{target.root_domain}/")
    url = URLAsset.objects.create(
        target=target,
        raw_url=f"https://{tag}.{target.root_domain}/a",
        canonical_url=f"https://{tag}.{target.root_domain}/a",
        host=f"{tag}.{target.root_domain}",
        path="/a",
    )
    api = APIEndpoint.objects.create(
        target=target, url=f"https://{tag}.{target.root_domain}/api/v1", method="GET"
    )
    js = JavaScriptAsset.objects.create(
        target=target,
        js_url=f"https://cdn.{target.root_domain}/{tag}.js",
        host=f"cdn.{target.root_domain}",
        sha256=tag * 8,
    )
    tech = Technology.objects.create(target=target, asset_value=svc.url, product=f"{tag}-product")
    cve = CVE.objects.create(
        target=target, cve_id=f"CVE-2024-{tag.upper()}", product=tech.product, asset_value=svc.url
    )
    finding = SecurityFinding.objects.create(
        target=target, asset_value=svc.url, finding_type=f"{tag}-finding"
    )
    run = ScanRun.objects.create(
        target=target, scan_type="DISCOVERY", trigger="baseline", status="COMPLETED"
    )
    ev = Event.objects.create(
        target=target,
        event_type="NEW_SUBDOMAIN",
        asset_type="SUBDOMAIN",
        asset_id=sub.id,
        asset_value=sub.hostname,
        fingerprint=f"fp-{tag}",
        scan_run=run,
    )
    return {
        "sub": sub,
        "port": port,
        "svc": svc,
        "url": url,
        "api": api,
        "js": js,
        "tech": tech,
        "cve": cve,
        "finding": finding,
        "run": run,
        "event": ev,
    }


@override_settings(EXPORTS_DIR="/tmp/recon-export-tests")
class ExportAuthorizationTests(TestCase):
    """P1-015"""

    def setUp(self):
        self.alice = _user("alice")
        self.bob = _user("bob")
        self.a = _target("a.invalid", owner=self.alice)
        self.b = _target("b.invalid", owner=self.bob)
        os.makedirs(export_dir(self.a), exist_ok=True)

    def _login(self, user):
        self.client.force_login(user)

    def _completed_job(self, target, name="export.txt", body="secret-data"):
        d = export_dir(target)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path, "w") as fh:
            fh.write(body)
        return ExportJob.objects.create(
            target=target,
            export_type="subdomains",
            format="txt",
            file_path=path,
            status=ExportJob.STATUS_COMPLETED,
            file_size=len(body),
            row_count=1,
            created_by=target and None,
        )

    def test_authorized_download_succeeds(self):
        job = self._completed_job(self.a)
        self._login(self.alice)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(b"".join(r.streaming_content), b"secret-data")

    def test_unauthorized_download_is_denied(self):
        job = self._completed_job(self.b)
        self._login(self.alice)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertEqual(r.status_code, 403)

    def test_guessed_export_id_does_not_bypass_authorization(self):
        """P1-015: sequential pk guessing must not leak another target's export."""
        secret = self._completed_job(self.b, name="guessed.txt", body="B-SECRET")
        self._login(self.alice)
        # walk the whole id space around the victim job
        for pk in range(max(1, secret.pk - 3), secret.pk + 4):
            r = self.client.get(reverse("export-download", args=[pk]))
            self.assertNotEqual(r.status_code, 200, f"pk={pk} leaked")
            if r.status_code == 200:
                self.fail("unauthorized export was served")
        # and the target's own job still works, so the 403s were authorization
        mine = self._completed_job(self.a, name="mine.txt", body="A-OK")
        self.assertEqual(
            self.client.get(reverse("export-download", args=[mine.pk])).status_code, 200
        )

    def test_anonymous_cannot_download(self):
        job = self._completed_job(self.a)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertIn(r.status_code, (302, 403))

    def test_history_is_scoped_to_authorized_targets(self):
        mine = self._completed_job(self.a)
        theirs = self._completed_job(self.b)
        self._login(self.alice)
        r = self.client.get(reverse("export-history"))
        self.assertEqual(r.status_code, 200)
        ids = [j.pk for j in r.context["jobs"]]
        self.assertIn(mine.pk, ids)
        self.assertNotIn(theirs.pk, ids)

    def test_export_index_denies_unauthorized_target(self):
        self._login(self.alice)
        r = self.client.get(reverse("export-index", args=[self.b.id]))
        self.assertEqual(r.status_code, 403)

    def test_export_create_denies_unauthorized_target(self):
        self._login(self.alice)
        r = self.client.post(
            reverse("export-create", args=[self.b.id]),
            {"export_type": "subdomains", "format": "txt"},
        )
        self.assertEqual(r.status_code, 403)
        self.assertEqual(ExportJob.all_objects.filter(target=self.b).count(), 0)

    def test_viewer_cannot_create_exports(self):
        self._login(self.bob)  # bob is an owner on b only, still OPERATOR-less
        r = self.client.post(
            reverse("export-create", args=[self.b.id]),
            {"export_type": "subdomains", "format": "txt"},
        )
        self.assertIn(r.status_code, (302, 403))

    def test_unknown_export_type_is_rejected_not_queued(self):
        op = _user("oper", role="OPERATOR")
        grant_membership(op, self.a, TargetMembership.ROLE_OPERATOR)
        self._login(op)
        r = self.client.post(
            reverse("export-create", args=[self.a.id]),
            {"export_type": "../../etc/passwd", "format": "txt"},
        )
        self.assertIn(r.status_code, (404, 302))
        self.assertEqual(ExportJob.all_objects.filter(export_type="../../etc/passwd").count(), 0)

    def test_deleted_target_export_is_not_served(self):
        job = self._completed_job(self.a)
        self._login(self.alice)
        from apps.core.authorization import revoke_membership

        revoke_membership(self.alice, self.a)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertEqual(r.status_code, 403)

    def test_traversal_in_stored_path_is_refused(self):
        """A tampered file_path must not turn a download into file disclosure."""
        job = self._completed_job(self.a)
        outside = "/tmp/recon-export-tests-SECRET.txt"
        with open(outside, "w") as fh:
            fh.write("TOP-SECRET")
        job.file_path = outside
        job.save(update_fields=["file_path"])
        self._login(self.alice)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertEqual(r.status_code, 404)
        self._assert_no_leak("TOP-SECRET", r)

    def test_traversal_relative_path_is_refused(self):
        job = self._completed_job(self.a)
        job.file_path = os.path.join(export_dir(self.a), "..", "..", "..", "etc", "passwd")
        job.save(update_fields=["file_path"])
        self._login(self.alice)
        r = self.client.get(reverse("export-download", args=[job.pk]))
        self.assertEqual(r.status_code, 404)

    def _assert_no_leak(self, needle, response):
        if response.status_code == 200:
            body = b"".join(response.streaming_content)
            self.assertNotIn(needle.encode(), body)

    def test_incomplete_job_is_not_served(self):
        job = self._completed_job(self.a)
        job.status = ExportJob.STATUS_PROCESSING
        job.save(update_fields=["status"])
        self._login(self.alice)
        self.assertEqual(
            self.client.get(reverse("export-download", args=[job.pk])).status_code, 404
        )

    def test_missing_file_is_not_served(self):
        job = self._completed_job(self.a)
        os.unlink(job.file_path)
        self._login(self.alice)
        self.assertEqual(
            self.client.get(reverse("export-download", args=[job.pk])).status_code, 404
        )


@override_settings(EXPORTS_DIR="/tmp/recon-export-tests2")
class ConcurrentExportTests(TransactionTestCase):
    """Real commits (no wrapping transaction), so the SQLite single-writer
    behaviour under test is the production one."""

    @staticmethod
    def _tune_sqlite_connection():
        from django.db import connections

        if connections["default"].vendor != "sqlite":
            return
        with connections["default"].cursor() as cursor:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=20000;")

    def _run_export_with_retry(self, job):
        """Retry only the SQLite single-writer artefact, never the assertion.

        The job row is created once: retrying the *creation* would leave extra
        export jobs behind and mask the collision being tested.
        """
        import time

        from django.db import OperationalError

        deadline = time.monotonic() + 30
        last = None
        while time.monotonic() < deadline:
            try:
                return run_export_job(job.pk)
            except OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                last = exc
                time.sleep(0.05)
        raise last

    def test_concurrent_exports_do_not_collide(self):
        t = _target("conc.invalid")
        results = []
        errors = []
        jobs = [
            ExportJob.all_objects.create(target=t, export_type="subdomains", format="txt")
            for _ in range(4)
        ]

        def _run(job):
            try:
                self._tune_sqlite_connection()
                results.append(self._run_export_with_retry(job))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_run, args=(j,)) for j in jobs]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        paths = {j.file_path for j in ExportJob.all_objects.filter(target=t)}
        self.assertEqual(len(paths), 4)  # every export has its own artifact
        for p in paths:
            self.assertTrue(os.path.isfile(p))
        # no temp files left behind
        leftovers = [f for f in os.listdir(export_dir(t)) if f.startswith(".tmp-")]
        self.assertEqual(leftovers, [])


@override_settings(EXPORTS_DIR="/tmp/recon-export-tests3")
class ExportPurityTests(TestCase):
    """P1-016: an export never mixes targets."""

    def _snapshot_text(self, target):
        path, _size, _rows = build_snapshot(target, {})
        with zipfile.ZipFile(path) as z:
            body = "\n".join(z.read(n).decode() for n in z.namelist())
        return body

    def test_snapshot_contains_only_its_own_target(self):
        a = _target("pa.invalid")
        b = _target("pb.invalid")
        _seed(a, "AAA")
        _seed(b, "BBB")
        text = self._snapshot_text(a)
        self.assertIn("AAA", text)
        self.assertNotIn("BBB", text)
        self.assertIn("pa.invalid", text)  # its own domain
        self.assertNotIn("pb.invalid", text)  # never the other one

    def test_every_asset_class_is_scoped(self):
        a = _target("qa.invalid")
        b = _target("qb.invalid")
        _seed(a, "AAA")
        _seed(b, "BBB")
        from apps.monitoring.exports import collect

        for etype in [
            "subdomains",
            "ips",
            "ports",
            "http",
            "urls",
            "apis",
            "javascript",
            "technologies",
            "cves",
            "findings",
            "events",
        ]:
            _name, _header, rows = collect(etype, a, {})
            flat = " ".join(" ".join(str(c) for c in r) for r in rows)
            self.assertNotIn("BBB", flat, f"{etype} leaked from target B")
            self.assertNotIn("qb.invalid", flat, f"{etype} leaked target B's domain")
        # events and metadata are included and scoped
        _name, _header, events = collect("events", a, {})
        self.assertTrue(any("AAA" in " ".join(str(c) for c in r) for r in events))
        self.assertFalse(any("BBB" in " ".join(str(c) for c in r) for r in events))

    def test_export_directory_is_keyed_by_id_not_domain(self):
        t = _target("weird.invalid")
        d = export_dir(t)
        self.assertIn(f"target-{t.pk:08d}", d)
        # a domain-shaped directory is not used, so a hostile domain can never
        # steer a path outside the export root
        self.assertNotIn(t.root_domain, d)

    def test_snapshot_contains_scan_metadata(self):
        t = _target("meta.invalid")
        _seed(t, "AAA")
        path, _size, _rows = build_snapshot(t, {})
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            meta_name = [n for n in names if n.endswith("metadata.json")]
            self.assertEqual(len(meta_name), 1)
            import json

            meta = json.loads(z.read(meta_name[0]))
            self.assertEqual(meta["target"], "meta.invalid")
            self.assertIn("baseline", meta)
            self.assertIn("exported_at", meta)


class ExportRenderFidelityTests(SimpleTestCase):
    """A row must never be silently reshaped on its way into an export.

    ``dict(zip(header, row))`` truncates to the shorter of the two, so a row
    with fewer values than headers would export as a record with fabricated
    empty fields, and a row with more would drop data without a trace. Either
    is a corrupted evidence artifact, which is precisely what P1-015/P1-016
    exist to prevent, so the mismatch is raised instead.
    """

    def test_json_export_round_trips_a_well_formed_row(self):
        from apps.monitoring.exports import render_json

        out = json.loads(render_json("x", ["a", "b"], [["1", "2"]]))
        self.assertEqual(out, [{"a": "1", "b": "2"}])

    def test_json_export_refuses_a_short_row_instead_of_zero_filling(self):
        from apps.monitoring.exports import render_json

        with self.assertRaises(ValueError) as ctx:
            render_json("x", ["a", "b", "c"], [["1"]])
        self.assertIn("3 headers", str(ctx.exception))

    def test_json_export_refuses_a_long_row_instead_of_dropping_values(self):
        from apps.monitoring.exports import render_json

        with self.assertRaises(ValueError):
            render_json("x", ["a"], [["1", "secret-leak"]])

    def test_txt_and_csv_renderers_do_not_pad_or_truncate(self):
        from apps.monitoring.exports import render_csv, render_txt

        # These render the row verbatim, so they must not raise on length drift.
        self.assertIn("1", render_txt("x", ["a", "b"], [["1"]]))
        self.assertIn("1", render_csv("x", ["a", "b"], [["1"]]))
