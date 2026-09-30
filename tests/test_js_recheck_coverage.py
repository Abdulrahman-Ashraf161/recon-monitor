"""P1-009: the JS recheck sweep must be batched, not truncated.

The old implementation stopped after the first 200 assets, so on a target with
more scripts the remainder was never rechecked and nothing recorded the
omission. Coverage must be total, in bounded batches.
"""

from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.assets.models import JavaScriptAsset
from apps.monitoring.tasks import recheck_javascript
from apps.targets.models import Target


def _target(name="js.invalid"):
    return Target.objects.create(
        name=name, root_domain=name, authorization_status=Target.AUTH_AUTHORIZED
    )


def _assets(target, count):
    JavaScriptAsset.objects.bulk_create(
        [
            JavaScriptAsset(
                target=target,
                js_url=f"https://cdn.{name}.invalid/{i}.js",
                host=f"cdn.{name}.invalid",
                sha256=f"{i:064d}",
                size=10,
            )
            for i, name in enumerate([target.root_domain] * count)
        ]
    )


class JsRecheckCoverageTests(TestCase):
    @override_settings(JS_RECHECK_BATCH_SIZE=50)
    def test_more_than_200_assets_are_all_processed(self):
        t = _target()
        total = 250  # deliberately above the old [:200] cap
        _assets(t, total)
        seen = []
        ingested = []

        def fake_fetch(target, url, **kw):
            seen.append(url)
            return b"var a=1;"

        def fake_ingest(target, url, body, source=None, **kw):
            ingested.append(url)
            return None, "NEW_JS"

        # both helpers are imported inside the task, so patch them where they live
        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", side_effect=fake_fetch),
            patch("services.correlation.ingest.ingest_js", side_effect=fake_ingest),
        ):
            out = recheck_javascript(t.id)
        self.assertEqual(len(ingested), total)
        self.assertEqual(out["scanned"], total)
        self.assertEqual(out["batch_size"], 50)
        self.assertEqual(len(seen), total)
        self.assertEqual(len(set(seen)), total)  # every distinct asset, once

    @override_settings(JS_RECHECK_BATCH_SIZE=25)
    def test_batching_crosses_page_boundaries(self):
        t = _target()
        _assets(t, 130)
        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", return_value=b"var a=1;"),
            patch("services.correlation.ingest.ingest_js", return_value=(None, "NEW_JS")),
        ):
            out = recheck_javascript(t.id)
        self.assertEqual(out["scanned"], 130)

    def test_single_failure_does_not_stop_the_sweep(self):
        t = _target()
        _assets(t, 20)
        calls = {"n": 0}

        def flaky(target, url, **kw):
            calls["n"] += 1
            if url.endswith("/3.js"):  # exactly one asset fails
                raise RuntimeError("boom")
            return b"var a=1;"

        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", side_effect=flaky),
            patch("services.correlation.ingest.ingest_js", return_value=(None, "NEW_JS")),
        ):
            out = recheck_javascript(t.id)
        self.assertEqual(out["failed"], 1)
        self.assertEqual(out["scanned"], 19)
        self.assertEqual(calls["n"], 20)

    def test_unscannable_target_assets_are_counted_not_silently_dropped(self):
        t = _target()
        _assets(t, 5)
        Target.all_objects.filter(pk=t.pk).update(status=Target.STATUS_PAUSED)
        t.refresh_from_db()
        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", return_value=b"x"),
            patch("services.correlation.ingest.ingest_js", return_value=(None, "NEW_JS")),
        ):
            out = recheck_javascript(t.id)
        self.assertEqual(out["not_scannable"], 5)
        self.assertEqual(out["scanned"], 0)

    def test_summary_reports_covered_and_skipped(self):
        t = _target()
        _assets(t, 3)
        from apps.jobs.tasks import _ReconFetchSkipped

        def mixed(target, url, **kw):
            if url.endswith("/1.js"):
                raise _ReconFetchSkipped("out of scope")
            return b"var a=1;"

        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", side_effect=mixed),
            patch("services.correlation.ingest.ingest_js", return_value=(None, "NEW_JS")),
        ):
            out = recheck_javascript(t.id)
        self.assertEqual(out["scanned"], 2)
        self.assertEqual(out["skipped"], 1)
        self.assertEqual(out["failed"], 0)

    def test_all_targets_swept_when_no_target_given(self):
        a, b = _target("a.invalid"), _target("b.invalid")
        _assets(a, 2)
        _assets(b, 2)
        with (
            patch("apps.jobs.tasks._fetch_url_for_recon", return_value=b"var a=1;"),
            patch("services.correlation.ingest.ingest_js", return_value=(None, "NEW_JS")),
        ):
            out = recheck_javascript()
        self.assertEqual(out["scanned"], 4)
