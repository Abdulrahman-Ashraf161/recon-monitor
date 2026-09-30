"""P1-007/P1-008: total CVE correlation coverage and idempotent synchronization.

P1-007: the old ``Technology.objects.all()[:2000]`` cap silently skipped every
        technology past the 2000th. Coverage must be total, in bounded batches.
P1-008: running the sync twice must not duplicate CVEs or events.
"""

import os
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.assets.models import CVE, Technology
from apps.events.models import Event
from apps.monitoring.models import CVESyncState
from apps.monitoring.tasks import sync_cve_database
from apps.targets.models import Target

# A bundled-KB product that actually matches, so candidates are created.
MATCHING_PRODUCT = "apache-log4j"


def _kb_patch():
    """A tiny deterministic KB so the test does not depend on the bundle."""
    kb = [
        {
            "product": MATCHING_PRODUCT,
            "affected_range": "<=2.14.1",
            "summary": "Log4Shell",
            "cve_id": "CVE-2021-44228",
        }
    ]
    return patch("services.cve_engine.matcher.BUNDLED_KB", kb)


class CveCoverageTests(TestCase):
    """P1-007: no global cap, bounded batches, total coverage."""

    @override_settings(CVE_CORRELATION_BATCH_SIZE=250)
    def test_more_than_2000_records_are_all_processed(self):
        target = Target.objects.create(
            name="cve.invalid",
            root_domain="cve.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        total = 2300  # deliberately above the old [:2000] cap
        Technology.objects.bulk_create(
            [
                Technology(
                    target=target,
                    asset_value=f"https://h{i}.cve.invalid",
                    product=f"p{i}",
                    version="1.0",
                )
                for i in range(total)
            ]
        )
        with _kb_patch(), patch("shutil.which", return_value=None):
            out = sync_cve_database()
        self.assertEqual(out["recorrelated"], total)
        self.assertEqual(out["failed"], 0)
        self.assertEqual(out["mode"], "full")
        # every technology is stamped as checked -- none silently skipped
        self.assertEqual(Technology.objects.filter(cve_checked_at__isnull=True).count(), 0)

    @override_settings(CVE_CORRELATION_BATCH_SIZE=100)
    def test_batching_walks_past_the_first_page(self):
        target = Target.objects.create(
            name="cve2.invalid",
            root_domain="cve2.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.bulk_create(
            [
                Technology(target=target, asset_value=f"https://h{i}.cve2.invalid", product=f"p{i}")
                for i in range(450)
            ]
        )
        with _kb_patch(), patch("shutil.which", return_value=None):
            out = sync_cve_database()
        self.assertEqual(out["batch_size"], 100)
        self.assertEqual(out["recorrelated"], 450)

    def test_candidates_are_created_for_matching_technologies(self):
        target = Target.objects.create(
            name="cve3.invalid",
            root_domain="cve3.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.create(
            target=target,
            asset_value="https://app.cve3.invalid",
            product=MATCHING_PRODUCT,
            version="2.14.1",
        )
        with _kb_patch(), patch("shutil.which", return_value=None):
            sync_cve_database()
        self.assertEqual(CVE.objects.filter(target=target).count(), 1)
        self.assertEqual(
            Event.objects.filter(target=target, event_type="NEW_CVE_CANDIDATE").count(), 1
        )

    def test_one_failing_technology_does_not_abort_the_sweep(self):
        target = Target.objects.create(
            name="cve4.invalid",
            root_domain="cve4.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.bulk_create(
            [
                Technology(target=target, asset_value=f"https://h{i}.cve4.invalid", product=f"p{i}")
                for i in range(10)
            ]
        )
        calls = {"n": 0}

        def flaky(tech, kb=None):
            calls["n"] += 1
            if tech.product == "p3":
                raise RuntimeError("boom")
            return True

        with (
            patch("services.correlation.ingest.correlate_cves_for_tech", side_effect=flaky),
            patch("shutil.which", return_value=None),
        ):  # no git: never touch the network
            out = sync_cve_database()
        self.assertEqual(out["failed"], 1)  # exactly the one bad row
        self.assertEqual(out["recorrelated"], 9)  # the other nine still ran
        self.assertEqual(calls["n"], 10)  # every row was attempted
        # (the stamp assertion lives in the real-correlation tests above; here the
        #  correlator is mocked out, so it deliberately writes nothing)


class CveIdempotencyTests(TestCase):
    """P1-008: repeated synchronization duplicates nothing."""

    def test_two_runs_create_no_duplicate_cves_or_events(self):
        target = Target.objects.create(
            name="cve5.invalid",
            root_domain="cve5.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.create(
            target=target,
            asset_value="https://app.cve5.invalid",
            product=MATCHING_PRODUCT,
            version="2.14.1",
        )
        with _kb_patch(), patch("shutil.which", return_value=None):
            first = sync_cve_database()
            second = sync_cve_database()
        self.assertEqual(first["recorrelated"], 1)
        # the second pass may be incremental (nothing changed -> nothing to redo)
        self.assertIn(second["mode"], ("full", "incremental"))
        self.assertLessEqual(second["recorrelated"], 1)
        # idempotency is the actual requirement: no duplicate rows, no dup events
        self.assertEqual(CVE.objects.filter(target=target).count(), 1)
        self.assertEqual(
            Event.objects.filter(target=target, event_type="NEW_CVE_CANDIDATE").count(), 1
        )

    def test_repeated_runs_with_full_sync_stay_idempotent(self):
        target = Target.objects.create(
            name="cve6.invalid",
            root_domain="cve6.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.create(
            target=target,
            asset_value="https://app.cve6.invalid",
            product=MATCHING_PRODUCT,
            version="2.14.1",
        )
        with _kb_patch(), patch("shutil.which", return_value=None):
            sync_cve_database()
            sync_cve_database(full_sync=True)
            sync_cve_database(full_sync=True)
        self.assertEqual(CVE.objects.filter(target=target).count(), 1)
        self.assertEqual(
            Event.objects.filter(target=target, event_type="NEW_CVE_CANDIDATE").count(), 1
        )


class IncrementalCorrelationTests(TestCase):
    """P1-007: prefer incremental re-correlation when the KB is unchanged."""

    def _state(self, count=12345):
        state, _ = CVESyncState.objects.get_or_create(source="cvelistV5")
        state.record_count = count
        # Derive the KB path from settings rather than hardcoding it: P3-005
        # moved the clone out of world-writable /tmp and under DATA_DIR, so a
        # literal here would silently stop matching the sync task.
        from django.conf import settings

        state.info = {
            "path": os.path.join(str(settings.DATA_DIR), "cvelistV5"),
            "count": count,
        }
        state.last_synced = timezone.now()
        state.save()
        return state

    def test_unchanged_kb_skips_already_checked_technologies(self):
        target = Target.objects.create(
            name="cve7.invalid",
            root_domain="cve7.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        old = Technology.objects.create(
            target=target, asset_value="https://a.cve7.invalid", product="old"
        )
        Technology.all_objects.filter(pk=old.pk).update(
            cve_checked_at=timezone.now() - timedelta(days=1)
        )
        self._state()
        with (
            _kb_patch(),
            patch("shutil.which", return_value="git"),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run"),
            patch("os.walk", return_value=[("cves", [], [f"c{i}.json" for i in range(12345)])]),
        ):
            out = sync_cve_database()
        self.assertTrue(out["kb_unchanged"])
        self.assertEqual(out["mode"], "incremental")
        self.assertEqual(out["recorrelated"], 0)  # the old one is skipped

    def test_new_technology_is_correlated_even_when_kb_unchanged(self):
        target = Target.objects.create(
            name="cve8.invalid",
            root_domain="cve8.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        Technology.objects.create(
            target=target, asset_value="https://new.cve8.invalid", product="brand-new"
        )
        self._state()
        with (
            _kb_patch(),
            patch("shutil.which", return_value="git"),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run"),
            patch("os.walk", return_value=[("cves", [], [f"c{i}.json" for i in range(12345)])]),
        ):
            out = sync_cve_database()
        self.assertTrue(out["kb_unchanged"])
        self.assertEqual(out["mode"], "incremental")
        self.assertEqual(out["recorrelated"], 1)

    def test_changed_kb_forces_a_full_pass(self):
        target = Target.objects.create(
            name="cve9.invalid",
            root_domain="cve9.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        old = Technology.objects.create(
            target=target, asset_value="https://a.cve9.invalid", product="old"
        )
        Technology.all_objects.filter(pk=old.pk).update(
            cve_checked_at=timezone.now() - timedelta(days=1)
        )
        self._state(count=111)
        # a sync that reports a different record count == the KB changed
        with (
            _kb_patch(),
            patch("shutil.which", return_value="git"),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run"),
            patch("os.walk", return_value=[("cves", [], [f"c{i}.json" for i in range(222)])]),
        ):
            out = sync_cve_database()
        self.assertFalse(out["kb_unchanged"])
        self.assertEqual(out["mode"], "full")
        self.assertEqual(out["recorrelated"], 1)
