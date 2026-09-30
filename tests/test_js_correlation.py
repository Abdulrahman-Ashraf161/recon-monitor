"""P2-003: JS semantic diff correlation (add *and* remove) with correct parents.

A JS_CHANGED parent must be accompanied by one child event per semantic delta --
route added/removed, library added/removed, secret candidate added/removed --
each carrying the right parent event, target, correlation id and ScanRun.
"""

from django.test import TestCase

from apps.assets.models import JavaScriptAsset, JavaScriptFinding
from apps.core.execution_context import ScanContext, scan_context
from apps.events.models import Event
from apps.jobs.models import ScanRun
from apps.targets.models import Target
from services.correlation.ingest import ingest_js

URL = "https://cdn.invalid/app.js"

V1 = b"""
fetch("/api/v1/users");
fetch("/api/v1/orders");
var React = 1; var lodash = 1;
var key = "AKIAIOSFODNN7EXAMPLE";
"""

V2 = b"""
fetch("/api/v1/users");
fetch("/api/v1/orders/new");
var React = 1;
var key = "AKIAIOSFODNN7EXAMPLE";
var other = "AKIAIOSFODNN7EXAMPLZ";
"""


def _target():
    return Target.objects.create(
        name="jsd.invalid", root_domain="jsd.invalid", authorization_status=Target.AUTH_AUTHORIZED
    )


def _events(target, event_type):
    return list(Event.objects.filter(target=target, event_type=event_type))


class SemanticDeltaTests(TestCase):
    def setUp(self):
        self.t = _target()
        ingest_js(self.t, URL, V1, source="test")

    def test_added_route_emits_child(self):
        ingest_js(self.t, URL, V2, source="test")
        added = _events(self.t, "NEW_JS_ENDPOINT")
        self.assertTrue(any("/api/v1/orders/new" in e.asset_value for e in added))
        removed = _events(self.t, "JS_ENDPOINT_REMOVED")
        self.assertTrue(any("/api/v1/orders" in e.asset_value for e in removed))

    def test_removed_route_is_reported(self):
        # store a first version that has an extra route, then re-ingest the
        # narrower body: the extra route disappears and must be reported.
        ingest_js(self.t, URL, b'fetch("/api/v1/users");\nfetch("/api/v1/ghost");', source="test")
        ingest_js(self.t, URL, V1, source="test")
        removed = _events(self.t, "JS_ENDPOINT_REMOVED")
        self.assertTrue(
            any("/api/v1/ghost" in e.asset_value for e in removed),
            f"ghost route removal not reported: {[e.asset_value for e in removed]}",
        )

    def test_library_removed_is_reported(self):
        ingest_js(self.t, URL, b'fetch("/api/v1/users");var jquery=1;', source="test")
        ingest_js(self.t, URL, V1, source="test")  # v1 has react+lodash, no jquery
        removed = _events(self.t, "JS_LIBRARY_REMOVED")
        self.assertTrue(
            any("jquery" in e.asset_value for e in removed),
            f"jquery removal not reported: {[e.asset_value for e in removed]}",
        )

    def test_rotated_secret_is_reported_as_add_and_remove(self):
        """A replaced credential of the same type is a real semantic change."""
        ingest_js(self.t, URL, b'var a="AKIAIOSFODNN7EXAMPLE";', source="test")
        ingest_js(self.t, URL, b'var a="AKIAIOSFODNN7EXAMPLZ";', source="test")
        added = _events(self.t, "NEW_JS_SECRET_CANDIDATE")
        removed = _events(self.t, "JS_SECRET_CANDIDATE_REMOVED")
        self.assertTrue(
            any(e.evidence.get("rotated") for e in added),
            "rotation not flagged on the new candidate",
        )
        self.assertTrue(removed, "the rotated-away credential was not reported")

    def test_secret_candidate_added_and_removed(self):
        ingest_js(self.t, URL, V2, source="test")
        added = _events(self.t, "NEW_JS_SECRET_CANDIDATE")
        self.assertTrue(added)
        # now remove every secret
        ingest_js(self.t, URL, b"fetch('/api/v1/users'); var React=1;", source="test")
        removed = _events(self.t, "JS_SECRET_CANDIDATE_REMOVED")
        self.assertTrue(removed)

    def test_children_carry_parent_correlation_and_target(self):
        ingest_js(self.t, URL, V2, source="test")
        parent = Event.objects.get(target=self.t, event_type="JS_CHANGED")
        self.assertTrue(parent.correlation_id)
        children = Event.objects.filter(target=self.t, parent_event=parent)
        self.assertTrue(children.exists(), "no child events linked to the parent")
        for child in children:
            self.assertEqual(child.target_id, self.t.pk)
            self.assertEqual(child.correlation_id, parent.correlation_id)
            self.assertEqual(child.asset_type, "JS_FILE")

    def test_children_carry_the_scan_run(self):
        run = ScanRun.objects.create(target=self.t, scan_type="DISCOVERY", trigger="test")
        with scan_context(ScanContext(target_id=self.t.pk, scan_run=run)):
            ingest_js(self.t, URL, V2, source="test")
        parent = Event.objects.get(target=self.t, event_type="JS_CHANGED")
        self.assertEqual(parent.scan_run_id, run.pk)
        for child in Event.objects.filter(target=self.t, parent_event=parent):
            self.assertEqual(child.scan_run_id, run.pk)

    def test_parent_event_summarises_the_delta(self):
        ingest_js(self.t, URL, V2, source="test")
        parent = Event.objects.get(target=self.t, event_type="JS_CHANGED")
        delta = parent.evidence["semantic_delta"]
        self.assertEqual(delta["endpoints_added"], 1)  # /api/v1/orders/new
        self.assertEqual(delta["endpoints_removed"], 1)  # /api/v1/orders
        self.assertEqual(delta["libraries_removed"], 1)  # lodash
        # V1 -> V2 adds a *second* AWS key (the original stays), so this is an
        # addition only; a genuine removal/rotation is asserted separately below.
        self.assertEqual(delta["secrets_added"], 1)
        self.assertEqual(delta["secrets_removed"], 0)

    def test_unchanged_content_emits_no_children(self):
        _js, outcome = ingest_js(self.t, URL, V1, source="test")
        self.assertEqual(outcome, "UNCHANGED")
        self.assertEqual(len(_events(self.t, "JS_CHANGED")), 0)
        self.assertEqual(len(_events(self.t, "NEW_JS_ENDPOINT")), 0)
        self.assertEqual(len(_events(self.t, "JS_ENDPOINT_REMOVED")), 0)

    def test_findings_are_persisted_for_removed_secret(self):
        before = JavaScriptFinding.all_objects.filter(
            js=JavaScriptAsset.objects.get(target=self.t, js_url=URL)
        ).count()
        self.assertGreater(before, 0)
        ingest_js(self.t, URL, b"var nothing=1;", source="test")
        # findings are historical evidence of what was seen, so they remain
        after = JavaScriptFinding.all_objects.filter(
            js=JavaScriptAsset.objects.get(target=self.t, js_url=URL)
        ).count()
        self.assertEqual(after, before)
        self.assertTrue(_events(self.t, "JS_SECRET_CANDIDATE_REMOVED"))

    def test_target_isolation_of_children(self):
        other = Target.objects.create(
            name="jsx.invalid",
            root_domain="jsx.invalid",
            authorization_status=Target.AUTH_AUTHORIZED,
        )
        ingest_js(other, "https://cdn.invalid/other.js", b'fetch("/other");', source="test")
        ingest_js(self.t, URL, V2, source="test")
        # the other target has its own parent only
        for ev in Event.objects.filter(
            target=other,
            event_type__in=["NEW_JS_ENDPOINT", "JS_ENDPOINT_REMOVED", "NEW_JS_LIBRARY"],
        ):
            self.assertEqual(ev.target_id, other.pk)
        self.assertFalse(
            Event.objects.filter(target=self.t, asset_value__contains="other.js").exists()
        )
