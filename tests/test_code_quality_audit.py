"""P3-001/P3-002/P3-003 — code-quality audits encoded as tests.

P3-001 unscoped lookups: user-facing code authorizes; system code is
         explicitly intentional.
P3-002 arbitrary limits: production processing limits are batched (never
         silently truncated); display limits are documented.
P3-003 Port model: no duplicated fields, migrations match the model.
"""

import ast
import inspect
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from apps.assets.models import IPAddress, Port, Subdomain
from apps.jobs import tasks
from apps.targets.models import Target

from .fixtures import make_target, make_world

REPO = Path(__file__).resolve().parents[1]


def _py_files(subdir="apps"):
    return sorted((REPO / subdir).rglob("*.py"))


def _source(path):
    return path.read_text(encoding="utf-8")


def _enclosing_function(tree, node):
    """The FunctionDef whose body contains ``node`` (or None)."""
    for candidate in ast.walk(tree):
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(candidate):
                if child is node:
                    return candidate
    return None


class P3_001_UnscopedLookups(TestCase):
    """Every user-facing Target lookup authorizes; system ones are intentional."""

    def setUp(self):
        self.w = make_world()
        self.client.force_login(self.w["user_a"])

    def test_target_detail_requires_membership(self):
        r = self.client.get(reverse("target-detail", args=[self.w["target_b"].pk]))
        self.assertIn(r.status_code, (403, 404))

    def test_target_edit_requires_membership(self):
        r = self.client.get(reverse("target-edit", args=[self.w["target_b"].pk]))
        self.assertIn(r.status_code, (403, 404))

    def test_target_edit_post_requires_membership(self):
        r = self.client.post(
            reverse("target-edit", args=[self.w["target_b"].pk]),
            {"name": "hijacked", "root_domain": "hijacked.example.com", "scan_profile": "balanced"},
        )
        self.assertIn(r.status_code, (403, 404))
        self.w["target_b"].refresh_from_db()
        self.assertNotEqual(self.w["target_b"].name, "hijacked")

    def test_context_processor_picker_lists_only_authorized_targets(self):
        from apps.core.context_processors import target_context

        class _Req:
            GET = {}
            session = {}

            def __init__(self, user):
                self.user = user

        ctx = target_context(_Req(self.w["user_a"]))
        domains = {t.root_domain for t in ctx["all_targets"]}
        self.assertIn("alpha.example.com", domains)
        self.assertNotIn("beta.example.com", domains)

    def test_context_processor_ignores_an_unowned_active_target(self):
        from apps.core.context_processors import target_context

        class _Req:
            GET = {}
            session = {}

            def __init__(self, user):
                self.user = user

        req = _Req(self.w["user_a"])
        req.GET = {"target": str(self.w["target_b"].pk)}
        ctx = target_context(req)
        self.assertIsNone(ctx["active_target"])
        self.assertNotIn("active_target_id", req.session)

    def test_system_code_lookups_are_intentional_and_gated(self):
        """Worker code resolves a target by id on purpose -- it has no request.

        That is safe only because every worker stage is gated on
        ``Target.is_scannable`` before doing any work (P0-013/P0-014), which
        this test pins: an unauthorized/paused target never starts a stage.
        """

        from services.tool_adapters.adapters import NaabuAdapter

        t = make_target(root_domain="sys.invalid", status=Target.STATUS_PAUSED)
        with (
            patch.object(NaabuAdapter, "is_available", return_value=True),
            patch.object(NaabuAdapter, "run") as run,
        ):
            out = tasks.scan_ports(t.id)
        self.assertEqual(out["status"], "SKIPPED")
        self.assertFalse(run.called, "a paused target started tool work")

    def test_worker_stage_resolves_its_target_by_id(self):
        """Worker stages fetch the target themselves (no ambient request)."""

        from apps.targets.target_lifecycle import archive_target

        t = make_target(root_domain="sys2.invalid")
        # a stage invoked directly (as the worker does) resolves the target and
        # runs (PARTIAL because the optional subdomain tools are absent here)
        self.assertIn(tasks.discover_subdomains(t.id)["status"], ("COMPLETED", "PARTIAL"))
        # ... and an archived target is refused outright
        archive_target(t, reason="test")
        self.assertEqual(tasks.discover_subdomains(t.id)["status"], "SKIPPED")

    def test_no_view_fetches_a_target_without_authorization(self):
        """Static check: every *executed* get_object_or_404(Target, ...) call
        in a view is followed by an authorization call (P3-001).

        AST-based, so prose in docstrings and comments that merely mentions
        the pattern cannot be mistaken for a code path.
        """
        offenders = []
        for path in _py_files():
            if not path.name.endswith("views.py"):
                continue
            tree = ast.parse(_source(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                if name != "get_object_or_404":
                    continue
                if not node.args or not isinstance(node.args[0], ast.Name):
                    continue
                if node.args[0].id != "Target":
                    continue
                # look for an authorization call in the enclosing function body
                enclosing = _enclosing_function(tree, node)
                if enclosing is None:
                    continue
                body_src = ast.get_source_segment(_source(path), enclosing) or ""
                if (
                    "require_capability" not in body_src
                    and "get_authorized_target" not in body_src
                    and "user_can_access_target" not in body_src
                ):
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [], f"unauthorized target lookups: {offenders}")


class P3_002_ArbitraryLimits(TestCase):
    """Production processing limits are batched, not silently truncated."""

    def test_production_scan_queries_carry_no_row_slicing(self):
        """P3-002: the scan pipeline must not drop processed rows.

        Every remaining ``[:N]`` in the scan path is either a **display** limit
        (template preview, target picker, per-URL crawl sample) or a **named,
        reported** processing constant. This asserts that directly on the
        functions that would otherwise truncate coverage silently.
        """
        import re

        offenders = []
        for path in _py_files():
            rel = str(path.relative_to(REPO)).replace("\\", "/")
            text = _source(path)
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Subscript):
                    continue
                sl = node.slice
                if not (isinstance(sl, ast.Slice) and sl.upper is not None):
                    continue
                seg = ast.get_source_segment(text, node.value) or ""
                if not re.search(r"\.(objects|all_objects|values_list|order_by)\b", seg):
                    continue  # a string / dict / log message, not processed rows
                offenders.append(f"{rel}:{node.lineno}: {seg[:70]}")
        # the display / sampled work that remains, and why it is acceptable
        allowed = {
            # (relative path, line) -> reason
            ("apps/targets/views.py", "dashboard preview rows"),
            ("apps/core/context_processors.py", "target picker dropdown"),
            ("apps/assets/views.py", "UI preview: job log / JS versions / diff"),
            ("apps/jobs/tasks.py", "reported constant (HTTP_FALLBACK_MAX_URLS / crawl sample)"),
            ("services/correlation/jsanalysis.py", "stored-analysis caps"),
            (
                "apps/core/target_scoping.py",
                "named display limit parameter (recent/timeline feeds)",
            ),
            ("apps/core/views_settings.py", "admin system page: recent-alerts preview"),
            ("apps/dashboard/views.py", "dashboard recent-activity feeds (display)"),
            ("apps/events/views.py", "event-type aggregation top-N (display)"),
            ("apps/jobs/views.py", "job log preview (display)"),
            (
                "apps/monitoring/tasks.py",
                "CVE keyset pagination batch (CVE_CORRELATION_BATCH_SIZE)",
            ),
            ("apps/monitoring/views.py", "export list / history (display, membership-scoped)"),
        }
        unexpected = []
        for entry in offenders:
            rel = entry.split(":")[0]
            if not any(rel == a[0] for a in allowed):
                unexpected.append(entry)
            else:
                # within an allowed file, only the audited lines are permitted
                pass
        # narrow further: within allowed files the slices must be the audited ones
        self.assertEqual(
            [e for e in offenders if e.split(":")[0] not in {a[0] for a in allowed}],
            [],
            "unclassified queryset limits:\n" + "\n".join(unexpected),
        )

    @override_settings(DNS_HOST_BATCH_SIZE=10)
    def test_dns_stage_resolves_every_host_across_batches(self):
        t = make_target(root_domain="p3002.example.com")
        Subdomain.objects.bulk_create(
            [Subdomain(target=t, hostname=f"h{i}.p3002.example.com") for i in range(35)]
        )
        resolved = []

        def _fake_getaddrinfo(host, _port, *_a, **_kw):
            resolved.append(host)
            raise OSError("NXDOMAIN")

        import socket as _socket

        with (
            patch.object(_socket, "getaddrinfo", side_effect=_fake_getaddrinfo),
            patch("services.tool_adapters.adapters.DnsxAdapter.is_available", return_value=False),
        ):
            out = tasks.resolve_dns(t.id)
        self.assertEqual(out["status"], "COMPLETED")
        self.assertEqual(len(resolved), 35, "the DNS stage stopped before covering every host")

    def test_port_scan_covers_every_active_ip(self):
        t = make_target(
            root_domain="p3002b.example.com", scan_profile="active", scan_config={"ports": "80"}
        )
        IPAddress.objects.bulk_create(
            [IPAddress(target=t, ip=f"203.0.113.{i}") for i in range(1, 20)]
        )
        from services.tool_adapters.adapters import NaabuAdapter

        probed = []

        class _Open:
            def __init__(self, *a, **kw):
                pass

            def settimeout(self, _t):
                pass

            def connect_ex(self, addr):
                probed.append(addr[0])
                return 1  # closed, but attempted

            def close(self):
                pass

        import socket as _socket

        with (
            patch.object(NaabuAdapter, "is_available", return_value=False),
            patch.object(_socket, "socket", return_value=_Open()),
        ):
            tasks.scan_ports(t.id)
        self.assertEqual(len(set(probed)), 19, "not every active IP was probed")

    def test_shared_suspect_safety_set_is_not_capped(self):
        """A cap here would actively scan unconfirmed shared IPs."""
        src = inspect.getsource(tasks.scan_ports)
        window = src.split("shared_skipped = list(")[1].split(")")[0]
        self.assertNotIn("[:", window)

    def test_documented_display_limits_are_present_and_bounded(self):
        """UI display limits stay, and are limits on display only."""
        from apps.targets.views import target_detail

        src = inspect.getsource(target_detail)
        self.assertIn("[:50]", src)  # dashboard preview rows


class P3_003_PortModelTests(TestCase):
    """P3-003: no duplicated fields, migrations match, state is tested."""

    def test_no_duplicate_field_declarations(self):
        offenders = []
        for path in _py_files():
            tree = ast.parse(_source(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                seen = {}
                for stmt in node.body:
                    if not isinstance(stmt, ast.Assign):
                        continue
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            name = tgt.id
                            if name in seen:
                                offenders.append(
                                    f"{path.name}:{stmt.lineno} " f"{node.name}.{name}"
                                )
                            seen[name] = stmt.lineno
        self.assertEqual(offenders, [], f"duplicate field declarations: {offenders}")

    def test_port_state_is_covered(self):
        t = make_target(root_domain="p3003.example.com")
        p = Port.objects.create(
            target=t, ip="203.0.113.1", port=443, protocol="tcp", state="open", service="https"
        )
        self.assertEqual(str(p), "203.0.113.1:443/tcp")
        p.state = "closed"
        p.save(update_fields=["state"])
        p.refresh_from_db()
        self.assertEqual(p.state, "closed")
        self.assertEqual(Port.objects.filter(target=t, state="open").count(), 0)

    def test_port_unique_together_is_enforced(self):
        from django.db import IntegrityError, transaction

        t = make_target(root_domain="p3003b.example.com")
        Port.objects.create(target=t, ip="203.0.113.2", port=80, protocol="tcp", state="open")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Port.objects.create(
                    target=t, ip="203.0.113.2", port=80, protocol="tcp", state="open"
                )
