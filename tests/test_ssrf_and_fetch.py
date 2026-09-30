"""P0-015/P0-016: every outbound fetch goes through the centralized TLS+SSRF layer.

The centralized layer lives in apps/jobs/tasks.py:

  _url_allowed_for_fetch  -> scope + hostname/IP validation + private/reserved
                             IP blocking + DNS-rebinding defense
  _ssl_context_for        -> TLS policy honoring target.verify_tls
  _safe_opener            -> adds per-hop redirect re-validation
  _fetch_url_for_recon    -> the safe fetch, used by the whole recon pipeline

P0-015 removed the two CERT_NONE JS fetches (recheck_javascript in
apps/monitoring/tasks.py and the DOWNLOAD stage in services/correlation/
jsanalysis.py); both now fetch through _fetch_url_for_recon and therefore honor
target.verify_tls. P0-016 pins the SSRF matrix: loopback, RFC1918, IPv6
loopback, link-local/metadata, out-of-scope, scheme rejection, DNS rebinding,
redirect-to-private-IP, redirect-out-of-scope, in-scope redirect followed, and
invalid TLS both with verification enabled and intentionally disabled.
"""

import http.server
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
import urllib.error
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from apps.jobs import tasks
from apps.scope.models import ScopeRule

from .fixtures import make_target


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    """Local echo server with three redirect targets."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        port = self.server.server_address[1]
        if self.path.startswith("/redirect-private"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/land")
            self.end_headers()
            return
        if self.path.startswith("/redirect-ooo"):
            self.send_response(302)
            self.send_header("Location", "http://out-of-scope.example.org/land")
            self.end_headers()
            return
        if self.path.startswith("/redirect-ok"):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/land")
            self.end_headers()
            return
        body = b"LAND"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LocalHttpServer:
    """Background http/https server on loopback with a random port."""

    def __init__(self, tls_cert=None):
        if tls_cert is None:
            self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
            self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()


def _self_signed_cert():
    """Cert whose identity (wronghost.invalid) never matches 127.0.0.1."""
    tmp = tempfile.mkdtemp(prefix="recon_tls_")
    cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=wronghost.invalid",
            "-addext",
            "subjectAltName=DNS:wronghost.invalid",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class UrlAllowedTests(TestCase):
    """P0-016 matrix against _url_allowed_for_fetch."""

    def setUp(self):
        self.t = make_target(authorization_expires_at=timezone.now() + timedelta(days=30))

    def _blocked(self, url, needle="block"):
        ok, reason, _host = tasks._url_allowed_for_fetch(self.t, url)
        self.assertFalse(ok, f"expected {url} to be refused, got allowed")
        self.assertIn(needle, reason.lower())

    def test_loopback_is_blocked(self):
        self._blocked(f"http://127.0.0.1/{secrets.token_hex(4)}")

    def test_rfc1918_private_is_blocked(self):
        for ip in ("10.0.0.8", "192.168.1.5", "172.16.0.2"):
            self._blocked(f"http://{ip}/x")

    def test_ipv6_loopback_is_blocked(self):
        self._blocked("http://[::1]/x")

    def test_link_local_metadata_ip_is_blocked(self):
        self._blocked("http://169.254.169.254/latest/meta-data/")

    def test_carrier_grade_nat_is_blocked(self):
        self._blocked("http://100.64.0.1/x")

    def test_out_of_scope_host_is_blocked(self):
        self._blocked("http://evil.example.org/x", needle="scope")

    def test_file_scheme_is_rejected(self):
        self._blocked("file:///etc/passwd", needle="scheme")

    def test_in_scope_subdomain_is_allowed(self):
        ok, reason, _host = tasks._url_allowed_for_fetch(self.t, f"http://a.{self.t.root_domain}/x")
        self.assertTrue(ok, reason)

    def test_dns_rebinding_defense_blocks_resolved_private_ip(self):
        # Explicit scope rule allows the hostname; the resolve-then-check gate
        # (defense-in-depth at connect time) still blocks a private resolution.
        ScopeRule.objects.create(
            target=self.t, rule_type=ScopeRule.RULE_ALLOW_DOMAIN, value="localhost"
        )
        with mock.patch(
            "services.scope_engine.validator.host_resolves_to_blocked",
            return_value=(True, "resolves to blocked IP 127.0.0.1"),
        ):
            ok, reason, _host = tasks._url_allowed_for_fetch(self.t, "http://localhost/x")
        self.assertFalse(ok)
        self.assertIn("blocked", reason.lower())


class RedirectValidationTests(TestCase):
    """P0-016: redirect hops are re-validated, not trusted on the first URL."""

    def setUp(self):
        self.server = _LocalHttpServer()
        self.addCleanup(self.server.close)
        self.t = make_target(authorization_expires_at=timezone.now() + timedelta(days=30))
        ScopeRule.objects.create(
            target=self.t, rule_type=ScopeRule.RULE_ALLOW_DOMAIN, value="localhost"
        )
        # Isolate the redirect re-validation: allow hostnames through the
        # resolve-then-check gate so only the per-hop scope/IP check is at stake.
        patcher = mock.patch(
            "services.scope_engine.validator.host_resolves_to_blocked", return_value=(False, "ok")
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _initial(self, path):
        return f"http://localhost:{self.server.port}/{path}"

    def test_redirect_to_private_ip_is_blocked(self):
        with self.assertRaises(tasks._ReconFetchSkipped) as ctx:
            tasks._fetch_url_for_recon(self.t, self._initial("redirect-private"), timeout=5)
        self.assertIn("redirect forbidden", str(ctx.exception))

    def test_redirect_out_of_scope_is_blocked(self):
        with self.assertRaises(tasks._ReconFetchSkipped) as ctx:
            tasks._fetch_url_for_recon(self.t, self._initial("redirect-ooo"), timeout=5)
        self.assertIn("redirect forbidden", str(ctx.exception))

    def test_redirect_in_scope_is_followed(self):
        body = tasks._fetch_url_for_recon(self.t, self._initial("redirect-ok"), timeout=5)
        self.assertEqual(body, b"LAND")


class TlsPolicyTests(TestCase):
    """P0-015: _ssl_context_for policy, no server needed."""

    def test_default_target_verifies_certificates(self):
        ctx = tasks._ssl_context_for(make_target())
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_intentional_opt_out_disables_only_that_target(self):
        ctx = tasks._ssl_context_for(make_target(verify_tls=False))
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)


class TlsHandshakeTests(TestCase):
    """Real handshakes against a self-signed (untrusted, wrong hostname) server."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._server = _LocalHttpServer(tls_cert=_self_signed_cert())
        cls.addClassCleanup(cls._server.close)

    def _fetch(self, verify_tls):
        target = make_target(verify_tls=verify_tls)
        url = f"https://127.0.0.1:{self._server.port}/"
        # SSRF gate is not the subject here; TLS is.
        with mock.patch(
            "apps.jobs.tasks._url_allowed_for_fetch", return_value=(True, "ok", "127.0.0.1")
        ):
            return tasks._fetch_url_for_recon(target, url, timeout=5)

    def test_invalid_tls_blocked_when_verification_enabled(self):
        with self.assertRaises(urllib.error.URLError) as ctx:
            self._fetch(verify_tls=True)
        self.assertIsInstance(ctx.exception.reason, ssl.SSLCertVerificationError)

    def test_invalid_tls_accepted_when_verification_intentionally_off(self):
        self.assertEqual(self._fetch(verify_tls=False), b"LAND")


class JsPathConsistencyTests(TestCase):
    """P0-015/P0-016: the JS recheck and JS-analysis fetch through the central layer."""

    def test_recheck_routes_through_central_fetch_and_shared_ingest(self):
        from apps.assets.models import JavaScriptAsset
        from apps.monitoring.tasks import recheck_javascript

        target = make_target()
        js = JavaScriptAsset.objects.create(
            target=target,
            js_url="https://cdn.example.org/app.js",
            host="cdn.example.org",
            sha256="0" * 64,
            size=4,
        )

        with mock.patch(
            "apps.jobs.tasks._fetch_url_for_recon", return_value=b"console.log('new');"
        ) as fetcher:
            out = recheck_javascript(target_id=target.pk)
            # First call is the recheck's own fetch; any further calls are the
            # eager JS_CHANGED analysis fan-out re-entering the same layer.
            self.assertEqual(
                fetcher.call_args_list[0], mock.call(target, js.js_url, stage="js-recheck")
            )

        self.assertEqual(out["changed"], 1)
        js.refresh_from_db()
        self.assertNotEqual(js.sha256, "0" * 64)

    def test_js_analysis_download_blocked_when_out_of_scope(self):
        from apps.assets.models import JavaScriptAsset
        from apps.jobs.models import JSAnalysisJob
        from services.correlation.jsanalysis import run_analysis

        target = make_target()
        js = JavaScriptAsset.objects.create(
            target=target,
            js_url="https://evil.example.org/x.js",
            host="evil.example.org",
            sha256="0" * 64,
            size=4,
        )
        job = JSAnalysisJob.objects.create(target=target, js=js, trigger="NEW_JS")

        status = run_analysis(job.pk)
        self.assertEqual(status, "FAILED")
        job.refresh_from_db()
        self.assertIn("download blocked", job.error)

    def test_js_analysis_download_respects_verify_tls(self):
        from apps.assets.models import JavaScriptAsset
        from apps.jobs.models import JSAnalysisJob
        from services.correlation.jsanalysis import run_analysis

        for verify_tls in (True, False):
            with mock.patch(
                "apps.jobs.tasks._url_allowed_for_fetch", return_value=(True, "ok", "127.0.0.1")
            ):
                target = make_target(verify_tls=verify_tls)
                js = JavaScriptAsset.objects.create(
                    target=target,
                    js_url=f"https://127.0.0.1:{self._server.port}/app.js",
                    host="127.0.0.1",
                    sha256="0" * 64,
                    size=4,
                )
                job = JSAnalysisJob.objects.create(target=target, js=js, trigger="manual")
                status = run_analysis(job.pk)
                job.refresh_from_db()
                if verify_tls:
                    self.assertEqual(status, "FAILED")
                    self.assertIn("download failed", job.error)
                else:
                    # Opt-in insecure: the fetch succeeds; the "background" JS
                    # analysis proceeds past the DOWNLOADING stage.
                    self.assertIn(status, ("PARTIAL", "COMPLETED", "FAILED"))
                    self.assertNotIn("download failed", job.error)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._server = _LocalHttpServer(tls_cert=_self_signed_cert())
        cls.addClassCleanup(cls._server.close)
