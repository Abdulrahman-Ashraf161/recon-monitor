"""Deployment-artifact tests (P3-007 / FINAL-005 / FINAL-006).

These assert properties of the shipped deployment surface that unit tests of
application code cannot reach: the compose file, the Dockerfile, the
``.dockerignore`` and the documented settings module. Each of these was a real
defect found while standing up the production stack:

* ``docker-compose.yml`` set ``DJANGO_SETTINGS_MODULE: production``, a value
  that is *not* importable (``ModuleNotFoundError: No module named
  'production'``), so every container in the documented deployment failed to
  start. The correct value is the dotted path ``config.settings.production``.
* there was no ``.dockerignore``, so ``COPY . .`` baked the developer's
  virtualenv, SQLite database, generated evidence, VCS history and -- worst of
  all -- the real ``.env`` secret file into the production image.

Both are silent failures: the app boots perfectly on a developer machine and
only breaks in the image, which is exactly why they are pinned by tests.
"""

import ast
import re
from pathlib import Path

from django.test import SimpleTestCase

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker" / "docker-compose.yml"
DOCKERFILE = REPO / "docker" / "Dockerfile"
DOCKERIGNORE = REPO / ".dockerignore"
ASGI = REPO / "config" / "asgi.py"

SERVICES = ("web", "worker", "beat", "db", "redis")


def _compose_text():
    return COMPOSE.read_text(encoding="utf-8")


def _parse_settings_modules():
    """Return the DJANGO_SETTINGS_MODULE value for every app service.

    Parsed with a small indentation walk so the assertions do not depend on a
    YAML library being installed in the runtime image (tests are not shipped to
    the image anyway, but this keeps the check dependency-free).
    """
    found = {}
    current = None
    for raw in _compose_text().splitlines():
        line = raw.strip()
        m = re.match(r"^([a-z][a-z0-9_-]*):\s*$", line)
        if m and not raw.startswith(" " * 6):
            current = m.group(1)
        m = re.match(r"^DJANGO_SETTINGS_MODULE:\s*(\S+)\s*$", line)
        if m:
            found[current] = m.group(1)
    return found


class DeploymentArtifactTests(SimpleTestCase):
    def test_compose_file_exists_and_declares_every_service(self):
        self.assertTrue(COMPOSE.is_file(), "docker/docker-compose.yml is missing")
        text = _compose_text()
        for svc in SERVICES:
            with self.subTest(service=svc):
                self.assertRegex(text, rf"(?m)^\s{{2}}{svc}:", f"{svc} service not declared")

    def test_compose_settings_module_is_the_dotted_importable_path(self):
        """Regression: `production` is not an importable module."""
        found = _parse_settings_modules()
        self.assertTrue(found, "no DJANGO_SETTINGS_MODULE found in the compose file")
        for svc, value in found.items():
            with self.subTest(service=svc):
                self.assertEqual(
                    value,
                    "config.settings.production",
                    f"service {svc!r} must use the dotted settings path; "
                    f"{value!r} raises ModuleNotFoundError at container start",
                )

    def test_settings_module_target_actually_exists(self):
        module = "config.settings.production"
        path = REPO.joinpath(*module.split(".")).with_suffix(".py")
        self.assertTrue(path.is_file(), f"{module} does not exist at {path}")
        source = path.read_text(encoding="utf-8")
        ast.parse(source)  # must at least be syntactically valid

    def test_asgi_does_not_hardcode_settings(self):
        """ASGI must honour the environment, not pin a settings module.

        ``os.environ.setdefault`` is acceptable (it only fills a gap) but a bare
        ``os.environ[...] =`` would silently override the deployment's choice.
        """
        source = ASGI.read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn("setdefault", source, "config/asgi.py should use setdefault")
        self.assertNotRegex(
            source,
            r"os\.environ\[",
            "config/asgi.py assigns DJANGO_SETTINGS_MODULE directly, overriding the environment",
        )

    def test_dockerignore_exists(self):
        self.assertTrue(
            DOCKERIGNORE.is_file(),
            "no .dockerignore: `COPY . .` would bake .venv, data/, db.sqlite3, "
            ".git and the real .env into the production image",
        )

    def test_dockerignore_excludes_secrets_and_bulk(self):
        patterns = {
            line.strip()
            for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        for required in (".env", ".venv/", "data/", ".git/", "db.sqlite3", "__pycache__/"):
            with self.subTest(pattern=required):
                self.assertIn(
                    required,
                    patterns,
                    f".dockerignore must exclude {required!r}",
                )

    def test_dockerignore_re_admits_only_the_example_env(self):
        """`.env` must be excluded but `.env.example` must stay available."""
        patterns = DOCKERIGNORE.read_text(encoding="utf-8")
        self.assertRegex(patterns, r"(?m)^\.env$", "must exclude the real .env")
        self.assertRegex(patterns, r"(?m)^!\.env\.example$", "must re-admit .env.example")

    def test_dockerignore_cannot_be_neutralised_by_a_later_rule(self):
        """A later `.env*` style rule must not re-include the real .env.

        dockerignore is last-match-wins, so a broad pattern placed after the
        negation would silently restore the secret. Assert the broad pattern
        does not appear after the `!.env.example` negation.
        """
        lines = [raw.strip() for raw in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()]
        neg = lines.index("!.env.example")
        for later in lines[neg + 1 :]:
            if later.startswith("!"):
                continue
            with self.subTest(rule=later):
                self.assertNotIn(
                    ".env",
                    later.replace("!.env.example", ""),
                    f"rule {later!r} appears after `!.env.example` and could "
                    f"re-include the real .env (last match wins)",
                )

    def test_dockerfile_copies_requirements_before_source(self):
        """Layered build: deps installed before `COPY . .` for layer caching."""
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("COPY requirements.lock.txt requirements.txt ./", text)
        self.assertLess(
            text.index("COPY requirements.lock.txt"),
            text.index("COPY . ."),
            "requirements must be copied/installed before the source layer",
        )

    def test_dockerfile_runs_daphne_asgi(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("config.asgi:application", text, "must serve the ASGI app (websockets)")

    def _git_ls_files(self, *args):
        """Run `git ls-files` without a shell, and skip if git is unavailable."""
        import shutil
        import subprocess

        git = shutil.which("git")
        if not git:
            self.skipTest("git unavailable")
        return subprocess.run(
            [git, "ls-files", *args], cwd=REPO, capture_output=True, text=True, check=False
        ).stdout.strip()

    def test_repo_env_file_is_not_committed(self):
        """A real .env must never be tracked in git."""
        out = self._git_ls_files("--error-unmatch", ".env")
        self.assertEqual(out, "", "a real .env is tracked in git")

    def test_example_env_is_tracked(self):
        out = self._git_ls_files(".env.example")
        self.assertTrue(
            (REPO / ".env.example").is_file() or out,
            "an .env.example must exist so operators know which vars to set",
        )


class ToolingConfigTests(SimpleTestCase):
    """The linters were previously unconfigured, so every tool ran on defaults.

    Without config, ruff/flake8/mypy reported Django-idiomatic code as errors
    (mutable class defaults, the `from .base import *` settings idiom, untyped
    model fields) and the real findings were buried in the noise. These tests
    pin the existence and the *intent* of each config, and assert the
    actionable rules stay enabled -- a config that silences everything would
    make a future regression invisible.
    """

    RUFF = REPO / "ruff.toml"
    FLAKE8 = REPO / ".flake8"
    MYPY = REPO / "mypy.ini"

    def test_all_three_tool_configs_exist(self):
        for path in (self.RUFF, self.FLAKE8, self.MYPY):
            with self.subTest(config=path.name):
                self.assertTrue(path.is_file(), f"{path.name} is missing")

    def test_ruff_keeps_the_actionable_rules_enabled(self):
        source = self.RUFF.read_text(encoding="utf-8")
        # The global ignore block is everything before the per-file section.
        global_ignores = source.split("[lint.per-file-ignores]")[0]
        # These catch real defects and must never be ignored repo-wide.
        for rule in ("F601", "B023", "RUF100"):
            with self.subTest(rule=rule):
                self.assertNotIn(f'"{rule}"', global_ignores, f"{rule} must stay enabled")
        # B017 is only exempt under tests/, where assertRaises(Exception) is
        # normal in negative-path assertions.
        self.assertNotIn('"B017"', global_ignores)
        # F401/F841 likewise only under tests/ (unused locals, deliberate
        # importability checks).
        for rule in ("F401", "F841"):
            with self.subTest(rule=rule):
                self.assertNotIn(f'"{rule}"', global_ignores)

    def test_ruff_ignores_are_justified_in_the_config(self):
        source = self.RUFF.read_text(encoding="utf-8")
        for rule in ("RUF012", "S603", "B008"):
            with self.subTest(rule=rule):
                self.assertIn(f'"{rule}"', source)
        # Each ignore block must carry a comment explaining why, so a future
        # reader does not "clean it up" and unmask the noise.
        for keyword in ("Django", "generated"):
            with self.subTest(reason=keyword):
                self.assertIn(keyword, source)

    def test_ruff_excludes_generated_migrations(self):
        source = self.RUFF.read_text(encoding="utf-8")
        self.assertIn("migrations", source)
        self.assertIn('"**/migrations/*.py" = ["ALL"]', source)

    def test_flake8_agrees_with_ruff_on_line_length(self):
        ruff = self.RUFF.read_text(encoding="utf-8")
        flake8 = self.FLAKE8.read_text(encoding="utf-8")
        ruff_len = re.search(r"line-length\s*=\s*(\d+)", ruff).group(1)
        flake8_len = re.search(r"max-line-length\s*=\s*(\d+)", flake8).group(1)
        self.assertEqual(
            ruff_len,
            flake8_len,
            "ruff and flake8 disagree on max line length, so they will report "
            "contradictory results on the same file",
        )

    def test_mypy_does_not_ignore_the_whole_application(self):
        source = self.MYPY.read_text(encoding="utf-8")
        # tests/ and settings/ may be ignored; the application packages must not.
        for section in ("[mypy-tests.*]", "[mypy-config.settings.*]"):
            self.assertIn(section, source)
        for app in ("[mypy-apps.assets.models]", "[mypy-apps.core.api]"):
            self.assertIn(app, source)
        # A blanket ignore would defeat the purpose.
        self.assertNotIn("ignore_errors = True\n\n[mypy-apps", source)

    def test_tool_configs_do_not_suppress_the_ssrf_or_auth_modules(self):
        # The security-critical modules must be fully linted. Exempting
        # apps/jobs/tasks.py (the SSRF fetch layer) or the authorization and
        # scope modules would hide a real regression.
        for path in (self.RUFF, self.FLAKE8):
            source = path.read_text(encoding="utf-8")
            for guarded in ("jobs/tasks", "core/authorization", "scope_engine"):
                with self.subTest(config=path.name, module=guarded):
                    self.assertNotIn(guarded, source, f"{path.name} must not exempt {guarded}")
        mypy = self.MYPY.read_text(encoding="utf-8")
        # No blanket-ignore for the SSRF layer or the authorization modules.
        for module in (
            "apps.jobs.tasks",
            "apps.core.authorization",
            "services.scope_engine",
            "apps.core.target_scoping",
        ):
            with self.subTest(module=module):
                self.assertNotIn(
                    f"[mypy-{module}]", mypy, f"{module} must be type-checked, not exempted"
                )
        # A blanket `ignore_errors` for an app package would hide real findings.
        app_sections = re.findall(r"(?ms)^\[mypy-(apps\.[^\]]+)\]\n(.*?)(?=^\[|\Z)", mypy)
        for section, body in app_sections:
            with self.subTest(section=section):
                self.assertNotIn(
                    "ignore_errors = True",
                    body,
                    f"{section} uses ignore_errors; the application must be checked",
                )


class DocumentationCurrencyTests(SimpleTestCase):
    """P3-004, P3-006, FINAL-002: docs must match the implementation.

    These three tasks were the only ones with no automated coverage, which is
    exactly how a stale URL or a drifted architecture document can survive a
    remediation pass. They are documentation contracts, so they are asserted
    like any other.
    """

    REPO_URL = "https://github.com/Abdulrahman-Ashraf161/recon-monitor"
    STALE_MARKERS = ("github.com/Abdulrahman-Ashraf161/recon-monitor",)
    DOCS = ("README.md", "docs/architecture.md", "docs/setup.md", "docs/deployment.md")

    def _doc(self, rel):
        return (REPO / rel).read_text(encoding="utf-8")

    def test_p3_004_canonical_repository_url_is_present(self):
        for rel in ("README.md", "docs/setup.md"):
            with self.subTest(doc=rel):
                self.assertIn(
                    self.REPO_URL, self._doc(rel), f"{rel} must point at the canonical repository"
                )

    def test_p3_004_no_unknown_repository_urls_in_shipped_docs(self):
        """Any github.com URL in shipped docs must be the canonical one.

        The old bug was a stale repository URL; the generic check is that no
        *other* recon-monitor repository URL is referenced anywhere shipped.
        """
        import re

        for rel in self.DOCS:
            body = self._doc(rel)
            for url in set(re.findall(r"https://github\.com/[\w.-]+/[\w.-]+", body)):
                # `git clone` URLs legitimately carry a `.git` suffix.
                normalised = url.rstrip("/").removesuffix(".git")
                with self.subTest(doc=rel, url=url):
                    self.assertEqual(
                        normalised,
                        self.REPO_URL,
                        f"{rel} references an unexpected repository URL",
                    )

    def test_p3_006_architecture_documents_the_current_invariants(self):
        body = self._doc("docs/architecture.md")
        for concept, why in (
            ("ScanRun", "canonical execution root"),
            ("membership", "target-level authorization model"),
            ("heartbeat", "liveness / stall detection"),
            ("reconcil", "removal safety"),
        ):
            with self.subTest(concept=concept):
                self.assertIn(concept, body, f"ARCHITECTURE.md must document {why} ({concept})")

    def test_p3_006_architecture_documents_the_membership_role_model(self):
        body = self._doc("docs/architecture.md")
        for role in ("OWNER", "OPERATOR", "VIEWER"):
            with self.subTest(role=role):
                self.assertIn(role, body)

    def test_final_002_docs_do_not_describe_removed_behaviour(self):
        """FINAL-002: no doc may claim a behaviour the code removed.

        ``ScanJob.run_id`` was replaced by a real ScanRun FK, so a doc that
        still documents a free-form run id would be stale by definition.
        """
        for rel in self.DOCS:
            body = self._doc(rel)
            with self.subTest(doc=rel):
                self.assertNotRegex(
                    body,
                    r"ScanJob\.run_id(?!.*legacy)",
                    f"{rel} still documents the removed ScanJob.run_id field",
                )
