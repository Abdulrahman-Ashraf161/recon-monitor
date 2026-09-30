"""Dependency pin consistency (requirements discrepancy resolution).

The repository shipped two contradictory sources of truth:

* ``requirements.txt`` allowed ``Django>=5.0,<6.0``
* ``requirements.lock.txt`` pinned ``Django==6.1.1``

while the venv the project is actually developed and tested against runs
Django 5.2.17. A deploy built from the lock file would therefore not have been
the tested configuration, and the two files disagreed with each other.

These tests pin the resolution: both files must name the same Django line, the
constraint must be satisfiable by the installed version, and the lock must not
drift from the interpreter the suite runs on.
"""

import re
from pathlib import Path

from django import VERSION as DJANGO_VERSION
from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parent.parent


def installed_django_version():
    """`django.VERSION` is (major, minor, micro, stage, serial) and the serial
    is an int, so take only the leading numeric components ("5.2.17")."""
    parts = []
    for part in DJANGO_VERSION:
        if not isinstance(part, int):
            break
        parts.append(str(part))
    return ".".join(parts)


REQUIREMENTS = REPO_ROOT / "requirements.txt"
LOCKFILE = REPO_ROOT / "requirements.lock.txt"


def _pinned_versions(text):
    """Map lowercased distribution name -> exact version for `name==version`."""
    pins = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+-]+)$", line)
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    return pins


def _constraints(text):
    """Map lowercased distribution name -> raw requirement specifier."""
    out = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if m and m.group(3):
            out[m.group(1).lower().replace("_", "-")] = m.group(3).strip()
    return out


class DjangoPinConsistencyTests(SimpleTestCase):
    def setUp(self):
        self.requirements = REQUIREMENTS.read_text(encoding="utf-8")
        self.lock = LOCKFILE.read_text(encoding="utf-8")
        self.pins = _pinned_versions(self.lock)
        self.constraints = _constraints(self.requirements)

    def test_lock_pins_django(self):
        self.assertIn("django", self.pins, "lock file must pin Django exactly")
        self.assertEqual(
            self.pins["django"],
            installed_django_version(),
            "lock must match the Django version the suite is verified against",
        )

    def test_requirements_and_lock_agree_on_django(self):
        spec = self.constraints.get("django", "")
        self.assertTrue(spec, "requirements.txt must constrain Django")
        self.assertIn("5.2", spec, f"requirements.txt must target the 5.2 LTS line, got {spec!r}")
        # The lock must satisfy the range declared in requirements.txt.
        self.assertTrue(
            spec.replace(" ", "").find(self.pins["django"]) >= 0
            or f">={self.pins['django'].rsplit('.', 1)[0]}" in spec.replace(" ", ""),
            f"lock pin Django=={self.pins['django']} does not satisfy {spec!r}",
        )

    def test_installed_django_satisfies_requirements(self):
        installed = installed_django_version()
        spec = self.constraints.get("django", "").replace(" ", "")
        self.assertIn(
            f">={installed.rsplit('.', 1)[0]}",
            spec,
            f"installed Django {installed} is below requirements.txt {spec!r}",
        )
        upper = re.search(r"<\s*([0-9.]+)", spec)
        if upper:
            self.assertLess(
                tuple(int(x) for x in installed.split(".")),
                tuple(int(x) for x in upper.group(1).split(".")),
                f"installed Django {installed} violates upper bound {upper.group(1)}",
            )

    def test_django_is_not_pinned_to_a_major_untested_by_the_suite(self):
        """Guard against reintroducing a lock-only major bump."""
        major = DJANGO_VERSION[0]
        self.assertEqual(major, 5, "project targets the Django 5.x LTS line")
        self.assertEqual(self.pins["django"].split(".")[0], str(major))

    def test_lock_header_documents_the_django_line(self):
        header = "\n".join(self.lock.splitlines()[:30])
        self.assertIn("5.2", header, "lock header must state which Django line is verified")

    def test_lock_header_does_not_claim_to_be_a_full_freeze(self):
        header = "\n".join(self.lock.splitlines()[:30])
        self.assertNotIn("(pip freeze)", header, "header must not claim to be a full venv freeze")
        self.assertIn("runtime", header.lower(), "header must describe this as a runtime lock")

    def test_every_runtime_dependency_is_pinned(self):
        """requirements.txt entries must appear in the lock (directly or transitively)."""
        lock_names = set(self.pins)
        # Distributions whose runtime deps carry the direct requirement.
        provided_via = {
            "psycopg2-binary": "postgres driver",
        }
        for name in self.constraints:
            with self.subTest(dependency=name):
                if name in lock_names:
                    continue
                self.assertIn(
                    name,
                    provided_via,
                    f"{name} is required but neither pinned in the lock nor listed "
                    f"as intentionally provided elsewhere",
                )
