"""Base adapter: validate input -> build command -> execute -> capture -> parse -> normalize."""
import hashlib
import shutil
import subprocess

DEFAULT_TIMEOUT = 300


class AdapterResult:
    def __init__(self, tool, status="COMPLETED", data=None, raw="", error="", duration_ms=0):
        self.tool = tool
        self.status = status  # COMPLETED/FAILED/PARTIAL/SKIPPED
        self.data = data or []
        self.raw = raw
        self.error = error
        self.duration_ms = duration_ms


class BaseAdapter:
    tool_name = "base"
    binary = ""

    def resolved_binary(self):
        """T25: prefer explicit TOOL_BIN_DIR pinning; fall back to PATH.

        Set TOOL_BIN_DIR=/opt/recon-tools/bin in production so ambient-PATH
        binary planting cannot redirect tool execution. Dev flow (~/go/bin +
        PATH via setup_tools.sh) keeps working when the setting is empty.
        """
        import os

        from django.conf import settings

        pinned_dir = getattr(settings, "TOOL_BIN_DIR", "") or os.environ.get("TOOL_BIN_DIR", "")
        if pinned_dir and self.binary and "/" not in self.binary:
            candidate = os.path.join(pinned_dir, self.binary)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return self.binary

    def is_available(self):
        if not self.binary:
            return False
        if "/" in self.binary:
            import os

            return os.path.isfile(self.binary) and os.access(self.binary, os.X_OK)
        if self.resolved_binary() != self.binary:
            return True  # pinned binary exists and is executable
        return shutil.which(self.binary) is not None

    def version(self):
        if not self.is_available():
            return "missing"
        try:
            p = subprocess.run([self.binary, "-version"], capture_output=True, text=True, timeout=15)
            out = (p.stdout + p.stderr).strip().splitlines()
            return out[0][:80] if out else "unknown"
        except Exception:
            return "unknown"

    def build_command(self, *args, **kwargs):
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str = ""):
        raise NotImplementedError

    def run_stdin(self, hosts, timeout=DEFAULT_TIMEOUT, extra_args=None):
        """Task 13: run the tool with hosts piped on stdin (dnsx/httpx style).

        Returns AdapterResult(COMPLETED/PARTIAL/FAILED/SKIPPED, data,
        raw[:100k], error[:2k], duration_ms). Missing binary -> SKIPPED,
        TimeoutExpired -> FAILED (never hangs the worker).
        """
        import subprocess
        import time

        if not self.is_available():
            return AdapterResult(self.tool_name, status="SKIPPED",
                                 error=f"{self.binary} not installed")
        try:
            binary = self.resolved_binary()
        except Exception:
            binary = self.binary
        cmd = [binary] + list(extra_args or [])
        stdin_text = hosts if isinstance(hosts, str) else '\n'.join(hosts)
        start = time.time()
        try:
            proc = subprocess.run(cmd, input=stdin_text, capture_output=True,
                                  text=True, timeout=timeout)
            dur = int((time.time() - start) * 1000)
        except subprocess.TimeoutExpired:
            return AdapterResult(self.tool_name, status="FAILED", error="timeout")
        except Exception as e:
            return AdapterResult(self.tool_name, status="FAILED", error=str(e)[:2000])
        data = self.parse(proc.stdout, proc.stderr)
        if proc.returncode != 0 and not proc.stdout.strip():
            return AdapterResult(self.tool_name, status="FAILED", raw=proc.stdout[:100000],
                                 error=proc.stderr[:2000], duration_ms=dur)
        status = "COMPLETED" if proc.returncode == 0 else "PARTIAL"
        return AdapterResult(self.tool_name, status=status, data=data,
                             raw=proc.stdout[:100000],
                             error=proc.stderr[:2000] if proc.returncode else "",
                             duration_ms=dur)

    def run(self, *args, timeout=DEFAULT_TIMEOUT, **kwargs):
        if not self.is_available():
            return AdapterResult(self.tool_name, status="SKIPPED", error=f"{self.binary} not installed")
        cmd = self.build_command(*args, **kwargs)
        # T25: execute the pinned binary when TOOL_BIN_DIR provides one.
        try:
            resolved = self.resolved_binary()
            if cmd and cmd[0] == self.binary and resolved != self.binary:
                cmd = [resolved] + list(cmd[1:])
        except Exception:
            pass
        # T25: in production without pinning, resolving via ambient PATH is
        # worth a warning (binary-planting defense-in-depth).
        import logging as _logging
        import os

        from django.conf import settings

        if (not getattr(settings, "TOOL_BIN_DIR", "") and not os.environ.get("TOOL_BIN_DIR", "")
                and getattr(settings, "DEBUG", True) is False):
            _logging.getLogger(__name__).warning(
                "TOOL_BIN_DIR not set — resolving %s via ambient PATH", self.binary)
        import time

        start = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            dur = int((time.time() - start) * 1000)
            if p.returncode != 0 and not p.stdout.strip():
                return AdapterResult(self.tool_name, status="FAILED", raw=p.stdout, error=p.stderr[:2000], duration_ms=dur)
            data = self.parse(p.stdout, p.stderr)
            status = "COMPLETED" if p.returncode == 0 else "PARTIAL"
            return AdapterResult(self.tool_name, status=status, data=data, raw=p.stdout[:100000], error=p.stderr[:2000] if p.returncode else "", duration_ms=dur)
        except subprocess.TimeoutExpired:
            return AdapterResult(self.tool_name, status="FAILED", error="timeout")
        except Exception as e:
            return AdapterResult(self.tool_name, status="FAILED", error=str(e)[:1000])


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def redact_command(cmd: list[str]) -> str:
    """T23: redact secrets in logged tool commands (never log credentials).

    Handles two shapes:
    1. separate-arg values: -shodan-key <value>, -H "Authorization: ..." —
       the flag element names the secret, the NEXT element holds it.
    2. inline secrets: key=..., user:pass@host URLs, known marker substrings.
    Non-secret parts (incl. -u <target url>) are preserved verbatim.
    """
    import re

    SECRET_FLAG_NAMES = {
        "-shodan-key", "--shodan-key", "-censys-key", "--censys-key",
        "-virustotal-key", "--virustotal-key", "-github-token", "--github-token",
        "-chaos-key", "--chaos-key", "-urlscan-key", "--urlscan-key",
        "-api-key", "--api-key", "-apikey", "--apikey", "-token", "--token",
        "-secret", "--secret", "-password", "--password", "-passwd", "--passwd",
        "-pwd", "--pwd", "-h", "--header", "-H",
    }
    SECRET_CONTENT_MARKERS = (
        "webhook", "token", "secret", "key=", "password", "passwd", "pwd=",
        "authorization", "bearer", "apikey", "api_key", "cookie=", "session=",
        "credential", "x-amz-signature", "hooks.slack.com", "discord.com/api/webhooks",
    )
    _USERINFO_RE = re.compile(r"(://[^/\s]*?)([^/\s:@]+):([^/\s@]+)@")

    out = []
    redact_next = False
    for part in cmd:
        low = part.lower()
        if redact_next:
            out.append("***REDACTED***")
            redact_next = False
            continue
        if low in SECRET_FLAG_NAMES:
            out.append(part)
            redact_next = True
            continue
        if any(k in low for k in SECRET_CONTENT_MARKERS):
            out.append("***REDACTED***")
            continue
        redacted, n = _USERINFO_RE.subn(r"\1***REDACTED***@", part)
        out.append(redacted if n else part)
    if redact_next:
        out.append("***REDACTED***")
    return " ".join(out)


def _safe_artifact_path(path: str, base_dir) -> str:
    """T24: contain tool file reads inside base_dir (traversal/symlink guard).

    Returns the resolved absolute path, or raises ValueError if it escapes.
    """
    import os

    base = os.path.realpath(str(base_dir))
    resolved = os.path.realpath(path)
    if resolved != base and not resolved.startswith(base + os.sep):
        raise ValueError(f"artifact path escapes base dir: {path!r}")
    return resolved
