"""Base adapter: validate input -> build command -> execute -> capture -> parse -> normalize."""

import hashlib
import shutil
import subprocess

DEFAULT_TIMEOUT = 300


class AdapterResult:
    """Normalised tool result.

    P1-002: carries the full execution evidence needed to persist a complete
    ``ToolExecution`` row -- the (already redacted) command, the process exit
    code, and the captured stdout/stderr streams that get referenced from the
    database row.
    """

    def __init__(
        self,
        tool,
        status="COMPLETED",
        data=None,
        raw="",
        error="",
        duration_ms=0,
        command="",
        exit_code=None,
        stdout="",
        stderr="",
    ):
        self.tool = tool
        self.status = status  # COMPLETED/FAILED/PARTIAL/SKIPPED
        self.data = data or []
        self.raw = raw
        self.error = error
        self.duration_ms = duration_ms
        self.command = command  # redacted command line, never secrets
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


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
            p = subprocess.run(
                [self.binary, "-version"], capture_output=True, text=True, timeout=15
            )
            out = (p.stdout + p.stderr).strip().splitlines()
            return out[0][:80] if out else "unknown"
        except Exception:
            return "unknown"

    def build_command(self, *args, **kwargs):
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str = ""):
        raise NotImplementedError

    def run_stdin(self, hosts, timeout=DEFAULT_TIMEOUT, extra_args=None, cancel_check=None):
        """Task 13: run the tool with hosts piped on stdin (dnsx/httpx style).

        Returns AdapterResult(COMPLETED/PARTIAL/FAILED/SKIPPED, data,
        raw[:100k], error[:2k], duration_ms). Missing binary -> SKIPPED,
        TimeoutExpired -> FAILED (never hangs the worker).

        ``cancel_check`` (P0-013): an optional callable invoked repeatedly while
        the tool runs; when it raises (a kill-switch trip), the tool's whole
        process group is terminated before the exception propagates. This is
        what makes a 300s DNS pass actually stop the moment the target is
        paused instead of running to completion.
        """
        import time

        if not self.is_available():
            return AdapterResult(
                self.tool_name,
                status="SKIPPED",
                error=f"{self.binary} not installed",
                command=redact_command([self.binary, *(extra_args or [])]),
                exit_code=None,
            )
        try:
            binary = self.resolved_binary()
        except Exception:
            binary = self.binary
        cmd = [binary, *(extra_args or [])]
        cmd_redacted = redact_command(cmd)
        stdin_text = hosts if isinstance(hosts, str) else "\n".join(hosts)
        start = time.time()
        try:
            returncode, stdout, stderr = _run_tool_process(
                cmd, stdin_text=stdin_text, timeout=timeout, cancel_check=cancel_check
            )
            dur = int((time.time() - start) * 1000)
        except subprocess.TimeoutExpired:
            return AdapterResult(
                self.tool_name,
                status="FAILED",
                error="timeout",
                command=cmd_redacted,
                exit_code=None,
            )
        except Exception:
            raise  # kill-switch trip: let the caller's cancellation handler run
        if returncode != 0 and not stdout.strip():
            return AdapterResult(
                self.tool_name,
                status="FAILED",
                raw=stdout[:100000],
                error=stderr[:2000],
                duration_ms=dur,
                command=cmd_redacted,
                exit_code=returncode,
                stdout=stdout,
                stderr=stderr,
            )
        data = self.parse(stdout, stderr)
        status = "COMPLETED" if returncode == 0 else "PARTIAL"
        return AdapterResult(
            self.tool_name,
            status=status,
            data=data,
            raw=stdout[:100000],
            error=stderr[:2000] if returncode else "",
            duration_ms=dur,
            command=cmd_redacted,
            exit_code=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def run(self, *args, timeout=DEFAULT_TIMEOUT, cancel_check=None, **kwargs):
        if not self.is_available():
            return AdapterResult(
                self.tool_name,
                status="SKIPPED",
                error=f"{self.binary} not installed",
                command=redact_command([self.binary]),
            )
        cmd = self.build_command(*args, **kwargs)
        # T25: execute the pinned binary when TOOL_BIN_DIR provides one.
        try:
            resolved = self.resolved_binary()
            if cmd and cmd[0] == self.binary and resolved != self.binary:
                cmd = [resolved, *cmd[1:]]
        except Exception:
            pass
        # P1-002: the persisted command is the redacted rendering of exactly
        # what runs, so an auditor can reproduce it without seeing credentials.
        cmd_redacted = redact_command(cmd)
        # T25: in production without pinning, resolving via ambient PATH is
        # worth a warning (binary-planting defense-in-depth).
        import logging as _logging
        import os

        from django.conf import settings

        if (
            not getattr(settings, "TOOL_BIN_DIR", "")
            and not os.environ.get("TOOL_BIN_DIR", "")
            and getattr(settings, "DEBUG", True) is False
        ):
            _logging.getLogger(__name__).warning(
                "TOOL_BIN_DIR not set — resolving %s via ambient PATH", self.binary
            )
        import time

        start = time.time()
        try:
            returncode, stdout, stderr = _run_tool_process(
                cmd, stdin_text="", timeout=timeout, cancel_check=cancel_check
            )
            dur = int((time.time() - start) * 1000)
        except subprocess.TimeoutExpired:
            return AdapterResult(
                self.tool_name,
                status="FAILED",
                error="timeout",
                command=cmd_redacted,
                exit_code=None,
            )
        except Exception:
            raise  # kill-switch trip: let the caller's cancellation handler run
        if returncode != 0 and not stdout.strip():
            return AdapterResult(
                self.tool_name,
                status="FAILED",
                raw=stdout,
                error=stderr[:2000],
                duration_ms=dur,
                command=cmd_redacted,
                exit_code=returncode,
                stdout=stdout,
                stderr=stderr,
            )
        data = self.parse(stdout, stderr)
        status = "COMPLETED" if returncode == 0 else "PARTIAL"
        return AdapterResult(
            self.tool_name,
            status=status,
            data=data,
            raw=stdout[:100000],
            error=stderr[:2000] if returncode else "",
            duration_ms=dur,
            command=cmd_redacted,
            exit_code=returncode,
            stdout=stdout,
            stderr=stderr,
        )


def _kill_tool_group(proc, grace=5.0):
    """SIGTERM a tool's whole process group, then SIGKILL after `grace`.

    ``start_new_session=True`` gives the tool its own process group so a
    spawned backend subprocess is killed too — a plain ``proc.kill()`` would
    only reap the direct child and could orphan the child's children.
    """
    import os
    import signal

    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, ValueError):
        try:
            proc.terminate()
        except Exception:
            pass
    if grace:
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, ValueError):
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def _run_tool_process(cmd, stdin_text="", timeout=DEFAULT_TIMEOUT, cancel_check=None):
    """Run a tool in its own process group; stop the group on timeout/cancel.

    Polls ``cancel_check`` (the kill-switch callback) every ~0.2s instead of
    blocking on the child, so a pause or an authorization lapse terminates the
    tool process group immediately rather than waiting for a 5-minute default
    timeout. Raises ``subprocess.TimeoutExpired`` on timeout; on cancellation
    the original exception from ``cancel_check`` is re-raised *after* the group
    is terminated, so the caller's own cancellation handling runs.

    Returns ``(returncode, stdout, stderr)``.
    """
    import threading
    import time

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    collected = {}

    def _pump():
        try:
            collected["out"], collected["err"] = proc.communicate(stdin_text)
        except Exception as exc:
            collected["pump_exc"] = exc

    pump = threading.Thread(target=_pump, daemon=True)
    pump.start()

    deadline = time.monotonic() + timeout
    cancelled = None
    try:
        while proc.poll() is None:
            try:
                if cancel_check is not None:
                    cancel_check()
            except BaseException as exc:
                cancelled = exc
                _kill_tool_group(proc, grace=2.0)
                break
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(cmd, timeout)
            time.sleep(0.2)
    finally:
        if proc.poll() is None:
            _kill_tool_group(proc, grace=2.0)
        pump.join(timeout=5)
    if cancelled is not None:
        raise cancelled
    return proc.returncode, collected.get("out", ""), collected.get("err", "")


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
        "-shodan-key",
        "--shodan-key",
        "-censys-key",
        "--censys-key",
        "-virustotal-key",
        "--virustotal-key",
        "-github-token",
        "--github-token",
        "-chaos-key",
        "--chaos-key",
        "-urlscan-key",
        "--urlscan-key",
        "-api-key",
        "--api-key",
        "-apikey",
        "--apikey",
        "-token",
        "--token",
        "-secret",
        "--secret",
        "-password",
        "--password",
        "-passwd",
        "--passwd",
        "-pwd",
        "--pwd",
        "-h",
        "--header",
        "-H",
    }
    SECRET_CONTENT_MARKERS = (
        "webhook",
        "token",
        "secret",
        "key=",
        "password",
        "passwd",
        "pwd=",
        "authorization",
        "bearer",
        "apikey",
        "api_key",
        "cookie=",
        "session=",
        "credential",
        "x-amz-signature",
        "hooks.slack.com",
        "discord.com/api/webhooks",
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
