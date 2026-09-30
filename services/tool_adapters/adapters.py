"""Concrete adapters for every recon tool. Missing binaries -> SKIPPED, never crash."""

import json
import re

from .base import BaseAdapter


class SubfinderAdapter(BaseAdapter):
    tool_name = "subfinder"
    binary = "subfinder"

    def build_command(self, domain, **kw):
        return [self.binary, "-d", domain, "-silent", "-json"]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host")
                if host:
                    out.append({"hostname": host, "source": "subfinder"})
            except json.JSONDecodeError:
                if "." in line and " " not in line:
                    out.append({"hostname": line, "source": "subfinder"})
        return out


class AmassAdapter(BaseAdapter):
    tool_name = "amass"
    binary = "amass"

    def build_command(self, domain, **kw):
        return [self.binary, "enum", "-passive", "-d", domain]

    def parse(self, stdout, stderr=""):
        return [
            {"hostname": l.strip(), "source": "amass"}
            for l in stdout.splitlines()
            if "." in l.strip() and " " not in l.strip()
        ]


class FindomainAdapter(BaseAdapter):
    tool_name = "findomain"
    binary = "findomain"

    def build_command(self, domain, **kw):
        return [self.binary, "-t", domain, "-q"]

    def parse(self, stdout, stderr=""):
        return [
            {"hostname": l.strip(), "source": "findomain"}
            for l in stdout.splitlines()
            if "." in l.strip() and " " not in l.strip()
        ]


class AssetfinderAdapter(BaseAdapter):
    tool_name = "assetfinder"
    binary = "assetfinder"

    def build_command(self, domain, **kw):
        return [self.binary, "--subs-only", domain]

    def parse(self, stdout, stderr=""):
        return [
            {"hostname": l.strip(), "source": "assetfinder"}
            for l in stdout.splitlines()
            if "." in l.strip() and " " not in l.strip()
        ]


class CrtshAdapter(BaseAdapter):
    """crt.sh via HTTPS (no binary needed, uses requests)."""

    tool_name = "crtsh"
    binary = "python3"  # always "available"; network may fail -> FAILED/PARTIAL

    def is_available(self):
        return True

    def build_command(self, domain, **kw):
        return ["crt.sh", domain]

    def parse(self, stdout, stderr=""):
        try:
            data = json.loads(stdout) if stdout.strip().startswith("[") else []
        except json.JSONDecodeError:
            return []
        out = []
        for entry in data:
            for h in (entry.get("name_value") or "").splitlines():
                h = h.strip().lower().lstrip("*.")
                if h:
                    out.append({"hostname": h, "source": "crtsh"})
        return out

    def run(self, domain, timeout=60, **kw):
        from .base import AdapterResult

        try:
            import requests
        except ImportError:
            return AdapterResult("crtsh", status="SKIPPED", error="requests library not installed")

        # T4: resolve-then-check even for this fixed public host (DNS hijack /
        # rebinding could otherwise redirect the query to internal space).
        try:
            from services.scope_engine.validator import host_resolves_to_blocked

            blocked, why = host_resolves_to_blocked("crt.sh")
            if blocked:
                return AdapterResult("crtsh", status="FAILED", error=f"crt.sh {why}")
        except Exception:
            pass
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
            if r.status_code != 200:
                return AdapterResult("crtsh", status="FAILED", error=f"HTTP {r.status_code}")
            return AdapterResult(
                "crtsh", status="COMPLETED", data=self.parse(r.text), raw=r.text[:100000]
            )
        except Exception as e:
            return AdapterResult("crtsh", status="FAILED", error=str(e)[:500])


class KnockpyAdapter(BaseAdapter):
    tool_name = "knockpy"
    binary = "knockpy"

    def build_command(self, domain, **kw):
        return [self.binary, "-d", domain, "--recon", "--silent"]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            s = line.strip().strip("[],'\" ")
            if domain_in_line(s):
                out.append({"hostname": s, "source": "knockpy"})
        return out


def domain_in_line(line):
    line = line.strip()
    return "." in line and " " not in line


class PurednsAdapter(BaseAdapter):
    tool_name = "puredns"
    binary = "puredns"

    def build_command(self, domain, wordlist=None, **kw):
        cmd = [
            self.binary,
            "bruteforce",
            wordlist or "/usr/share/wordlists/subdomains.txt",
            domain,
            "--silent",
        ]
        return cmd

    def parse(self, stdout, stderr=""):
        return [
            {"hostname": l.strip(), "source": "puredns"}
            for l in stdout.splitlines()
            if domain_in_line(l)
        ]


class DnsxAdapter(BaseAdapter):
    tool_name = "dnsx"
    binary = "dnsx"

    def build_command(self, hosts, **kw):
        return [self.binary, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp"]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def run(self, hosts, timeout=300, **kw):
        """Task 13: pipe hosts on stdin (build_command holds flags only)."""
        return self.run_stdin(
            hosts,
            timeout=timeout,
            extra_args=["-silent", "-json", "-a", "-aaaa", "-cname", "-resp"],
        )


class FfufAdapter(BaseAdapter):
    tool_name = "ffuf"
    binary = "ffuf"

    def build_command(self, url, wordlist=None, **kw):
        return [
            self.binary,
            "-u",
            url,
            "-w",
            wordlist or "/usr/share/wordlists/dirb.txt",
            "-mc",
            "200,301,302,401,403",
            "-o",
            "-",
            "-of",
            "json",
            "-s",
        ]

    def parse(self, stdout, stderr=""):
        try:
            data = json.loads(stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []


class NaabuAdapter(BaseAdapter):
    tool_name = "naabu"
    binary = "naabu"

    def build_command(self, host, ports=None, **kw):
        cmd = [self.binary, "-host", host, "-silent", "-json"]
        if ports:
            cmd += ["-p", ports]
        return cmd

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
                out.append({"ip": obj.get("ip"), "port": obj.get("port"), "protocol": "tcp"})
            except json.JSONDecodeError:
                m = re.match(r"([\d.]+):(\d+)", line.strip())
                if m:
                    out.append({"ip": m.group(1), "port": int(m.group(2)), "protocol": "tcp"})
        return out


class HttpxAdapter(BaseAdapter):
    tool_name = "httpx"
    binary = "httpx"

    def build_command(self, hosts=None, **kw):
        return [
            self.binary,
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-type",
            "-content-length",
            "-server",
            "-ip",
            "-tls-probe",
        ]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def run(self, hosts, timeout=600, **kw):
        """Task 13: pipe hosts/URLs on stdin (build_command holds flags only)."""
        return self.run_stdin(
            hosts,
            timeout=timeout,
            extra_args=[
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-type",
                "-content-length",
                "-server",
                "-ip",
                "-tls-probe",
            ],
        )


class GauAdapter(BaseAdapter):
    tool_name = "gau"
    binary = "gau"

    def build_command(self, domain, **kw):
        return [self.binary, domain, "--subs"]

    def parse(self, stdout, stderr=""):
        return [
            {"url": l.strip(), "source": "gau"}
            for l in stdout.splitlines()
            if l.strip().startswith("http")
        ]


class WaybackurlsAdapter(BaseAdapter):
    tool_name = "waybackurls"
    binary = "waybackurls"

    def build_command(self, domain, **kw):
        return [self.binary, domain]

    def parse(self, stdout, stderr=""):
        return [
            {"url": l.strip(), "source": "waybackurls"}
            for l in stdout.splitlines()
            if l.strip().startswith("http")
        ]


class WaymoreAdapter(BaseAdapter):
    tool_name = "waymore"
    binary = "waymore"

    def build_command(self, domain, **kw):
        return [self.binary, "-i", domain, "-mode", "U"]

    def parse(self, stdout, stderr=""):
        return [
            {"url": l.strip(), "source": "waymore"}
            for l in stdout.splitlines()
            if l.strip().startswith("http")
        ]


class KatanaAdapter(BaseAdapter):
    tool_name = "katana"
    binary = "katana"

    def build_command(self, url, **kw):
        return [self.binary, "-u", url, "-silent", "-jsonl"]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("request", {}).get("endpoint"):
                    out.append({"url": obj["request"]["endpoint"], "source": "katana"})
            except json.JSONDecodeError:
                if line.strip().startswith("http"):
                    out.append({"url": line.strip(), "source": "katana"})
        return out


class DirsearchAdapter(BaseAdapter):
    tool_name = "dirsearch"
    binary = "dirsearch"

    def build_command(self, url, **kw):
        return [self.binary, "-u", url, "--format=json", "-q"]

    def parse(self, stdout, stderr=""):
        try:
            data = json.loads(stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []


class GobusterAdapter(BaseAdapter):
    tool_name = "gobuster"
    binary = "gobuster"

    def build_command(self, url, wordlist=None, **kw):
        return [
            self.binary,
            "dir",
            "-u",
            url,
            "-w",
            wordlist or "/usr/share/wordlists/dirb.txt",
            "-q",
            "-o",
            "-",
        ]

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            m = re.match(r"(\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                out.append({"path": m.group(1), "status": int(m.group(2))})
        return out


class NucleiAdapter(BaseAdapter):
    tool_name = "nuclei"
    binary = "nuclei"

    def build_command(self, target_url, severity=None, **kw):
        cmd = [self.binary, "-u", target_url, "-silent", "-jsonl"]
        if severity:
            cmd += ["-severity", severity]
        return cmd

    def parse(self, stdout, stderr=""):
        out = []
        for line in stdout.splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


class JsluiceAdapter(BaseAdapter):
    tool_name = "jsluice"
    binary = "jsluice"

    def build_command(self, js_file=None, **kw):
        return [self.binary, "urls", js_file or ""]

    def parse(self, stdout, stderr=""):
        return [{"url": l.strip(), "source": "jsluice"} for l in stdout.splitlines() if l.strip()]


class LinkfinderAdapter(BaseAdapter):
    tool_name = "linkfinder"
    binary = "linkfinder"

    def build_command(self, js_url=None, js_file=None, **kw):
        if js_url:
            return [self.binary, "-i", js_url, "-o", "cli"]
        return [self.binary, "-i", js_file or "", "-o", "cli"]

    def parse(self, stdout, stderr=""):
        return [
            {"endpoint": l.strip(), "source": "linkfinder"}
            for l in stdout.splitlines()
            if l.strip().startswith("/") or l.strip().startswith("http")
        ]


class SecretfinderAdapter(BaseAdapter):
    tool_name = "secretfinder"
    binary = "secretfinder"

    def build_command(self, js_url=None, js_file=None, **kw):
        if js_url:
            return [self.binary, "-i", js_url, "-o", "cli"]
        return [self.binary, "-i", js_file or "", "-o", "cli"]

    def parse(self, stdout, stderr=""):
        findings = []
        for line in stdout.splitlines():
            if "->" in line or "found" in line.lower():
                findings.append({"raw": line.strip()[:500], "source": "secretfinder"})
        return findings


class SemgrepAdapter(BaseAdapter):
    tool_name = "semgrep"
    binary = "semgrep"

    def build_command(self, path=None, **kw):
        return [self.binary, "--config", "auto", "--json", "-q", path or "."]

    def parse(self, stdout, stderr=""):
        try:
            return json.loads(stdout).get("results", [])
        except json.JSONDecodeError:
            return []


class RetirejsAdapter(BaseAdapter):
    tool_name = "retire"
    binary = "retire"

    def build_command(self, path=None, js_content=None, **kw):
        return [self.binary, "--outputformat", "json", "--path", path or "."]

    def parse(self, stdout, stderr=""):
        try:
            return json.loads(stdout).get("data", [])
        except json.JSONDecodeError:
            return []


ADAPTERS = {
    "subfinder": SubfinderAdapter,
    "amass": AmassAdapter,
    "findomain": FindomainAdapter,
    "assetfinder": AssetfinderAdapter,
    "crtsh": CrtshAdapter,
    "knockpy": KnockpyAdapter,
    "puredns": PurednsAdapter,
    "dnsx": DnsxAdapter,
    "ffuf": FfufAdapter,
    "naabu": NaabuAdapter,
    "httpx": HttpxAdapter,
    "gau": GauAdapter,
    "waybackurls": WaybackurlsAdapter,
    "waymore": WaymoreAdapter,
    "katana": KatanaAdapter,
    "dirsearch": DirsearchAdapter,
    "gobuster": GobusterAdapter,
    "nuclei": NucleiAdapter,
    "jsluice": JsluiceAdapter,
    "linkfinder": LinkfinderAdapter,
    "secretfinder": SecretfinderAdapter,
    "semgrep": SemgrepAdapter,
    "retire": RetirejsAdapter,
}


def tool_health():
    """Return list of {tool, version, path, status} without crashing on missing tools."""

    rows = []
    for name, cls in ADAPTERS.items():
        inst = cls()
        import shutil as _s

        path = _s.which(getattr(inst, "binary", "") or "") or (
            "builtin" if name == "crtsh" else "missing"
        )
        try:
            version = inst.version() if name != "crtsh" else "https-api"
        except Exception:
            version = "unknown"
        status = "OK" if (name == "crtsh" or path not in ("missing", None)) else "MISSING"
        rows.append({"tool": name, "version": version, "path": path, "status": status})
    return rows
