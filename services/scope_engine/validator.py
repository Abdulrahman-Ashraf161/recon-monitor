"""Scope Validator — mandatory gate before ANY active operation."""

import ipaddress

# T4: SSRF guard — ranges that must never be actively fetched/scanned, even if a
# hostname that resolves into them passes validate_host(). Checked unconditionally
# in validate_ip() (no scope rule can re-enable them) and at the HTTP layer via
# host_resolves_to_blocked() before every outbound fetch (defense-in-depth
# against DNS rebinding: validate at connect time, not just ingest time).
PRIVATE_BLOCK_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_private_or_reserved(ip_str: str) -> bool:
    """True if the IP must never be touched. Fail-closed on unparsable input."""
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return True
    return (
        any(addr in net for net in PRIVATE_BLOCK_NETWORKS)
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def host_resolves_to_blocked(hostname: str) -> tuple[bool, str]:
    """Resolve-then-check helper for the HTTP layer (T4 defense-in-depth).

    Returns (blocked, reason). Any resolved address in a blocked range blocks
    the fetch. DNS failures return (False, ...) — resolution errors are handled
    by the caller's normal fetch-failure path, not the SSRF path.
    """
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False, "unresolvable"
    for _fam, _, _, _, sockaddr in infos:
        # getaddrinfo always yields a textual address in sockaddr[0]; the stub
        # types it as `str | int` for the AF_UNIX case, which cannot occur here.
        ip = str(sockaddr[0])
        # Strip IPv6 zone ids (fe80::1%eth0) before parsing.
        ip = ip.split("%")[0]
        if is_private_or_reserved(ip):
            return True, f"resolves to blocked IP {ip}"
    return False, "ok"


def _matches_domain(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def validate_host(target, host: str, scope_rules) -> tuple[bool, str]:
    """Check host against target scope rules. Returns (allowed, reason)."""
    host = (host or "").lower().strip().rstrip(".")
    allows = [r.value for r in scope_rules if r.rule_type == "allow_domain"]
    excludes = [r.value for r in scope_rules if r.rule_type == "exclude_host"]
    for pat in excludes:
        if _matches_domain(host, pat):
            return False, f"excluded host {pat}"
    if allows:
        for pat in allows:
            if _matches_domain(host, pat):
                return True, "allowed"
        # default: subdomains of the root domain are allowed
        if host == target.root_domain or host.endswith("." + target.root_domain):
            return True, "allowed (root domain)"
        return False, "not in allowed domains"
    # no explicit allow rules: root domain + subdomains allowed
    if host == target.root_domain or host.endswith("." + target.root_domain):
        return True, "allowed (root domain)"
    return False, "outside root domain"


def validate_ip(target, ip: str, scope_rules) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "invalid ip"
    # T4: private/reserved ranges are blocked unconditionally — no scope rule
    # (allow_ip or otherwise) can re-enable scanning of link-local/metadata space.
    if is_private_or_reserved(ip):
        return False, "private/reserved IP blocked"
    for r in scope_rules:
        if r.rule_type == "exclude_ip":
            try:
                if addr in ipaddress.ip_network(r.value, strict=False):
                    return False, f"excluded ip {r.value}"
            except ValueError:
                continue
    allows = [r.value for r in scope_rules if r.rule_type == "allow_ip"]
    if allows:
        for net in allows:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True, "allowed"
            except ValueError:
                continue
        return False, "not in allowed ips"
    return True, "allowed"


def scope_allows_scan(target, scope_rules) -> tuple[bool, str]:
    if target.status != target.STATUS_ACTIVE:
        return False, f"target status {target.status}"
    if not target.is_scannable:
        return False, "authorization expired or target not active"
    return True, "ok"
