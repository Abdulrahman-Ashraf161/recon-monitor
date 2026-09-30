"""Scan profiles (TASK-055): Passive / Balanced / Active / Full.

Each profile declares capabilities -> tools. Views + tasks use this so we never
'auto-run all tools for every target'.
"""

PROFILES = {
    "passive": {
        "label": "Passive",
        "description": "No direct contact: passive subdomains, DNS, historical URLs, tech+ CVE correlation.",
        "capabilities": [
            "passive_subdomains",
            "dns",
            "historical_urls",
            "tech_correlation",
            "cve_correlation",
        ],
        "tools": [
            "subfinder",
            "amass",
            "findomain",
            "assetfinder",
            "crtsh",
            "gau",
            "waybackurls",
            "waymore",
        ],
    },
    "balanced": {
        "label": "Balanced",
        "description": "Passive + HTTP probing, katana crawl, JS analysis, targeted validation.",
        "capabilities": [
            "passive_subdomains",
            "dns",
            "historical_urls",
            "http_probing",
            "katana",
            "js_analysis",
            "tech_correlation",
            "cve_correlation",
            "targeted_validation",
        ],
        "tools": [
            "subfinder",
            "amass",
            "dnsx",
            "httpx",
            "gau",
            "waybackurls",
            "waymore",
            "katana",
            "jsluice",
            "linkfinder",
            "secretfinder",
            "semgrep",
            "retirejs",
            "nuclei-targeted",
        ],
    },
    "active": {
        "label": "Active",
        "description": "Balanced + port scanning, content discovery, optional active subdomain discovery.",
        "capabilities": [
            "passive_subdomains",
            "active_subdomains",
            "dns",
            "port_scan",
            "http_probing",
            "katana",
            "content_discovery",
            "js_analysis",
            "tech_correlation",
            "cve_correlation",
            "targeted_validation",
        ],
        "tools": [
            "subfinder",
            "amass",
            "findomain",
            "dnsx",
            "puredns",
            "naabu",
            "httpx",
            "katana",
            "ffuf",
            "dirsearch",
            "gobuster",
            "nuclei-targeted",
        ],
    },
    "full": {
        "label": "Full",
        "description": "All configured capabilities.",
        "capabilities": [
            "passive_subdomains",
            "active_subdomains",
            "dns",
            "port_scan",
            "http_probing",
            "historical_urls",
            "katana",
            "content_discovery",
            "js_analysis",
            "tech_correlation",
            "cve_correlation",
            "targeted_validation",
        ],
        "tools": [
            "subfinder",
            "amass",
            "findomain",
            "assetfinder",
            "dnsx",
            "puredns",
            "naabu",
            "httpx",
            "gau",
            "waybackurls",
            "waymore",
            "katana",
            "ffuf",
            "dirsearch",
            "gobuster",
            "jsluice",
            "linkfinder",
            "secretfinder",
            "semgrep",
            "retirejs",
            "nuclei",
        ],
    },
}

PROFILE_CHOICES = [(k, v["label"]) for k, v in PROFILES.items()]


def get_profile(name):
    return PROFILES.get((name or "balanced").lower(), PROFILES["balanced"])


def profile_allows(profile_name, capability):
    return capability in get_profile(profile_name)["capabilities"]
