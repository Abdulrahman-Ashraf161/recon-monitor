# Tool Capability Matrix (TASK-070)

> What each tool contributes, required/optional, fallback, coverage lost.

| Tool | Required? | Contributes | Fallback | Lost if missing |
|---|---|---|---|---|
| subfinder | No | passive subdomains | amass/crt.sh | fewer passive sources |
| amass | No | passive subdomains | subfinder/crt.sh | fewer sources |
| findomain | No | passive subdomains | others | fewer sources |
| assetfinder | No | passive subdomains | others | fewer sources |
| crt.sh (HTTPS) | No (network) | passive subdomains, no binary | — | one source lost |
| dnsx | No | A/AAAA/CNAME bulk DNS | stdlib socket A | record types beyond A |
| puredns | No | active brute-force | skipped | active DNS枚举 |
| naabu | No | port scan | stdlib connect (top ports) | speed/service detection |
| httpx | No | HTTP probe + title/tech/server | urllib fallback | tech-detect depth |
| gau | No | historical URLs | other URL sources | historical coverage |
| waybackurls | No | historical URLs | gau/waymore | same |
| waymore | No (pip) | historical URLs | gau | same |
| katana | No | crawl live hosts | skipped | crawled URLs/JS |
| ffuf/dirsearch/gobuster | No | active content discovery | skipped (profile-gated) | active paths |
| jsluice | No | JS endpoints/secrets | python regex fallback | JS intel depth |
| LinkFinder | No (clone) | JS endpoints | regex fallback | same |
| SecretFinder | No (clone) | JS secrets | regex fallback | same |
| semgrep | No (pip) | JS SAST | skipped | SAST findings |
| retire.js | No (npm) | JS vuln libs | version-regex fallback | lib CVE precision |
| nuclei | Recommended | validation + findings | CVE stays candidate | no validation |
| nuclei templates | Recommended (`nuclei -update-templates`) | template catalog | heuristic mapping | validation breadth |

Health: Settings → Tools & System (`tool_health()`), per-scan Tools executed/failed
in Jobs. Missing = SKIPPED + PARTIAL status, never silent (TASK-005 honest failures).
Scan profiles gate tools: passive never runs naabu/ffuf; balanced adds httpx/katana;
active adds port scan + content discovery; full = all configured.
