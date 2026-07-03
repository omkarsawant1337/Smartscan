"""
CVE Lookup Module — SmartScan v2.0
Uses NIST NVD API v2 (Free, no API key required)
Author: Omkar Sawant | github.com/omkarsawant1337
"""

import requests
import time
from rich.console import Console

console = Console()

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SKIP_SERVICES = {"unknown", "tcpwrapped", "", "filtered", "closed"}


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def run_cve_lookup_for_scan(scan_results: dict) -> dict:
    """
    Run CVE lookups for every open port in scan_results.
    Returns  { "IP:PORT" : [cve_dict, ...] }
    """
    cve_map   = {}
    all_ports = [
        (host["ip"], port)
        for host in scan_results["hosts"]
        for port in host["open_ports"]
    ]

    total = len(all_ports)
    if total == 0:
        console.print("[yellow][!] No open ports to look up CVEs for.[/yellow]")
        return cve_map

    console.print(f"\n[cyan][*] CVE lookup for {total} open port(s) via NVD API...[/cyan]")
    console.print("[dim]    Rate-limited to ~5 req/30 s — please wait[/dim]\n")

    for idx, (ip, port_info) in enumerate(all_ports, 1):
        port_num = port_info.get("port", "")
        service  = port_info.get("service", "")
        version  = port_info.get("version", "")
        product  = port_info.get("product", "")
        key      = f"{ip}:{port_num}"
        keyword  = _build_keyword(service, version, product)

        if not keyword:
            console.print(f"  [{idx}/{total}] Port {port_num} ({service}) — [dim]skipped (generic)[/dim]")
            cve_map[key] = []
            continue

        console.print(f"  [{idx}/{total}] Port [white]{port_num}[/white] → [bold cyan]{keyword}[/bold cyan]")
        cves = _search_cves(keyword)
        cve_map[key] = cves

        if cves:
            top   = cves[0]
            color = severity_color(top["cvss_severity"])
            console.print(
                f"         ↳ [bold]{top['cve_id']}[/bold]  "
                f"CVSS {top['cvss_score']}  "
                f"[{color}]{top['cvss_severity']}[/{color}]  "
                f"[dim]({len(cves)} found)[/dim]"
            )
        else:
            console.print("         ↳ [dim]No CVEs found[/dim]")

    return cve_map


def lookup_cve_by_id(cve_id: str) -> dict:
    """Fetch a specific CVE by ID (e.g. CVE-2021-44228). Returns dict or {}."""
    try:
        resp = requests.get(NVD_API_BASE, params={"cveId": cve_id}, timeout=12)
        time.sleep(0.7)
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                return _parse_cve(vulns[0]["cve"])
    except Exception as e:
        console.print(f"[red][!] CVE ID lookup error: {e}[/red]")
    return {}


def severity_color(severity: str) -> str:
    """Map CVSS severity to Rich color string."""
    return {
        "CRITICAL": "bold red",
        "HIGH":     "orange3",
        "MEDIUM":   "yellow",
        "LOW":      "green",
        "NONE":     "dim",
    }.get((severity or "").upper(), "white")


# ─────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────

def _search_cves(keyword: str) -> list:
    try:
        resp = requests.get(
            NVD_API_BASE,
            params={"keywordSearch": keyword, "resultsPerPage": 5, "startIndex": 0},
            timeout=12
        )
        time.sleep(0.7)

        if resp.status_code == 200:
            return [_parse_cve(item["cve"]) for item in resp.json().get("vulnerabilities", [])]
        elif resp.status_code == 403:
            console.print("[yellow][!] NVD rate limit — waiting 12 s...[/yellow]")
            time.sleep(12)
    except requests.exceptions.Timeout:
        console.print(f"[red][!] Timeout for: {keyword}[/red]")
    except requests.exceptions.ConnectionError:
        console.print("[red][!] No internet — CVE lookup skipped.[/red]")
    except Exception as e:
        console.print(f"[red][!] CVE error: {e}[/red]")
    return []


def _parse_cve(cve: dict) -> dict:
    cve_id      = cve.get("id", "N/A")
    descriptions = cve.get("descriptions", [])
    description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "N/A")
    score, sev, ver = _extract_cvss(cve)
    published   = cve.get("published", "N/A")[:10]
    modified    = cve.get("lastModified", "N/A")[:10]

    return {
        "cve_id":        cve_id,
        "description":   description[:300] + ("..." if len(description) > 300 else ""),
        "full_desc":     description,
        "cvss_score":    score,
        "cvss_severity": sev,
        "cvss_version":  ver,
        "published":     published,
        "modified":      modified,
        "url":           f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }


def _extract_cvss(cve: dict) -> tuple:
    metrics = cve.get("metrics", {})
    for key, label in [("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0")]:
        lst = metrics.get(key, [])
        if lst:
            m = lst[0].get("cvssData", {})
            return m.get("baseScore", "N/A"), m.get("baseSeverity", "N/A"), label
    lst = metrics.get("cvssMetricV2", [])
    if lst:
        m   = lst[0].get("cvssData", {})
        sev = lst[0].get("baseSeverity", "N/A")
        return m.get("baseScore", "N/A"), sev, "v2.0"
    return "N/A", "N/A", "N/A"


def _build_keyword(service: str, version: str, product: str) -> str:
    if service.lower() in SKIP_SERVICES:
        return ""
    base = product if product and product.lower() not in SKIP_SERVICES else service
    base = base.strip()
    if version and len(version) < 20 and any(c.isdigit() for c in version):
        return f"{base} {version}"
    return base
