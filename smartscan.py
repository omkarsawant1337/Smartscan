#!/usr/bin/env python3
"""
SmartScan v2.0 — AI-Powered Port Scanner
  ✔ Nmap port scanning (5 profiles)
  ✔ NIST NVD CVE lookup (free, no key)
  ✔ Groq AI analysis — LLaMA 3.3 70B (FREE)
  ✔ Professional HTML report

Author : Omkar Sawant
GitHub : github.com/omkarsawant1337
Usage  : sudo python3 smartscan.py
"""

import nmap
import sys
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from ai_analyzer import analyze_with_ai
from cve_lookup  import run_cve_lookup_for_scan, lookup_cve_by_id, severity_color
from report_gen  import generate_report

console = Console()

BANNER = r"""[bold cyan]
  ____                       _   ____
 / ___| _ __ ___   __ _ _ __| |_/ ___|  ___ __ _ _ __
 \___ \| '_ ` _ \ / _` | '__| __\___ \ / __/ _` | '_ \
  ___) | | | | | | (_| | |  | |_ ___) | (_| (_| | | | |
 |____/|_| |_| |_|\__,_|_|   \__|____/ \___\__,_|_| |_|
[/bold cyan]
[bold green]       AI-Powered Port Scanner + CVE Lookup  v2.0[/bold green]
[dim]       Author: Omkar Sawant | github.com/omkarsawant1337[/dim]
[bold orange3]       AI Engine: Groq LLaMA 3.3 70B (FREE)[/bold orange3]
"""


# ══════════════════════════════════════════════════════════════
# SETUP CHECKS
# ══════════════════════════════════════════════════════════════

def check_setup() -> None:
    """Warn about missing API key before starting."""
    if not os.environ.get("GROQ_API_KEY"):
        console.print(Panel(
            "[yellow]GROQ_API_KEY not set — AI analysis will be skipped.[/yellow]\n\n"
            "To enable free AI:\n"
            "  1. Go to [bold]https://console.groq.com[/bold] → Sign up (free)\n"
            "  2. Create an API key\n"
            "  3. Run: [bold cyan]export GROQ_API_KEY='gsk_...'[/bold cyan]\n"
            "  4. Add to [bold]~/.bashrc[/bold] to make permanent",
            title="[bold yellow]⚠  Groq API Key Missing[/bold yellow]",
            border_style="yellow"
        ))


# ══════════════════════════════════════════════════════════════
# SCAN PROFILE
# ══════════════════════════════════════════════════════════════

PROFILES = {
    "1": ("-F --open",               "Quick      — Top 100 ports (fast)"),
    "2": ("--top-ports 1000 --open", "Standard   — Top 1000 ports"),
    "3": ("-p- --open",              "Full       — All 65535 ports (slow)"),
    "4": ("-sV -sC -O --open",       "Service    — Version + OS detection ← recommended"),
    "5": ("-sS -O --open",           "Stealth    — SYN scan (requires root)"),
}

def get_scan_profile() -> tuple:
    console.print("\n[bold yellow]Select Scan Profile:[/bold yellow]")
    for k, (_, label) in PROFILES.items():
        console.print(f"  [cyan]{k}[/cyan]  {label}")
    choice = console.input("\n[bold]Choice [1-5] (default 4): [/bold]").strip() or "4"
    args, label = PROFILES.get(choice, PROFILES["4"])
    console.print(f"[dim]  → {label}[/dim]")
    return args, label


# ══════════════════════════════════════════════════════════════
# NMAP SCAN
# ══════════════════════════════════════════════════════════════

def run_scan(target: str, scan_args: str) -> dict:
    nm = nmap.PortScanner()

    console.print(f"\n[bold green][*] Target    :[/bold green] {target}")
    console.print(f"[bold green][*] Command   :[/bold green] nmap {scan_args} {target}\n")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
        p.add_task("Scanning...", total=None)
        nm.scan(hosts=target, arguments=scan_args)

    results = {
        "target":       target,
        "scan_time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nmap_version": ".".join(str(v) for v in nm.nmap_version()),
        "hosts":        []
    }

    for host in nm.all_hosts():
        host_data = {
            "ip":         host,
            "hostname":   nm[host].hostname(),
            "state":      nm[host].state(),
            "os_matches": [],
            "open_ports": []
        }

        for os_match in nm[host].get("osmatch", [])[:2]:
            host_data["os_matches"].append({
                "name":     os_match["name"],
                "accuracy": os_match["accuracy"]
            })

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                info = nm[host][proto][port]
                if info["state"] == "open":
                    host_data["open_ports"].append({
                        "port":      port,
                        "protocol":  proto,
                        "state":     info["state"],
                        "service":   info.get("name", "unknown"),
                        "version":   info.get("version", ""),
                        "product":   info.get("product", ""),
                        "extrainfo": info.get("extrainfo", ""),
                        "cpe":       info.get("cpe", "")
                    })

        results["hosts"].append(host_data)

    return results


# ══════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════

def display_scan_results(scan_results: dict) -> None:
    for host in scan_results["hosts"]:
        console.print(Panel(
            f"[bold white]IP        :[/bold white] {host['ip']}\n"
            f"[bold white]Hostname  :[/bold white] {host['hostname'] or 'N/A'}\n"
            f"[bold white]State     :[/bold white] [green]{host['state']}[/green]\n"
            f"[bold white]Open Ports:[/bold white] {len(host['open_ports'])}",
            title="[bold cyan]Host[/bold cyan]",
            border_style="cyan"
        ))

        if host["os_matches"]:
            console.print("[bold yellow]OS Detection:[/bold yellow]")
            for os_m in host["os_matches"]:
                console.print(f"  → {os_m['name']}  ({os_m['accuracy']}% accuracy)")

        if host["open_ports"]:
            t = Table(border_style="green", show_lines=False, expand=False)
            t.add_column("PORT",    style="cyan",   width=12)
            t.add_column("SERVICE", style="yellow", width=12)
            t.add_column("VERSION", style="white",  width=28)
            t.add_column("EXTRA",   style="dim",    width=22)
            for p in host["open_ports"]:
                ver = f"{p['product']} {p['version']}".strip()
                t.add_row(f"{p['port']}/{p['protocol']}", p["service"], ver or "Unknown", p["extrainfo"] or "—")
            console.print(t)
        else:
            console.print("[red]  No open ports found.[/red]")


def display_cve_results(cve_map: dict) -> None:
    if not any(cves for cves in cve_map.values()):
        console.print("[yellow]  No CVEs matched for scanned services.[/yellow]")
        return

    for port_key, cves in cve_map.items():
        if not cves:
            continue
        console.print(f"\n[bold white]── {port_key} ──[/bold white]")
        for c in cves:
            color = severity_color(c["cvss_severity"])
            console.print(
                f"  [bold cyan]{c['cve_id']}[/bold cyan]  "
                f"CVSS [bold]{c['cvss_score']}[/bold] ({c['cvss_version']})  "
                f"[{color}]{c['cvss_severity']}[/{color}]  "
                f"[dim]{c['published']}[/dim]"
            )
            console.print(f"  [dim]{c['description']}[/dim]")
            console.print(f"  [blue underline]{c['url']}[/blue underline]\n")


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    console.print(BANNER)
    check_setup()

    # ── Target ────────────────────────────────────────────────
    target = console.input("\n[bold yellow]Enter target IP / hostname / range: [/bold yellow]").strip()
    if not target:
        console.print("[red]No target provided. Exiting.[/red]")
        sys.exit(1)

    scan_args, _ = get_scan_profile()

    # ── Nmap Scan ─────────────────────────────────────────────
    scan_results = run_scan(target, scan_args)

    console.rule("[bold cyan]SCAN RESULTS[/bold cyan]")
    display_scan_results(scan_results)

    # ── CVE Lookup ────────────────────────────────────────────
    console.rule("[bold red]CVE LOOKUP[/bold red]")
    cve_map = {}

    if console.input("\n[bold yellow]Run CVE lookup on open ports? (y/n): [/bold yellow]").strip().lower() == "y":
        cve_map = run_cve_lookup_for_scan(scan_results)
        console.rule("[dim]CVE Details[/dim]")
        display_cve_results(cve_map)

    # ── Manual CVE ID lookup ──────────────────────────────────
    if console.input("[bold yellow]Look up a specific CVE ID? (y/n): [/bold yellow]").strip().lower() == "y":
        cve_id = console.input("[bold]Enter CVE ID (e.g. CVE-2021-44228): [/bold]").strip()
        result = lookup_cve_by_id(cve_id)
        if result:
            color = severity_color(result["cvss_severity"])
            console.print(Panel(
                f"[bold cyan]{result['cve_id']}[/bold cyan]\n\n"
                f"[white]{result['description']}[/white]\n\n"
                f"[dim]CVSS   :[/dim] [{color}]{result['cvss_score']} ({result['cvss_severity']}) {result['cvss_version']}[/{color}]\n"
                f"[dim]Published:[/dim] {result['published']}  [dim]Modified:[/dim] {result['modified']}\n"
                f"[dim]URL    :[/dim] [blue]{result['url']}[/blue]",
                title="[bold red]CVE Details[/bold red]",
                border_style="red"
            ))
        else:
            console.print(f"[red][!] '{cve_id}' not found or lookup failed.[/red]")

    # ── AI Analysis (Groq — FREE) ─────────────────────────────
    console.rule("[bold magenta]AI ANALYSIS  [dim](Groq · LLaMA 3.3 70B · FREE)[/dim][/bold magenta]")
    ai_report = None

    if not os.environ.get("GROQ_API_KEY"):
        console.print("[yellow][!] Skipping AI — GROQ_API_KEY not set.[/yellow]")
    else:
        if console.input("\n[bold yellow]Run Groq AI analysis? (y/n): [/bold yellow]").strip().lower() == "y":
            console.print("[cyan][*] Sending data to Groq LLaMA 3.3 70B...[/cyan]")
            ai_report = analyze_with_ai(scan_results, cve_map)

            if ai_report.startswith("[ERROR]"):
                console.print(f"[red]{ai_report}[/red]")
                ai_report = None
            else:
                console.print(Panel(
                    ai_report,
                    title="[bold magenta]🤖 Groq AI — LLaMA 3.3 70B Security Analysis[/bold magenta]",
                    border_style="magenta"
                ))

    # ── HTML Report ───────────────────────────────────────────
    console.rule("[bold green]REPORT[/bold green]")
    if console.input("\n[bold yellow]Generate HTML report? (y/n): [/bold yellow]").strip().lower() == "y":
        report_path = generate_report(scan_results, ai_report, cve_map)
        console.print(f"\n[bold green][✓] Report saved :[/bold green] {report_path}")
        console.print(f"[dim]    Open it     : xdg-open {report_path}[/dim]")

    console.print("\n[bold cyan][✓] SmartScan complete. Stay legal, stay ethical![/bold cyan]\n")


if __name__ == "__main__":
    main()
