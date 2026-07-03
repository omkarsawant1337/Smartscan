"""
AI Analysis Module — SmartScan v2.0
Uses Groq API (FREE) with LLaMA 3.3 70B model
Get free API key: https://console.groq.com
Author: Omkar Sawant | github.com/omkarsawant1337
"""

import os
import requests
from rich.console import Console

console = Console()

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"   # Best free model on Groq


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def analyze_with_ai(scan_results: dict, cve_map: dict = None) -> str:
    """
    Send scan + CVE data to Groq (LLaMA 3.3 70B) for security analysis.
    Returns the AI-generated report as a plain string.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "[ERROR] GROQ_API_KEY not set. Run: export GROQ_API_KEY='gsk_...'"

    prompt  = _build_prompt(scan_results, cve_map)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json"
    }
    payload = {
        "model":       GROQ_MODEL,
        "temperature": 0.3,
        "max_tokens":  2048,
        "messages": [
            {
                "role":    "system",
                "content": (
                    "You are a senior penetration tester and cybersecurity analyst. "
                    "Provide detailed, technical, and actionable security assessments. "
                    "Always reference specific CVE IDs, port numbers, and service versions found. "
                    "Format your response with clear numbered sections and bold headers."
                )
            },
            {
                "role":    "user",
                "content": prompt
            }
        ]
    }

    try:
        resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)

        if resp.status_code == 200:
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        elif resp.status_code == 401:
            return "[ERROR] Invalid Groq API key. Check your GROQ_API_KEY."
        elif resp.status_code == 429:
            return "[ERROR] Groq rate limit hit. Wait a moment and try again."
        else:
            return f"[ERROR] Groq API returned status {resp.status_code}: {resp.text[:200]}"

    except requests.exceptions.Timeout:
        return "[ERROR] Groq API request timed out."
    except requests.exceptions.ConnectionError:
        return "[ERROR] No internet connection to reach Groq API."
    except Exception as e:
        return f"[ERROR] Unexpected error: {e}"


def get_groq_models() -> list:
    """Return list of available free Groq models (for reference)."""
    return [
        "llama-3.3-70b-versatile",    # Best quality — recommended
        "llama-3.1-8b-instant",       # Fastest
        "mixtral-8x7b-32768",         # Large context window
        "gemma2-9b-it",               # Google Gemma 2
    ]


# ─────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────

def _build_prompt(scan_results: dict, cve_map: dict) -> str:
    scan_block = _format_scan(scan_results)
    cve_block  = _format_cves(cve_map)

    return f"""Analyze the following Nmap scan results and CVE findings. Provide a detailed security assessment.

{'═'*60}
SCAN RESULTS
{'═'*60}
{scan_block}

{cve_block}

{'═'*60}
REQUIRED ANALYSIS — provide ALL sections below:
{'═'*60}

**1. EXECUTIVE SUMMARY**
   - Overall risk level: Critical / High / Medium / Low
   - Key findings in 3-4 sentences

**2. CRITICAL CVEs TO PRIORITIZE**
   - Which CVEs pose the highest immediate risk and why
   - Reference actual CVE IDs from the data above

**3. OPEN PORT RISK ANALYSIS**
   - Per-port: service name, risk level, exploitation likelihood

**4. ATTACK CHAIN**
   - Step-by-step how an attacker could chain these vulnerabilities

**5. NMAP FOLLOW-UP COMMANDS**
   - Specific nmap commands to enumerate discovered services deeper

**6. EXPLOITATION GUIDANCE**
   - Relevant Metasploit modules (e.g. use exploit/unix/ftp/vsftpd_234_backdoor)
   - Manual exploitation steps or PoC references for top CVEs

**7. REMEDIATION PRIORITY LIST**
   - Ordered by urgency with concrete fix steps

Be specific and technical. Reference the actual ports and CVE IDs found."""


def _format_scan(scan_results: dict) -> str:
    lines = [
        f"Target    : {scan_results['target']}",
        f"Scan Time : {scan_results['scan_time']}",
        f"Hosts     : {len(scan_results['hosts'])}",
        ""
    ]
    for host in scan_results["hosts"]:
        lines.append(f"┌─ Host: {host['ip']}  ({host['hostname'] or 'no hostname'})  [{host['state']}]")
        if host.get("os_matches"):
            for os_m in host["os_matches"]:
                lines.append(f"│  OS: {os_m['name']} ({os_m['accuracy']}% accuracy)")
        if host["open_ports"]:
            lines.append(f"│  Open Ports ({len(host['open_ports'])}):")
            for p in host["open_ports"]:
                ver = f"{p.get('product','')} {p.get('version','')}".strip()
                lines.append(
                    f"│    PORT {p['port']}/{p['protocol']}  "
                    f"service={p['service']}  "
                    f"version={ver or 'unknown'}  "
                    f"extra={p.get('extrainfo','') or 'N/A'}"
                )
        else:
            lines.append("│  No open ports detected.")
        lines.append("└" + "─" * 55)
    return "\n".join(lines)


def _format_cves(cve_map: dict) -> str:
    if not cve_map:
        return ""

    lines = [f"{'═'*60}", "CVE LOOKUP RESULTS (NIST NVD)", f"{'═'*60}"]
    any_found = False

    for port_key, cves in cve_map.items():
        if not cves:
            continue
        any_found = True
        lines.append(f"\n  Port {port_key}:")
        for c in cves:
            lines.append(
                f"    [{c['cve_id']}]  "
                f"CVSS {c['cvss_score']} ({c['cvss_severity']})  "
                f"Published: {c['published']}"
            )
            lines.append(f"    {c['description'][:200]}...")

    if not any_found:
        lines.append("  No CVEs matched for scanned services.")

    return "\n".join(lines)
