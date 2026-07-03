"""
HTML Report Generator — SmartScan v2.0
Produces a professional dark-theme security report
Author: Omkar Sawant | github.com/omkarsawant1337
"""

import os
import re
from datetime import datetime


def generate_report(scan_results: dict, ai_analysis: str = None, cve_map: dict = None) -> str:
    """Generate full HTML security report, save to reports/ folder, return file path."""

    os.makedirs("reports", exist_ok=True)
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = scan_results["target"].replace("/", "_").replace(".", "-")
    filepath    = f"reports/smartscan_{safe_target}_{ts}.html"

    total_hosts = len(scan_results["hosts"])
    total_open  = sum(len(h["open_ports"]) for h in scan_results["hosts"])
    total_cves  = sum(len(v) for v in (cve_map or {}).values())

    port_rows   = _build_port_rows(scan_results)
    cve_section = _build_cve_section(cve_map, total_cves)
    ai_section  = _build_ai_section(ai_analysis)
    host_cards  = _build_host_cards(scan_results)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartScan Report — {scan_results['target']}</title>
<style>
:root {{
  --bg:      #070e1a;
  --surface: #0c1524;
  --card:    #0f1b2d;
  --border:  #172840;
  --cyan:    #00d4ff;
  --purple:  #a78bfa;
  --red:     #f87171;
  --orange:  #fb923c;
  --yellow:  #fbbf24;
  --green:   #4ade80;
  --dim:     #3d5470;
  --text:    #c8d8ea;
  --muted:   #7a90a8;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:28px 40px;font-size:13.5px;line-height:1.65}}

/* ── HEADER ── */
.header{{
  background:linear-gradient(135deg,#081428 0%,#100720 100%);
  border:1px solid var(--cyan);border-radius:12px;
  padding:34px 40px;text-align:center;margin-bottom:22px;
  position:relative;overflow:hidden;
}}
.header::before{{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% -10%,rgba(0,212,255,.1) 0%,transparent 65%);
}}
.header h1{{
  font-size:3em;letter-spacing:10px;color:var(--cyan);
  text-shadow:0 0 30px rgba(0,212,255,.45);position:relative;
}}
.header .sub{{color:var(--purple);letter-spacing:4px;font-size:.8em;margin-top:7px;position:relative}}
.header .meta{{color:var(--muted);font-size:.78em;margin-top:14px;position:relative}}
.header .meta b{{color:var(--text)}}
.groq-badge{{
  display:inline-block;margin-top:10px;
  background:rgba(251,146,60,.12);border:1px solid rgba(251,146,60,.4);
  color:var(--orange);font-size:.72em;padding:3px 14px;border-radius:99px;
  letter-spacing:1px;position:relative;
}}

/* ── STAT GRID ── */
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}}
.stat-card{{
  background:var(--card);border:1px solid var(--border);
  border-radius:9px;padding:20px 14px;text-align:center;
  transition:border-color .2s,transform .15s;
}}
.stat-card:hover{{border-color:var(--cyan);transform:translateY(-2px)}}
.stat-card .val{{font-size:2.3em;font-weight:700;color:var(--cyan)}}
.stat-card .lbl{{font-size:.68em;color:var(--dim);letter-spacing:2px;margin-top:5px}}

/* ── CARDS ── */
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:24px 28px;margin-bottom:18px}}
.card-title{{
  font-size:.92em;letter-spacing:2px;
  border-bottom:1px solid var(--border);
  padding-bottom:12px;margin-bottom:18px;
  display:flex;align-items:center;gap:12px;
}}
.t-cyan  {{color:var(--cyan)}}
.t-red   {{color:var(--red)}}
.t-purple{{color:var(--purple)}}
.t-green {{color:var(--green)}}
.badge{{
  font-size:.68em;padding:2px 10px;border-radius:99px;
  letter-spacing:0;font-weight:600;
}}
.badge-red   {{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.35);color:var(--red)}}
.badge-purple{{background:rgba(167,139,250,.12);border:1px solid rgba(167,139,250,.35);color:var(--purple)}}
.badge-cyan  {{background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:var(--cyan)}}

/* ── HOST BLOCKS ── */
.host-block{{
  background:#09111f;border:1px solid var(--border);
  border-radius:7px;padding:14px 18px;margin-bottom:12px;font-size:.88em;
}}
.hl{{color:var(--muted)}}
.hv{{color:var(--text)}}

/* ── TABLE ── */
table{{width:100%;border-collapse:collapse}}
th{{
  background:#08111e;color:var(--cyan);
  padding:10px 14px;text-align:left;
  font-size:.76em;letter-spacing:1.5px;
  border-bottom:1px solid var(--border);
}}
td{{padding:9px 14px;border-bottom:1px solid #0e1a2b;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(0,212,255,.025)}}

/* ── BADGES & RISK ── */
.port-badge{{
  background:#071525;border:1px solid var(--cyan);
  color:var(--cyan);padding:2px 9px;border-radius:4px;font-size:.8em;white-space:nowrap;
}}
.risk-CRITICAL{{color:var(--red);font-weight:700}}
.risk-HIGH    {{color:var(--orange);font-weight:700}}
.risk-MEDIUM  {{color:var(--yellow)}}
.risk-LOW     {{color:var(--green)}}
.risk-INFO    {{color:#60a5fa}}
.dim-text{{color:var(--muted);font-size:.86em}}
.empty-row{{text-align:center;color:var(--dim);padding:20px}}
.cve-link{{color:var(--cyan);text-decoration:none}}
.cve-link:hover{{text-decoration:underline}}

/* ── AI SECTION ── */
.card-ai{{border-color:rgba(167,139,250,.25)}}
.ai-content{{color:#c4b5fd;font-size:.88em;line-height:1.9;white-space:pre-wrap}}
.ai-content strong{{color:#e9d5ff}}

/* ── FOOTER ── */
footer{{
  text-align:center;color:var(--dim);font-size:.74em;
  margin-top:28px;padding-top:16px;border-top:1px solid var(--border);
}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <h1>⚡ SMARTSCAN</h1>
  <p class="sub">AI-POWERED PORT SCANNER &amp; VULNERABILITY ANALYZER</p>
  <div class="groq-badge">🤖 AI Powered by Groq — LLaMA 3.3 70B (FREE)</div>
  <p class="meta">
    Target: <b>{scan_results['target']}</b> &nbsp;|&nbsp;
    Scan Time: <b>{scan_results['scan_time']}</b> &nbsp;|&nbsp;
    Author: <b>Omkar Sawant</b> &nbsp;|&nbsp;
    <a href="https://github.com/omkarsawant1337" style="color:var(--cyan)">github.com/omkarsawant1337</a>
  </p>
</div>

<!-- STATS -->
<div class="stat-grid">
  <div class="stat-card"><div class="val">{total_hosts}</div><div class="lbl">HOSTS SCANNED</div></div>
  <div class="stat-card"><div class="val">{total_open}</div><div class="lbl">OPEN PORTS</div></div>
  <div class="stat-card"><div class="val">{total_cves}</div><div class="lbl">CVEs FOUND</div></div>
  <div class="stat-card"><div class="val">{'YES' if ai_analysis and not ai_analysis.startswith('[ERROR]') else 'NO'}</div><div class="lbl">AI ANALYSIS</div></div>
</div>

<!-- HOST INFO -->
<div class="card">
  <h2 class="card-title t-cyan">📡 HOST INFORMATION <span class="badge badge-cyan">{total_hosts} hosts</span></h2>
  {host_cards}
</div>

<!-- OPEN PORTS -->
<div class="card">
  <h2 class="card-title t-cyan">🔌 OPEN PORTS <span class="badge badge-cyan">{total_open} ports</span></h2>
  <table>
    <thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th><th>RISK</th><th>EXTRA INFO</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>
</div>

<!-- CVE FINDINGS -->
{cve_section}

<!-- AI ANALYSIS -->
{ai_section}

<footer>
  SmartScan v2.0 &nbsp;·&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;·&nbsp;
  AI: Groq LLaMA 3.3 70B (Free) &nbsp;·&nbsp;
  For <strong>authorized</strong> penetration testing only. Unauthorized use is illegal.
</footer>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


# ─────────────────────────────────────────────────────────────
# SECTION BUILDERS
# ─────────────────────────────────────────────────────────────

def _port_risk(port: int) -> str:
    if port in {21, 23, 445, 3389, 5900, 2121, 512, 513, 514}:
        return "CRITICAL"
    if port in {22, 80, 443, 3306, 5432, 6379, 27017, 1433, 8080, 9200}:
        return "HIGH"
    if port in {25, 53, 110, 143, 161, 8443, 11211, 2049, 111}:
        return "MEDIUM"
    return "LOW"


def _build_host_cards(scan_results: dict) -> str:
    out = ""
    for h in scan_results["hosts"]:
        os_line = ""
        if h.get("os_matches"):
            os_line = f'<br><span class="hl">OS Guess  : </span><span class="hv">{h["os_matches"][0]["name"]} ({h["os_matches"][0]["accuracy"]}% accuracy)</span>'
        out += f"""
        <div class="host-block">
          <span class="hl">IP        : </span><span class="hv">{h['ip']}</span><br>
          <span class="hl">Hostname  : </span><span class="hv">{h['hostname'] or 'N/A'}</span><br>
          <span class="hl">State     : </span><span style="color:var(--green)">{h['state']}</span><br>
          <span class="hl">Open Ports: </span><span class="hv">{len(h['open_ports'])}</span>{os_line}
        </div>"""
    return out or '<p class="empty-row">No hosts found.</p>'


def _build_port_rows(scan_results: dict) -> str:
    rows = ""
    for host in scan_results["hosts"]:
        for p in host["open_ports"]:
            risk    = _port_risk(p["port"])
            version = f"{p.get('product','')} {p.get('version','')}".strip() or "Unknown"
            rows += f"""
            <tr>
              <td><span class="port-badge">{p['port']}/{p['protocol']}</span></td>
              <td>{p['service']}</td>
              <td>{version}</td>
              <td><span class="risk-{risk}">{risk}</span></td>
              <td class="dim-text">{p.get('extrainfo','') or '—'}</td>
            </tr>"""
    return rows or '<tr><td colspan="5" class="empty-row">No open ports detected</td></tr>'


def _build_cve_section(cve_map: dict, total_cves: int) -> str:
    if not cve_map or total_cves == 0:
        return ""

    rows = ""
    for port_key, cves in cve_map.items():
        for c in cves:
            sev  = c.get("cvss_severity", "N/A")
            risk_cls = f"risk-{sev}" if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "risk-INFO"
            desc = c.get("description", "")
            short_desc = desc[:220] + ("..." if len(desc) > 220 else "")
            rows += f"""
            <tr>
              <td><a href="{c['url']}" target="_blank" class="cve-link">{c['cve_id']}</a></td>
              <td><span class="port-badge">{port_key}</span></td>
              <td><span class="{risk_cls}">{c.get('cvss_score','N/A')}</span></td>
              <td><span class="{risk_cls}">{sev}</span></td>
              <td class="dim-text" style="font-size:.8em">{short_desc}</td>
            </tr>"""

    return f"""
    <div class="card">
      <h2 class="card-title t-red">🔴 CVE FINDINGS <span class="badge badge-red">{total_cves} CVEs</span></h2>
      <table>
        <thead><tr><th>CVE ID</th><th>PORT</th><th>CVSS SCORE</th><th>SEVERITY</th><th>DESCRIPTION</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _build_ai_section(ai_analysis: str) -> str:
    if not ai_analysis or ai_analysis.startswith("[ERROR]"):
        return ""

    # Convert **bold** markdown → <strong>
    formatted = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', ai_analysis)
    formatted = formatted.replace("\n", "<br>")

    return f"""
    <div class="card card-ai">
      <h2 class="card-title t-purple">
        🤖 AI SECURITY ANALYSIS
        <span class="badge badge-purple">Groq · LLaMA 3.3 70B · FREE</span>
      </h2>
      <div class="ai-content">{formatted}</div>
    </div>"""
