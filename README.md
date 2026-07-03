# ⚡ SmartScan v2.0 — AI-Powered Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI-Groq%20LLaMA%203.3%2070B-orange?style=for-the-badge&logo=meta&logoColor=white"/>
  <img src="https://img.shields.io/badge/CVE-NIST%20NVD%20API-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tool-Nmap-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-black?style=for-the-badge&logo=kalilinux&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge"/>
</p>

<p align="center">
  <a href="https://github.com/omkarsawant1337">
    <img src="https://img.shields.io/badge/GitHub-omkarsawant1337-181717?style=flat-square&logo=github"/>
  </a>
  <a href="https://www.linkedin.com/in/omkar-sawant-vapt">
    <img src="https://img.shields.io/badge/LinkedIn-omkar--sawant--vapt-0077B5?style=flat-square&logo=linkedin"/>
  </a>
</p>

<p align="center">
  <b>Network recon · CVE lookup · Free AI analysis · HTML report — all in one CLI tool.</b><br>
  Built for ethical penetration testing and security research on Kali Linux.
</p>

---

## 👤 Author

| | |
|---|---|
| **Name** | Omkar Sawant |
| **GitHub** | [github.com/omkarsawant1337](https://github.com/omkarsawant1337) |
| **LinkedIn** | [linkedin.com/in/omkar-sawant-vapt](https://www.linkedin.com/in/omkar-sawant-vapt) |
| **AI Engine** | Groq LLaMA 3.3 70B — 100% FREE, no credit card |
| **Platform** | Kali Linux |

---

## 🖥️ Screenshots

### 1. Banner & Scan Start
<!-- Add screenshot: screenshots/1_banner.png -->
![Banner](screenshots/1_banner.png)

---

### 2. Port Scan Results
<!-- Add screenshot: screenshots/2_ports.png -->
![Port Scan](screenshots/2_ports.png)

---

### 3. CVE Lookup
<!-- Add screenshot: screenshots/3_cve.png -->
![CVE Lookup](screenshots/3_cve.png)

---

### 4. Groq AI Analysis
<!-- Add screenshot: screenshots/4_ai.png -->
![AI Analysis](screenshots/4_ai.png)

---

### 5. HTML Report (Browser)
<!-- Add screenshot: screenshots/5_report.png -->
![HTML Report](screenshots/5_report.png)

---

## 🎯 What It Does

SmartScan is a CLI-based port scanner that combines **Nmap**, **NIST NVD CVE database**, and **Groq AI (LLaMA 3.3 70B)** to automate the vulnerability assessment workflow that security professionals perform manually.

```
Target IP → Nmap Scan → CVE Lookup (NVD) → AI Analysis (Groq) → HTML Report
```

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔍 **Port Scanning** | Nmap with 5 configurable scan profiles |
| 🔴 **CVE Lookup** | NIST NVD API v2 — free, no API key, per open port |
| 🤖 **AI Analysis** | Groq LLaMA 3.3 70B — executive summary, attack chain, Metasploit modules |
| 📊 **HTML Report** | Professional dark-theme report with all findings |
| 🖥️ **Rich CLI** | Colored output, tables, progress bars via Rich library |
| 🔎 **Manual CVE Lookup** | Look up any CVE ID directly from the CLI |

---

## 🖥️ Demo — Real Scan on Metasploitable 2

### Port Scan Results
```
[*] Target    : 192.168.10.9
[*] Command   : nmap -sV -sC -O --open 192.168.10.9

Host: 192.168.10.9  |  State: up  |  Open Ports: 23
OS Detection: Linux 2.6.9 - 2.6.33 (100% accuracy)

┏━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ PORT       ┃ SERVICE     ┃ VERSION                      ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 21/tcp     │ ftp         │ vsftpd 2.3.4                 │  ← CVE-2011-2523 CRITICAL
│ 22/tcp     │ ssh         │ OpenSSH 4.7p1 Debian         │
│ 23/tcp     │ telnet      │ Linux telnetd                │
│ 25/tcp     │ smtp        │ Postfix smtpd                │
│ 53/tcp     │ domain      │ ISC BIND 9.4.2               │  ← CVE-2008-0122 HIGH
│ 80/tcp     │ http        │ Apache httpd 2.2.8           │
│ 139/tcp    │ netbios-ssn │ Samba smbd 3.X - 4.X         │
│ 445/tcp    │ netbios-ssn │ Samba smbd 3.0.20-Debian     │
│ 1524/tcp   │ bindshell   │ Metasploitable root shell    │  ← CRITICAL
│ 3306/tcp   │ mysql       │ MySQL 5.0.51a-3ubuntu5       │
│ 5432/tcp   │ postgresql  │ PostgreSQL DB 8.3.0 - 8.3.7  │
│ 5900/tcp   │ vnc         │ VNC protocol 3.3             │
│ 6667/tcp   │ irc         │ UnrealIRCd                   │
│ 8180/tcp   │ http        │ Apache Tomcat/Coyote JSP 1.1 │
└────────────┴─────────────┴──────────────────────────────┘
```

### CVE Lookup Results
```
[*] CVE lookup for 23 open port(s) via NVD API...

  [1/23]  Port 21 → vsftpd 2.3.4
          ↳ CVE-2011-2523  CVSS 9.8  CRITICAL  (1 found)

  [2/23]  Port 22 → OpenSSH
          ↳ CVE-1999-0661  CVSS 10.0  HIGH  (5 found)

  [3/23]  Port 23 → Linux telnetd
          ↳ CVE-2000-1195  CVSS 7.5  HIGH  (4 found)

  [5/23]  Port 53 → ISC BIND 9.4.2
          ↳ CVE-2008-0122  CVSS 10.0  HIGH  (2 found)

── 192.168.10.9:21 ──
  CVE-2011-2523  CVSS 9.8 (v3.1)  CRITICAL
  vsftpd 2.3.4 contains a backdoor which opens a shell on port 6200/tcp.
  https://nvd.nist.gov/vuln/detail/CVE-2011-2523
```

### Groq AI Analysis (LLaMA 3.3 70B)
```
1. EXECUTIVE SUMMARY
   Risk Level : CRITICAL
   CVE-2011-2523 (vsftpd backdoor) allows full remote code execution.
   23 open ports detected — massive attack surface.

2. CRITICAL CVEs TO PRIORITIZE
   • CVE-2011-2523 — vsftpd backdoor → shell on port 6200/tcp
   • CVE-2008-0122 — ISC BIND off-by-one → DoS / code execution
   • CVE-2000-1169 — OpenSSH X11 forwarding → event sniffing

3. ATTACK CHAIN
   Step 1 → Exploit CVE-2011-2523 (vsftpd) on Port 21
   Step 2 → Gain shell via port 6200/tcp
   Step 3 → Pivot to Samba (Port 445) for lateral movement
   Step 4 → Use bindshell (Port 1524) for persistent access

4. EXPLOITATION GUIDANCE
   msf > use exploit/unix/ftp/vsftpd_234_backdoor
   msf > set RHOSTS 192.168.10.9
   msf > run

5. REMEDIATION PRIORITY
   1. Patch vsftpd → remove backdoored version immediately
   2. Disable telnetd → enforce SSH only
   3. Patch ISC BIND → CVE-2008-0122
   4. Firewall Samba ports 139/445 from external access
```

---

## 📁 Project Structure

```
SmartScan/
├── smartscan.py        # Main entry point — scan flow, menus, display
├── ai_analyzer.py      # Groq API integration (LLaMA 3.3 70B)
├── cve_lookup.py       # NIST NVD API v2 CVE lookup (free)
├── report_gen.py       # Dark-theme HTML report generator
├── requirements.txt    # Python dependencies
├── screenshots/        # Demo screenshots (for README)
└── reports/            # Generated HTML reports (auto-created)
```

---

## 🚀 Setup on Kali Linux

```bash
# 1. Clone the repo
git clone https://github.com/omkarsawant1337/SmartScan.git
cd SmartScan

# 2. Install system dependency
sudo apt install nmap -y

# 3. Create virtual environment
python3 -m venv venv && source venv/bin/activate

# 4. Install Python packages
pip install -r requirements.txt

# 5. Get FREE Groq API key (no credit card)
#    → https://console.groq.com
#    → Sign up → API Keys → Create Key

# 6. Create launcher script
cat > run.sh << 'EOF'
#!/bin/bash
sudo env GROQ_API_KEY="gsk_YOUR_KEY_HERE" /home/kali/SmartScan/venv/bin/python3 /home/kali/SmartScan/smartscan.py
EOF
chmod +x run.sh
sudo ln -sf $(pwd)/run.sh /usr/local/bin/smartscan

# 7. Run from anywhere
smartscan
```

---

## 🎛️ Scan Profiles

| # | Profile | Nmap Args | Best For |
|---|---|---|---|
| 1 | Quick | `-F --open` | Fast initial recon |
| 2 | Standard | `--top-ports 1000 --open` | General enumeration |
| 3 | Full | `-p- --open` | Thorough coverage |
| **4** | **Service ★** | **`-sV -sC -O --open`** | **Best for CVE matching** |
| 5 | Stealth | `-sS -O --open` | Evade basic detection |

---

## 🔄 Tool Flow

```
┌─────────────────────────────────────────────────┐
│                 SmartScan v2.0                  │
└─────────────────────────────────────────────────┘
              │
              ▼
   ┌─────────────────────┐
   │     Nmap Scan       │  5 profiles · version/OS detection
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │    CVE Lookup       │  NIST NVD API v2 · CVSS v3.1 · per port
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │  Groq AI (FREE)     │  LLaMA 3.3 70B · attack chain · Metasploit
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────┐
   │    HTML Report      │  Dark theme · CVE table · AI section
   └─────────────────────┘
```

---

## 🆓 Groq Free Tier

| Model | Requests/min | Requests/day | Cost |
|---|---|---|---|
| LLaMA 3.3 70B Versatile | 30 | 6,000 | **$0.00** |

Sign up at [console.groq.com](https://console.groq.com) — no credit card, no billing.

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Port Scanner | Nmap + python-nmap |
| CVE Database | NIST NVD API v2 (free) |
| AI Engine | Groq API — LLaMA 3.3 70B (free) |
| CLI UI | Rich (tables, panels, progress bars) |
| HTTP Client | Requests |
| Report Output | Pure HTML/CSS (dark theme) |
| Platform | Kali Linux / Python 3.x |

---

## 📋 Skills Demonstrated

| Skill | Implementation |
|---|---|
| Network Reconnaissance | Nmap with 5 configurable profiles |
| Vulnerability Assessment | CVSS v3.1 scoring via NVD API |
| CVE Research | Real-time NVD database queries per open service |
| AI / LLM Integration | Groq REST API with structured prompt engineering |
| Python Development | Modular, clean, production-style architecture |
| Security Reporting | Auto-generated professional HTML reports |

---

## ⚠️ Legal Disclaimer

This tool is for **authorized** penetration testing and **educational purposes only**.  
Always obtain **written permission** before scanning any target.  
Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.  
The author is not responsible for any misuse of this tool.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/omkarsawant1337"><b>Omkar Sawant</b></a>
  &nbsp;|&nbsp;
  <a href="https://www.linkedin.com/in/omkar-sawant-vapt">LinkedIn</a>
  &nbsp;|&nbsp;
  <a href="https://github.com/omkarsawant1337">GitHub</a>
</p>
