# 🔴 AI-Driven Red Team Simulation Framework

A production-ready offensive security simulation platform that autonomously models a complete attack lifecycle — from reconnaissance through exploitation, privilege escalation, and persistence — using real tools and MITRE ATT&CK mappings.

---

## Architecture

```
redteam/
├── core/                    # Engine & orchestration
│   ├── engine.py            # Main orchestration engine
│   ├── attack_lifecycle.py  # Phase state machine & data structures
│   ├── event_bus.py         # Async pub/sub event system
│   └── plugin_loader.py     # Dynamic module discovery
├── recon/                   # Reconnaissance modules
│   ├── subdomain_enum.py    # DNS brute-force + crt.sh CT logs
│   ├── port_scanner.py      # Nmap wrapper with async scanning
│   ├── vuln_scanner.py      # NVD API + searchsploit integration
│   ├── web_recon.py         # Directory brute-force + tech detection
│   └── os_fingerprint.py    # Nmap OS detect + banner grabbing
├── exploit/                 # Exploitation modules
│   ├── exploit_selector.py  # AI-driven exploit scoring engine
│   ├── brute_force.py       # Hydra wrapper + Python SSH/FTP fallback
│   ├── web_exploits.py      # SQLi/XSS/CMDi/LFI + SQLMap
│   └── cve_exploits.py      # EternalBlue, Log4Shell, Shellshock
├── post_exploit/            # Post-exploitation modules
│   ├── priv_escalation.py   # Linux SUID/sudo + Windows UAC/token
│   ├── lateral_movement.py  # Subnet scan + credential reuse
│   ├── persistence.py       # Cron/SSH/registry/services
│   └── credential_harvest.py# Shadow/LSASS/SAM/browser/cloud
├── mitre/                   # MITRE ATT&CK integration
│   ├── attack_map.py        # ~50 technique database
│   └── navigator.py         # ATT&CK Navigator layer export
├── reporting/               # Report generation
│   ├── attack_graph.py      # NetworkX graph → JSON/DOT/PNG
│   └── report_generator.py  # Dark-themed HTML report (Jinja2)
├── dashboard/               # Real-time monitoring
│   └── server.py            # Flask + SocketIO web dashboard
├── cli.py                   # CLI entry point
└── config.py                # YAML configuration loader
```

## Features

### 🔍 Reconnaissance
- **Subdomain Enumeration** — DNS brute-force with built-in wordlist + Certificate Transparency log queries via crt.sh
- **Port Scanning** — Full Nmap integration with service version detection, or pure-Python socket fallback
- **Vulnerability Scanning** — NVD CVE database queries + local searchsploit integration
- **Web Reconnaissance** — Directory brute-forcing, technology fingerprinting (Wappalyzer-style), robots.txt parsing
- **OS Fingerprinting** — Nmap OS detection + TCP/IP stack analysis + banner grabbing

### 💥 Exploitation
- **Intelligent Exploit Selection** — Scores and prioritizes exploits based on CVSS, service versions, and known high-value CVE patterns
- **Credential Brute Force** — Hydra wrapper with Python fallbacks for SSH (paramiko) and FTP (ftplib)
- **Web Application Attacks** — SQL injection, XSS, command injection, LFI/RFI testing with SQLMap integration
- **CVE Exploits** — Real vulnerability checks for EternalBlue (MS17-010), Log4Shell, Shellshock, and more

### 🔓 Post-Exploitation
- **Privilege Escalation** — Linux (SUID binaries, sudo misconfigs, kernel exploits like DirtyCow/DirtyPipe) and Windows (UAC bypass, token impersonation, DLL hijacking)
- **Lateral Movement** — Internal subnet discovery, SSH/SMB credential reuse, pass-the-hash analysis
- **Persistence** — Identifies mechanisms: cron jobs, SSH keys, systemd services, registry run keys, scheduled tasks, WMI subscriptions
- **Credential Harvesting** — Maps credential stores: /etc/shadow, LSASS, SAM, Kerberos tickets, browser passwords, cloud credentials

### 📊 Reporting & Visualization
- **Attack Path Graph** — NetworkX-powered directed graph exported as JSON (D3.js), DOT (Graphviz), and PNG
- **HTML Security Report** — Professional dark-themed report with executive summary, risk matrix, vulnerability table, attack timeline, MITRE ATT&CK coverage grid, and remediation recommendations
- **Real-Time Dashboard** — Flask + SocketIO web dashboard with live event feed, phase progression bar, target status tracking

### 🛡️ MITRE ATT&CK
- ~50 techniques mapped across all attack phases
- ATT&CK Navigator layer export for visualization
- Every attack step tagged with technique IDs

---

## Installation

```bash
# Clone the repository
git clone https://github.com/apocalypse9949/Redteam-Automation.git
cd Redteam-Automation

# Install in development mode
pip install -e .

# Optional: Install external tools for full functionality
# - nmap (port scanning, OS detection)
# - hydra (credential brute-force)
# - sqlmap (SQL injection)
# - gobuster (directory brute-force)
# - searchsploit (local exploit database)
```

## Usage

```bash
# Basic scan against a single target
redteam scan 192.168.1.1

# Full scan with real-time dashboard
redteam scan 10.0.0.0/24 --full --dashboard --verbose

# Scan specific phases only
redteam scan target.com --phases recon,exploit --output ./results

# Custom engagement name and log file
redteam scan 192.168.1.1 --engagement-name "Q1 Assessment" --log-file scan.log

# Generate report from previous engagement data
redteam report ./output/engagement_data.json
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to YAML config file (default: `config.yaml`) |
| `--output, -o` | Output directory for reports (default: `./output`) |
| `--phases` | Comma-separated phases to run (default: all) |
| `--full` | Run all phases including post-exploitation |
| `--dashboard` | Start real-time web dashboard |
| `--dashboard-port` | Dashboard port (default: 5000) |
| `--verbose, -v` | Enable debug logging |
| `--log-file` | Log to file in addition to console |
| `--engagement-name` | Custom name for the engagement |

---

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
general:
  engagement_name: "RedTeam Assessment"
  output_dir: "./output"

recon:
  dns_wordlist: null        # Path to DNS wordlist (uses built-in)
  port_range: "1-1024"      # Nmap port range
  scan_speed: 4             # Nmap timing (1-5)
  use_crtsh: true           # Query Certificate Transparency logs

exploit:
  min_cvss: 5.0             # Minimum CVSS score for exploitation
  brute_timeout: 10         # Per-attempt timeout in seconds
  max_brute_attempts: 100   # Max credential attempts per service

dashboard:
  enabled: false
  port: 5000
```

---

## Attack Lifecycle

The framework follows a structured phase-based attack lifecycle:

```
INIT → RECON → SCANNING → ENUMERATION → EXPLOITATION
  → PRIVILEGE ESCALATION → LATERAL MOVEMENT → PERSISTENCE
  → CREDENTIAL ACCESS → REPORTING → COMPLETE
```

Each phase is orchestrated by the core engine with full event tracking and MITRE ATT&CK technique mapping.

---

## Output

After an engagement, the `output/` directory contains:

| File | Description |
|------|-------------|
| `security_assessment_report.html` | Full HTML report with dark theme |
| `report_data.json` | Raw engagement data in JSON |
| `attack_graph.json` | D3.js-compatible graph data |
| `attack_graph.dot` | Graphviz DOT format |
| `attack_graph.png` | Visual attack path diagram |
| `engagement_data.json` | Complete engagement state |
| `mitre_navigator_layer.json` | ATT&CK Navigator layer |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `python-nmap` | Nmap integration |
| `requests` | HTTP requests for web recon/exploitation |
| `beautifulsoup4` | HTML parsing for web exploitation |
| `flask` + `flask-socketio` | Real-time dashboard |
| `networkx` | Attack path graph generation |
| `jinja2` | HTML report templating |
| `matplotlib` | Graph PNG export |
| `pyyaml` | Configuration loading |
| `rich` | Terminal output formatting |

---

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing and research only**. Always obtain proper written authorization before scanning or testing any systems. Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical.

---

## License

MIT License
