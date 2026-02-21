"""
Report Generator Module.
Generates comprehensive HTML security assessment reports using Jinja2.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, BaseLoader

from redteam.core.attack_lifecycle import (
    Engagement, AttackPhase, StepStatus, Severity,
)
from redteam.mitre.attack_map import ATTACK_TECHNIQUES


logger = logging.getLogger("redteam.reporting.report_generator")


# Inline HTML template (no external file dependency)
REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ engagement.name }} - Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        /* Header */
        .report-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            border: 1px solid #333;
            border-radius: 12px;
            padding: 40px;
            margin-bottom: 30px;
            text-align: center;
        }
        .report-header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .report-header .subtitle { color: #888; font-size: 1.1em; }
        .report-header .meta {
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        .meta-item {
            background: rgba(255,255,255,0.05);
            padding: 10px 20px;
            border-radius: 8px;
            border: 1px solid #333;
        }
        .meta-item .label { color: #888; font-size: 0.85em; }
        .meta-item .value { font-weight: bold; color: #e94560; }

        /* Cards */
        .card {
            background: #1a1a2e;
            border: 1px solid #333;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .card h2 {
            color: #e94560;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .card h3 { color: #ff6b6b; margin: 15px 0 10px; }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label { color: #888; margin-top: 5px; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background: #16213e;
            color: #e94560;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #333;
        }
        td {
            padding: 10px 15px;
            border-bottom: 1px solid #222;
        }
        tr:hover { background: rgba(233, 69, 96, 0.05); }

        /* Severity badges */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #17a2b8; color: white; }
        .badge-info { background: #6c757d; color: white; }
        .badge-success { background: #28a745; color: white; }
        .badge-failed { background: #6c757d; color: white; }

        /* Risk Matrix */
        .risk-matrix {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin: 20px 0;
        }
        .risk-cell {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        .risk-critical { background: rgba(220,53,69,0.3); border: 1px solid #dc3545; }
        .risk-high { background: rgba(253,126,20,0.3); border: 1px solid #fd7e14; }
        .risk-medium { background: rgba(255,193,7,0.3); border: 1px solid #ffc107; color: #333; }
        .risk-low { background: rgba(23,162,184,0.3); border: 1px solid #17a2b8; }

        /* Timeline */
        .timeline { position: relative; padding-left: 30px; }
        .timeline::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(to bottom, #e94560, #ff6b6b, #17a2b8);
        }
        .timeline-item {
            margin-bottom: 15px;
            padding-left: 20px;
            position: relative;
        }
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -5px;
            top: 5px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #e94560;
        }
        .timeline-time { color: #888; font-size: 0.85em; }
        .timeline-action { margin-top: 3px; }

        /* MITRE ATT&CK */
        .mitre-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
        }
        .mitre-item {
            background: rgba(233,69,96,0.1);
            border: 1px solid rgba(233,69,96,0.3);
            border-radius: 8px;
            padding: 12px;
        }
        .mitre-id { color: #e94560; font-weight: bold; }
        .mitre-name { color: #ccc; }
        .mitre-tactic { color: #888; font-size: 0.85em; }

        /* Footer */
        .report-footer {
            text-align: center;
            color: #555;
            padding: 30px;
            margin-top: 30px;
            border-top: 1px solid #222;
        }

        @media print {
            body { background: white; color: black; }
            .card { border: 1px solid #ddd; }
            .report-header { background: #f5f5f5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="report-header">
            <h1>{{ engagement.name }}</h1>
            <p class="subtitle">Red Team Security Assessment Report</p>
            <div class="meta">
                <div class="meta-item">
                    <div class="label">Engagement ID</div>
                    <div class="value">{{ engagement.id[:8] }}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Start Time</div>
                    <div class="value">{{ engagement.start_time[:19] }}</div>
                </div>
                <div class="meta-item">
                    <div class="label">End Time</div>
                    <div class="value">{{ (engagement.end_time or 'In Progress')[:19] }}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Report Generated</div>
                    <div class="value">{{ now }}</div>
                </div>
            </div>
        </div>

        <!-- Executive Summary Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_targets }}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.compromised }}</div>
                <div class="stat-label">Hosts Compromised</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_vulns }}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.critical_vulns }}</div>
                <div class="stat-label">Critical Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_steps }}</div>
                <div class="stat-label">Attack Steps</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.techniques_used }}</div>
                <div class="stat-label">MITRE Techniques</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="card">
            <h2>Executive Summary</h2>
            <p>This report presents the findings of an automated red team assessment conducted against
            <strong>{{ stats.total_targets }}</strong> target system(s). The engagement followed a structured
            attack lifecycle aligned with the MITRE ATT&CK framework, progressing through reconnaissance,
            exploitation, and post-exploitation phases.</p>

            <h3>Key Findings</h3>
            <ul style="padding-left: 20px; margin-top: 10px;">
                <li><strong>{{ stats.compromised }}</strong> out of {{ stats.total_targets }} hosts were successfully compromised</li>
                <li><strong>{{ stats.total_vulns }}</strong> vulnerabilities were identified, of which <strong>{{ stats.critical_vulns }}</strong> are critical</li>
                <li><strong>{{ stats.techniques_used }}</strong> unique MITRE ATT&CK techniques were employed</li>
                <li>The assessment covered <strong>{{ stats.total_steps }}</strong> distinct attack steps</li>
            </ul>

            {% if stats.compromised > 0 %}
            <h3>Risk Assessment: HIGH</h3>
            <p style="color: #dc3545; font-weight: bold; margin-top: 10px;">
                The assessment revealed significant security weaknesses that could be exploited by real
                adversaries. Immediate remediation is recommended.
            </p>
            {% else %}
            <h3>Risk Assessment: MODERATE</h3>
            <p style="color: #ffc107; margin-top: 10px;">
                While no hosts were fully compromised, vulnerabilities were identified that require attention.
            </p>
            {% endif %}
        </div>

        <!-- Risk Matrix -->
        <div class="card">
            <h2>Risk Matrix</h2>
            <div class="risk-matrix">
                <div class="risk-cell risk-critical">
                    <div style="font-size: 1.5em;">{{ stats.critical_vulns }}</div>
                    <div>Critical</div>
                </div>
                <div class="risk-cell risk-high">
                    <div style="font-size: 1.5em;">{{ stats.high_vulns }}</div>
                    <div>High</div>
                </div>
                <div class="risk-cell risk-medium">
                    <div style="font-size: 1.5em;">{{ stats.medium_vulns }}</div>
                    <div>Medium</div>
                </div>
                <div class="risk-cell risk-low">
                    <div style="font-size: 1.5em;">{{ stats.low_vulns }}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>

        <!-- Target Summary -->
        <div class="card">
            <h2>Target Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Operating System</th>
                        <th>Open Ports</th>
                        <th>Vulnerabilities</th>
                        <th>Access Level</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                {% for ip, target in targets.items() %}
                    <tr>
                        <td><strong>{{ ip }}</strong></td>
                        <td>{{ target.hostname or 'N/A' }}</td>
                        <td>{{ target.os or 'Unknown' }}</td>
                        <td>{{ target.open_ports | length }}</td>
                        <td>{{ target.vulnerabilities | length }}</td>
                        <td><span class="badge badge-{{ 'critical' if target.access_level in ['root', 'system'] else 'high' if target.access_level == 'admin' else 'medium' if target.access_level == 'user' else 'info' }}">{{ target.access_level }}</span></td>
                        <td><span class="badge badge-{{ 'critical' if target.compromised else 'success' }}">{{ 'Compromised' if target.compromised else 'Secure' }}</span></td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Discovered Services -->
        <div class="card">
            <h2>Discovered Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                {% for ip, target in targets.items() %}
                    {% for port in target.open_ports %}
                    <tr>
                        <td>{{ ip }}</td>
                        <td>{{ port.port }}/{{ port.protocol }}</td>
                        <td>{{ port.service }}</td>
                        <td>{{ port.product }}</td>
                        <td>{{ port.version }}</td>
                    </tr>
                    {% endfor %}
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Vulnerabilities -->
        <div class="card">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>CVSS</th>
                        <th>Service</th>
                        <th>Description</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                {% for ip, target in targets.items() %}
                    {% for vuln in target.vulnerabilities %}
                    <tr>
                        <td><strong>{{ vuln.cve_id }}</strong></td>
                        <td><span class="badge badge-{{ 'critical' if vuln.cvss >= 9 else 'high' if vuln.cvss >= 7 else 'medium' if vuln.cvss >= 4 else 'low' }}">{{ vuln.cvss }}</span></td>
                        <td>{{ vuln.service or vuln.product }}</td>
                        <td>{{ vuln.description[:150] }}</td>
                        <td>{{ vuln.source }}</td>
                    </tr>
                    {% endfor %}
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Attack Timeline -->
        <div class="card">
            <h2>Attack Timeline</h2>
            <div class="timeline">
                {% for step in steps[:50] %}
                <div class="timeline-item">
                    <div class="timeline-time">{{ step.timestamp[:19] }} | {{ step.phase }}
                        {% if step.technique_id %}<span class="mitre-id"> [{{ step.technique_id }}]</span>{% endif %}
                    </div>
                    <div class="timeline-action">
                        <span class="badge badge-{{ step.severity }}">{{ step.severity }}</span>
                        <span class="badge badge-{{ 'success' if step.status == 'success' else 'failed' }}">{{ step.status }}</span>
                        {{ step.action }}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- MITRE ATT&CK Coverage -->
        <div class="card">
            <h2>MITRE ATT&CK Coverage</h2>
            <p style="margin-bottom: 15px;">Techniques used during this engagement:</p>
            <div class="mitre-grid">
                {% for technique in mitre_techniques %}
                <div class="mitre-item">
                    <div class="mitre-id">{{ technique.id }}</div>
                    <div class="mitre-name">{{ technique.name }}</div>
                    <div class="mitre-tactic">{{ technique.tactic }}</div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Recommendations -->
        <div class="card">
            <h2>Recommendations</h2>
            <ol style="padding-left: 20px;">
                {% if stats.compromised > 0 %}
                <li><strong>Patch Critical Vulnerabilities:</strong> Address all critical and high-severity vulnerabilities identified in this report immediately.</li>
                <li><strong>Strengthen Authentication:</strong> Enforce strong password policies and implement multi-factor authentication on all exposed services.</li>
                <li><strong>Network Segmentation:</strong> Implement proper network segmentation to limit lateral movement opportunities.</li>
                {% endif %}
                <li><strong>Harden Services:</strong> Disable unnecessary services and update all software to the latest patched versions.</li>
                <li><strong>Implement IDS/IPS:</strong> Deploy intrusion detection and prevention systems to detect active scanning and exploitation attempts.</li>
                <li><strong>Regular Assessments:</strong> Conduct periodic red team assessments to validate security controls.</li>
                <li><strong>Incident Response:</strong> Develop and test incident response procedures for the attack vectors identified.</li>
                <li><strong>Security Monitoring:</strong> Enhance logging and monitoring capabilities to detect the MITRE ATT&CK techniques used in this assessment.</li>
            </ol>
        </div>

        <!-- Footer -->
        <div class="report-footer">
            <p>Generated by RedTeam Framework v1.0.0</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>"""


class ReportGenerator:
    """Generates comprehensive HTML security assessment reports."""

    def __init__(self, config: Any, output_dir: Path):
        self.config = config
        self.output_dir = output_dir

    def generate(self, engagement: Engagement) -> Path:
        """
        Generate the HTML report.
        
        Returns:
            Path to the generated HTML report.
        """
        logger.info("Generating security assessment report...")

        # Calculate statistics
        stats = self._calculate_stats(engagement)

        # Prepare MITRE techniques data
        mitre_techniques = []
        for tid in sorted(engagement.mitre_techniques_used):
            if tid in ATTACK_TECHNIQUES:
                mitre_techniques.append({
                    "id": tid,
                    "name": ATTACK_TECHNIQUES[tid]["name"],
                    "tactic": ATTACK_TECHNIQUES[tid]["tactic"],
                })

        # Prepare steps data
        steps = [s.to_dict() for s in engagement.attack_steps]

        # Prepare targets data (convert to dicts)
        targets = {ip: t.to_dict() for ip, t in engagement.targets.items()}

        # Render template
        env = Environment(loader=BaseLoader())
        template = env.from_string(REPORT_TEMPLATE)

        html = template.render(
            engagement=engagement,
            targets=targets,
            stats=stats,
            steps=steps,
            mitre_techniques=mitre_techniques,
            now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Write report
        report_path = self.output_dir / "security_assessment_report.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        # Also save as JSON
        json_path = self.output_dir / "report_data.json"
        with open(json_path, "w") as f:
            json.dump({
                "stats": stats,
                "targets": targets,
                "steps": steps,
                "mitre_techniques": mitre_techniques,
            }, f, indent=2, default=str)

        logger.info(f"Report generated: {report_path}")
        return report_path

    def _calculate_stats(self, engagement: Engagement) -> dict:
        """Calculate engagement statistics."""
        all_vulns = []
        for target in engagement.targets.values():
            all_vulns.extend(target.vulnerabilities)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for step in engagement.attack_steps:
            sev = step.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_targets": len(engagement.targets),
            "compromised": len(engagement.get_compromised_targets()),
            "total_vulns": len(all_vulns),
            "total_steps": len(engagement.attack_steps),
            "techniques_used": len(engagement.mitre_techniques_used),
            "critical_vulns": severity_counts["critical"],
            "high_vulns": severity_counts["high"],
            "medium_vulns": severity_counts["medium"],
            "low_vulns": severity_counts["low"],
        }
