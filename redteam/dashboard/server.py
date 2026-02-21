"""
Real-Time Dashboard - Flask + SocketIO server.
Provides a web-based dashboard for monitoring engagement progress.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any

from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.dashboard.server")


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedTeam Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            background: #0a0a1a;
            color: #c0c0c0;
            overflow-x: hidden;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #0f0f2a 0%, #1a0a2e 100%);
            border-bottom: 1px solid #2a2a4a;
            padding: 15px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.4em;
            background: linear-gradient(135deg, #e94560, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .pulse {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #28a745;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(40, 167, 69, 0); }
            100% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0); }
        }

        /* Layout */
        .dashboard {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            grid-template-rows: auto 1fr 1fr;
            gap: 15px;
            padding: 15px;
            height: calc(100vh - 60px);
        }

        /* Stats Row */
        .stat-card {
            background: linear-gradient(135deg, #12122a, #1a1a3a);
            border: 1px solid #2a2a4a;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #e94560;
        }
        .stat-label {
            color: #666;
            font-size: 0.85em;
            margin-top: 5px;
            text-transform: uppercase;
        }

        /* Panels */
        .panel {
            background: #12122a;
            border: 1px solid #2a2a4a;
            border-radius: 10px;
            overflow: hidden;
        }
        .panel-header {
            padding: 12px 15px;
            background: rgba(233, 69, 96, 0.1);
            border-bottom: 1px solid #2a2a4a;
            font-weight: bold;
            color: #e94560;
            text-transform: uppercase;
            font-size: 0.85em;
        }
        .panel-content {
            padding: 10px;
            overflow-y: auto;
            max-height: 300px;
        }

        /* Events list */
        .event-item {
            padding: 8px 10px;
            margin-bottom: 5px;
            background: rgba(255,255,255,0.02);
            border-radius: 6px;
            border-left: 3px solid #333;
            font-size: 0.85em;
        }
        .event-item.recon { border-left-color: #17a2b8; }
        .event-item.exploit { border-left-color: #dc3545; }
        .event-item.success { border-left-color: #28a745; }
        .event-item.lateral { border-left-color: #e83e8c; }
        .event-time { color: #555; font-size: 0.8em; }

        /* Target list */
        .target-item {
            padding: 10px;
            margin-bottom: 5px;
            background: rgba(255,255,255,0.02);
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .target-ip { font-weight: bold; color: #e94560; }
        .target-status {
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.75em;
            font-weight: bold;
        }
        .status-compromised { background: rgba(220,53,69,0.3); color: #ff6b6b; }
        .status-scanning { background: rgba(23,162,184,0.3); color: #17a2b8; }
        .status-secure { background: rgba(40,167,69,0.3); color: #28a745; }

        /* Phase indicator */
        .phase-bar {
            grid-column: 1 / -1;
            background: #12122a;
            border: 1px solid #2a2a4a;
            border-radius: 10px;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .phase-step {
            flex: 1;
            text-align: center;
            padding: 8px;
            border-radius: 6px;
            font-size: 0.8em;
            background: rgba(255,255,255,0.03);
            border: 1px solid #2a2a4a;
            transition: all 0.3s ease;
        }
        .phase-step.active {
            background: rgba(233,69,96,0.2);
            border-color: #e94560;
            color: #e94560;
        }
        .phase-step.completed {
            background: rgba(40,167,69,0.2);
            border-color: #28a745;
            color: #28a745;
        }

        .event-log { grid-column: 1 / 3; }
        .targets-panel { grid-column: 3 / 4; }
        .mitre-panel { grid-column: 4 / 5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>REDTEAM DASHBOARD</h1>
        <div class="status-indicator">
            <div class="pulse"></div>
            <span id="phase-text">Initializing...</span>
        </div>
    </div>

    <div class="dashboard">
        <!-- Stats Row -->
        <div class="stat-card">
            <div class="stat-value" id="stat-targets">0</div>
            <div class="stat-label">Targets</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="stat-compromised">0</div>
            <div class="stat-label">Compromised</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="stat-vulns">0</div>
            <div class="stat-label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="stat-techniques">0</div>
            <div class="stat-label">Techniques</div>
        </div>

        <!-- Phase Bar -->
        <div class="phase-bar">
            <div class="phase-step" id="phase-recon">RECON</div>
            <div class="phase-step" id="phase-scanning">SCAN</div>
            <div class="phase-step" id="phase-enum">ENUM</div>
            <div class="phase-step" id="phase-exploit">EXPLOIT</div>
            <div class="phase-step" id="phase-privesc">PRIV ESC</div>
            <div class="phase-step" id="phase-lateral">LATERAL</div>
            <div class="phase-step" id="phase-persist">PERSIST</div>
            <div class="phase-step" id="phase-report">REPORT</div>
        </div>

        <!-- Event Log -->
        <div class="panel event-log">
            <div class="panel-header">Live Event Feed</div>
            <div class="panel-content" id="event-log"></div>
        </div>

        <!-- Targets -->
        <div class="panel targets-panel">
            <div class="panel-header">Targets</div>
            <div class="panel-content" id="target-list"></div>
        </div>

        <!-- MITRE -->
        <div class="panel mitre-panel">
            <div class="panel-header">MITRE ATT&CK</div>
            <div class="panel-content" id="mitre-list"></div>
        </div>
    </div>

    <script>
        const socket = io();
        const eventLog = document.getElementById('event-log');
        const targetList = document.getElementById('target-list');
        const mitreList = document.getElementById('mitre-list');
        const techniques = new Set();
        let vulnCount = 0;
        let compromisedCount = 0;
        const targets = {};

        socket.on('event', function(data) {
            addEvent(data);
        });

        socket.on('phase_change', function(data) {
            updatePhase(data.phase);
        });

        socket.on('stats_update', function(data) {
            updateStats(data);
        });

        function addEvent(data) {
            const div = document.createElement('div');
            const type = data.event_type || 'info';
            let cssClass = 'event-item';
            if (type.includes('recon') || type.includes('scan')) cssClass += ' recon';
            else if (type.includes('exploit') && type.includes('success')) cssClass += ' success';
            else if (type.includes('exploit')) cssClass += ' exploit';
            else if (type.includes('lateral')) cssClass += ' lateral';

            const time = new Date().toLocaleTimeString();
            div.className = cssClass;
            div.innerHTML = `<span class="event-time">${time}</span> ${data.message || JSON.stringify(data.data)}`;
            eventLog.insertBefore(div, eventLog.firstChild);

            // Update technique list
            if (data.data && data.data.technique_id) {
                techniques.add(data.data.technique_id);
                updateMitre();
            }
        }

        function updatePhase(phase) {
            document.getElementById('phase-text').textContent = phase;
            document.querySelectorAll('.phase-step').forEach(el => {
                el.classList.remove('active', 'completed');
            });

            const phaseMap = {
                'recon': 'phase-recon', 'scanning': 'phase-scanning',
                'enumeration': 'phase-enum', 'exploitation': 'phase-exploit',
                'privilege_escalation': 'phase-privesc', 'lateral_movement': 'phase-lateral',
                'persistence': 'phase-persist', 'reporting': 'phase-report',
            };

            let found = false;
            for (const [key, id] of Object.entries(phaseMap)) {
                const el = document.getElementById(id);
                if (key === phase) {
                    el.classList.add('active');
                    found = true;
                } else if (!found) {
                    el.classList.add('completed');
                }
            }
        }

        function updateStats(data) {
            document.getElementById('stat-targets').textContent = data.targets || 0;
            document.getElementById('stat-compromised').textContent = data.compromised || 0;
            document.getElementById('stat-vulns').textContent = data.vulns || 0;
            document.getElementById('stat-techniques').textContent = data.techniques || 0;
        }

        function updateMitre() {
            mitreList.innerHTML = '';
            techniques.forEach(t => {
                const div = document.createElement('div');
                div.className = 'event-item';
                div.innerHTML = `<strong style="color:#e94560">${t}</strong>`;
                mitreList.appendChild(div);
            });
            document.getElementById('stat-techniques').textContent = techniques.size;
        }
    </script>
</body>
</html>"""


class DashboardServer:
    """Flask + SocketIO real-time dashboard."""

    def __init__(self, config: Any, event_bus: EventBus, host: str = "0.0.0.0", port: int = 5000):
        self.config = config
        self.event_bus = event_bus
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'redteam-dashboard-secret'
        self.socketio = SocketIO(self.app, async_mode='threading', cors_allowed_origins="*")
        self._setup_routes()
        self._setup_events()
        self._thread = None

    def _setup_routes(self):
        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/status")
        def status():
            return jsonify({"status": "running"})

    def _setup_events(self):
        """Subscribe to event bus and forward to SocketIO."""
        self.event_bus.subscribe("*", self._forward_event)

    def _forward_event(self, event):
        """Forward event bus events to web clients."""
        try:
            self.socketio.emit("event", {
                "event_type": event.event_type,
                "data": event.data,
                "source": event.source,
                "message": self._format_event_message(event),
            })
        except Exception as e:
            logger.debug(f"Dashboard emit error: {e}")

    def _format_event_message(self, event) -> str:
        """Format event into a human-readable message."""
        data = event.data or {}
        etype = event.event_type

        if "phase_change" in etype:
            return f"Phase: {data.get('new_phase', '?')}"
        elif "target_discovered" in etype:
            return f"Target discovered: {data.get('ip', '?')}"
        elif "port_found" in etype:
            return f"Port {data.get('port', '?')}/{data.get('service', '?')} on {data.get('target', '?')}"
        elif "vuln_found" in etype:
            return f"Vuln: {data.get('cve_id', '?')} (CVSS: {data.get('cvss', '?')})"
        elif "exploit_success" in etype:
            return f"EXPLOIT SUCCESS: {data.get('target', '?')} via {data.get('method', '?')}"
        elif "exploit_attempt" in etype:
            return f"Exploit attempt: {data.get('service', data.get('cve', '?'))} on {data.get('target', '?')}"
        elif "lateral_move" in etype:
            return f"Lateral: {data.get('source', '?')} → {data.get('target', '?')}"
        else:
            return f"[{event.source}] {etype}"

    def start(self):
        """Start the dashboard server in a background thread."""
        def run():
            logger.info(f"Dashboard running on http://{self.host}:{self.port}")
            self.socketio.run(self.app, host=self.host, port=self.port,
                              allow_unsafe_werkzeug=True, use_reloader=False)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the dashboard server."""
        if self._thread:
            logger.info("Dashboard server stopping...")
