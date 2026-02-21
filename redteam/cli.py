"""
RedTeam Framework - CLI Entry Point.
Provides the command-line interface for running engagements.
"""

import argparse
import asyncio
import logging
import sys
import os
import json
from pathlib import Path
from datetime import datetime

from redteam.config import load_config
from redteam.core.engine import RedTeamEngine
from redteam.core.event_bus import EventBus


def setup_logging(verbose: bool = False, log_file: str = None):
    """Configure logging for the framework."""
    level = logging.DEBUG if verbose else logging.INFO

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-5s] %(name)-30s | %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="AI-Driven Red Team Simulation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  redteam scan 192.168.1.1
  redteam scan 192.168.1.0/24 --phases recon,exploit
  redteam scan 10.0.0.1 10.0.0.2 --dashboard --output ./results
  redteam scan target.example.com --full --verbose
  redteam report ./output/engagement_data.json
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a red team engagement")
    scan_parser.add_argument(
        "targets",
        nargs="+",
        help="Target IP addresses, CIDR ranges, or hostnames",
    )
    scan_parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default="./output",
        help="Output directory for reports (default: ./output)",
    )
    scan_parser.add_argument(
        "--phases",
        default=None,
        help="Comma-separated list of phases to run (default: all)",
    )
    scan_parser.add_argument(
        "--full",
        action="store_true",
        help="Run all phases including post-exploitation",
    )
    scan_parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start real-time web dashboard on port 5000",
    )
    scan_parser.add_argument(
        "--dashboard-port",
        type=int,
        default=5000,
        help="Dashboard port (default: 5000)",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    scan_parser.add_argument(
        "--log-file",
        default=None,
        help="Log to file in addition to console",
    )
    scan_parser.add_argument(
        "--engagement-name",
        default=None,
        help="Name for this engagement (default: auto-generated)",
    )

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from engagement data")
    report_parser.add_argument(
        "data_file",
        help="Path to engagement data JSON file",
    )
    report_parser.add_argument(
        "--output", "-o",
        default="./output",
        help="Output directory for the report",
    )

    return parser.parse_args()


async def run_scan(args):
    """Execute the scan/engagement."""
    # Load configuration
    config = load_config(args.config)

    # Override config with CLI args
    if args.engagement_name:
        config.general.engagement_name = args.engagement_name
    config.general.output_dir = args.output

    # Setup event bus
    event_bus = EventBus()

    # Console event listener
    def log_event(event):
        icon_map = {
            "phase_change": "[*]",
            "target_discovered": "[+]",
            "port_found": "[+]",
            "vuln_found": "[!]",
            "exploit_success": "[!!!]",
            "exploit_attempt": "[>]",
            "lateral_move": "[>>]",
            "persistence_planted": "[P]",
        }
        icon = icon_map.get(event.event_type, "[~]")
        data = event.data or {}

        if event.event_type == "phase_change":
            print(f"\n{'='*60}")
            print(f"  {icon} Phase: {data.get('new_phase', '?')}")
            print(f"{'='*60}\n")
        elif event.event_type == "exploit_success":
            print(f"\033[91m  {icon} EXPLOIT SUCCESS: {data.get('target', '?')} via {data.get('method', data.get('cve', '?'))}\033[0m")
        elif event.event_type == "vuln_found":
            print(f"\033[93m  {icon} Vulnerability: {data.get('cve_id', 'N/A')} (CVSS {data.get('cvss', '?')}) on {data.get('target', '?')}\033[0m")
        elif event.event_type == "port_found":
            print(f"  {icon} Port {data.get('port', '?')}/{data.get('service', '?')} on {data.get('target', '?')}")

    event_bus.subscribe("*", log_event)

    # Start dashboard if requested
    dashboard = None
    if args.dashboard:
        from redteam.dashboard.server import DashboardServer
        dashboard = DashboardServer(config, event_bus, port=args.dashboard_port)
        dashboard.start()
        print(f"\n  [*] Dashboard: http://localhost:{args.dashboard_port}\n")

    # Create and run engine
    engine = RedTeamEngine(config, event_bus)

    # Parse phases
    phases = None
    if args.phases:
        phases = [p.strip() for p in args.phases.split(",")]

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                  RedTeam Framework v1.0.0                    ║
║              AI-Driven Red Team Simulation                   ║
╠══════════════════════════════════════════════════════════════╣
║  Targets: {', '.join(args.targets):<50s}║
║  Output:  {args.output:<50s}║
║  Dashboard: {'Yes' if args.dashboard else 'No':<49s}║
╚══════════════════════════════════════════════════════════════╝
""")

    try:
        report_path = await engine.run_engagement(args.targets, phases=phases)

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    Engagement Complete                        ║
╠══════════════════════════════════════════════════════════════╣
║  Report: {str(report_path):<51s}║
╚══════════════════════════════════════════════════════════════╝
""")

    except KeyboardInterrupt:
        print("\n  [!] Engagement interrupted by user")
    except Exception as e:
        print(f"\n  [!] Error: {e}")
        logging.getLogger("redteam").exception("Engagement failed")
    finally:
        if dashboard:
            dashboard.stop()


def main():
    """Main entry point."""
    args = parse_args()

    if not args.command:
        print("Usage: redteam <command> [options]")
        print("Commands: scan, report")
        print("Run 'redteam <command> --help' for more info")
        sys.exit(1)

    setup_logging(
        verbose=getattr(args, 'verbose', False),
        log_file=getattr(args, 'log_file', None),
    )

    if args.command == "scan":
        asyncio.run(run_scan(args))
    elif args.command == "report":
        print(f"Report generation from {args.data_file}")
        # Load engagement data and generate report
        from redteam.reporting.report_generator import ReportGenerator
        from redteam.core.attack_lifecycle import Engagement
        config = load_config(getattr(args, 'config', 'config.yaml'))
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        gen = ReportGenerator(config, output_dir)
        # Would deserialize engagement from JSON here
        print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
