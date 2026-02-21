"""
Port Scanner Module.
Wraps Nmap for port scanning, service detection, and script scanning.

MITRE ATT&CK: T1046 - Network Service Discovery
"""

import asyncio
import logging
import shutil
from typing import Any

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.recon.port_scanner")


class PortScanner:
    """
    Network port scanner using python-nmap.
    Performs SYN/TCP scanning, service version detection, and NSE script scanning.
    """

    def __init__(self, config: Any, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus
        self.scan_type = getattr(config, 'scan_type', 'SYN')
        self.port_range = getattr(config, 'port_range', '1-1024')
        self.service_detection = getattr(config, 'service_detection', True)
        self.os_detection = getattr(config, 'os_detection', True)
        self.script_scan = getattr(config, 'script_scan', True)
        self.timing = getattr(config, 'timing', 4)

    async def scan(self, target: str, full_scan: bool = False) -> dict:
        """
        Perform a comprehensive port scan against a target.
        
        Args:
            target: Target IP address or hostname.
            full_scan: If True, scan all 65535 ports.
            
        Returns:
            Dictionary with ports, services, OS info, and raw data.
        """
        logger.info(f"Starting port scan on {target}")

        # Check if nmap is available
        if not shutil.which("nmap"):
            logger.warning("Nmap not found in PATH — using python-nmap fallback")

        try:
            import nmap
        except ImportError:
            logger.error("python-nmap not installed. Install with: pip install python-nmap")
            return {"ports": [], "services": [], "os": "", "error": "python-nmap not installed"}

        port_range = getattr(self.config, 'full_port_range', '1-65535') if full_scan else self.port_range

        # Build nmap arguments
        args = self._build_nmap_args(port_range)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._execute_scan, target, args)

        await self.event_bus.emit("scan_complete", {
            "module": "port_scanner",
            "target": target,
            "open_ports": len(result.get("ports", [])),
            "services": len(result.get("services", [])),
        }, source="port_scanner")

        return result

    def _build_nmap_args(self, port_range: str) -> str:
        """Build nmap command-line arguments."""
        args = []

        # Scan type
        if self.scan_type.upper() == "SYN":
            args.append("-sS")
        elif self.scan_type.upper() == "TCP":
            args.append("-sT")
        elif self.scan_type.upper() == "UDP":
            args.append("-sU")

        # Port range
        args.append(f"-p {port_range}")

        # Service version detection
        if self.service_detection:
            args.append("-sV")

        # OS detection
        if self.os_detection:
            args.append("-O")

        # Script scanning
        if self.script_scan:
            args.append("--script=default,vuln")

        # Timing
        args.append(f"-T{self.timing}")

        # Output verbosity
        args.append("-v")

        return " ".join(args)

    def _execute_scan(self, target: str, args: str) -> dict:
        """Execute the nmap scan and parse results."""
        import nmap
        scanner = nmap.PortScanner()

        result = {
            "ports": [],
            "services": [],
            "os": "",
            "scripts": [],
            "raw": {},
        }

        try:
            logger.info(f"Executing: nmap {args} {target}")
            scanner.scan(hosts=target, arguments=args)

            for host in scanner.all_hosts():
                # OS detection
                if "osmatch" in scanner[host]:
                    os_matches = scanner[host]["osmatch"]
                    if os_matches:
                        best_match = os_matches[0]
                        result["os"] = best_match.get("name", "Unknown")
                        result["os_accuracy"] = best_match.get("accuracy", "0")

                # Parse ports and services
                for proto in scanner[host].all_protocols():
                    ports = sorted(scanner[host][proto].keys())
                    for port in ports:
                        port_info = scanner[host][proto][port]
                        state = port_info.get("state", "")

                        if state == "open":
                            port_entry = {
                                "port": port,
                                "protocol": proto,
                                "state": state,
                                "service": port_info.get("name", ""),
                                "version": port_info.get("version", ""),
                                "product": port_info.get("product", ""),
                                "extra_info": port_info.get("extrainfo", ""),
                                "cpe": port_info.get("cpe", ""),
                            }
                            result["ports"].append(port_entry)

                            service_entry = {
                                "name": port_info.get("name", ""),
                                "port": port,
                                "protocol": proto,
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", ""),
                                "cpe": port_info.get("cpe", ""),
                            }
                            result["services"].append(service_entry)

                            # Script results
                            if "script" in port_info:
                                for script_name, script_output in port_info["script"].items():
                                    result["scripts"].append({
                                        "port": port,
                                        "script": script_name,
                                        "output": script_output,
                                    })

                            logger.info(
                                f"  {port}/{proto} {state} "
                                f"{port_info.get('product', '')} "
                                f"{port_info.get('version', '')}"
                            )

            result["raw"] = {
                "command_line": scanner.command_line(),
                "scan_info": scanner.scaninfo(),
            }

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            result["error"] = str(e)
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            result["error"] = str(e)

        logger.info(f"Scan complete: {len(result['ports'])} open ports found")
        return result

    async def quick_scan(self, target: str) -> dict:
        """Perform a quick top-100 ports scan."""
        logger.info(f"Quick scan on {target}")
        old_range = self.port_range
        self.port_range = "--top-ports 100"
        result = await self.scan(target)
        self.port_range = old_range
        return result
