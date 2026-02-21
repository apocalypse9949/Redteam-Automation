"""
OS Fingerprinting Module.
OS detection via Nmap and banner grabbing via raw socket connections.

MITRE ATT&CK: T1082 - System Information Discovery
"""

import asyncio
import logging
import socket
from typing import Any

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.recon.os_fingerprint")

# Banner signature patterns for OS identification
BANNER_SIGNATURES = {
    "Linux": ["linux", "ubuntu", "debian", "centos", "fedora", "red hat",
              "rhel", "arch", "kali", "opensuse", "sles"],
    "Windows": ["windows", "microsoft", "win32", "win64", "iis"],
    "macOS": ["darwin", "macos", "osx", "mac os x"],
    "FreeBSD": ["freebsd"],
    "OpenBSD": ["openbsd"],
    "Solaris": ["solaris", "sunos"],
    "AIX": ["aix"],
    "Cisco IOS": ["cisco", "ios"],
}

# Common ports for banner grabbing
BANNER_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]


class OSFingerprinter:
    """
    OS fingerprinting via Nmap OS detection and banner grabbing.
    """

    def __init__(self, config: Any, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus

    async def fingerprint(self, target: str) -> dict:
        """
        Fingerprint the target operating system.
        
        Args:
            target: Target IP address.
            
        Returns:
            Dictionary with OS info, banners, and confidence.
        """
        logger.info(f"Starting OS fingerprinting for {target}")
        result = {
            "os": "",
            "version": "",
            "confidence": 0,
            "method": "",
            "banners": [],
        }

        # Method 1: Nmap OS detection
        nmap_result = await self._nmap_os_detect(target)
        if nmap_result.get("os"):
            result.update(nmap_result)
            result["method"] = "nmap"

        # Method 2: Banner grabbing
        banners = await self._banner_grab(target)
        result["banners"] = banners

        # If Nmap didn't detect OS, try to infer from banners
        if not result["os"] and banners:
            inferred = self._infer_os_from_banners(banners)
            if inferred:
                result["os"] = inferred
                result["method"] = "banner_analysis"
                result["confidence"] = 60

        logger.info(f"OS fingerprint: {result['os']} ({result['confidence']}% confidence)")

        await self.event_bus.emit("scan_complete", {
            "module": "os_fingerprint",
            "target": target,
            "os": result["os"],
        }, source="os_fingerprint")

        return result

    async def _nmap_os_detect(self, target: str) -> dict:
        """Run Nmap OS detection scan."""
        result = {"os": "", "version": "", "confidence": 0}

        try:
            import nmap
            scanner = nmap.PortScanner()

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: scanner.scan(hosts=target, arguments="-O --osscan-guess -T4")
            )

            for host in scanner.all_hosts():
                if "osmatch" in scanner[host]:
                    matches = scanner[host]["osmatch"]
                    if matches:
                        best = matches[0]
                        result["os"] = best.get("name", "")
                        result["confidence"] = int(best.get("accuracy", 0))

                        # Extract version from OS classes
                        if "osclass" in best:
                            for cls in best["osclass"]:
                                if cls.get("osgen"):
                                    result["version"] = cls["osgen"]
                                    break

        except ImportError:
            logger.warning("python-nmap not available for OS detection")
        except Exception as e:
            logger.warning(f"Nmap OS detection failed: {e}")

        return result

    async def _banner_grab(self, target: str) -> list[dict]:
        """Grab service banners from common ports."""
        banners = []
        semaphore = asyncio.Semaphore(10)

        async def grab_banner(port: int):
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    banner = await loop.run_in_executor(
                        None, self._connect_and_grab, target, port
                    )
                    if banner:
                        banners.append({
                            "port": port,
                            "banner": banner,
                        })
                        logger.debug(f"Banner on port {port}: {banner[:80]}")
                except Exception:
                    pass

        tasks = [grab_banner(port) for port in BANNER_PORTS]
        await asyncio.gather(*tasks)

        return banners

    @staticmethod
    def _connect_and_grab(target: str, port: int, timeout: float = 3.0) -> str:
        """Connect to a port and grab the banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Some services send banner on connect, others need a probe
            try:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                # Send HTTP probe
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                try:
                    banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    banner = ""

            sock.close()
            return banner

        except (socket.error, socket.timeout, ConnectionRefusedError, OSError):
            return ""

    @staticmethod
    def _infer_os_from_banners(banners: list[dict]) -> str:
        """Infer OS from collected banners."""
        os_scores: dict[str, int] = {}

        for banner_info in banners:
            banner_lower = banner_info.get("banner", "").lower()
            for os_name, signatures in BANNER_SIGNATURES.items():
                for sig in signatures:
                    if sig in banner_lower:
                        os_scores[os_name] = os_scores.get(os_name, 0) + 1

        if os_scores:
            return max(os_scores, key=os_scores.get)
        return ""
