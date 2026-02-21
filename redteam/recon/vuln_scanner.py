"""
Vulnerability Scanner Module.
Matches discovered services against NVD/CVE databases and ExploitDB.

MITRE ATT&CK: T1595 - Active Scanning / Vulnerability Scanning
"""

import asyncio
import logging
import shutil
import subprocess
import json
from typing import Any

import requests

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.recon.vuln_scanner")


class VulnScanner:
    """
    Vulnerability scanner that matches services against known CVEs.
    Uses NVD API for CVE lookups and searchsploit for ExploitDB matching.
    """

    def __init__(self, config: Any, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus
        self.nvd_api_url = getattr(config, 'nvd_api_url',
                                    'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.use_exploitdb = getattr(config, 'exploitdb_search', True)

    async def scan(self, target: str, services: list[dict]) -> list[dict]:
        """
        Scan discovered services for known vulnerabilities.
        
        Args:
            target: Target IP address.
            services: List of discovered services from port scanning.
            
        Returns:
            List of vulnerability dictionaries.
        """
        logger.info(f"Starting vulnerability scan for {target} ({len(services)} services)")
        all_vulns = []

        for service in services:
            product = service.get("product", "")
            version = service.get("version", "")
            cpe = service.get("cpe", "")
            port = service.get("port", "")
            svc_name = service.get("name", "")

            if not product and not cpe:
                continue

            # Method 1: NVD CVE lookup
            nvd_vulns = await self._nvd_lookup(product, version, cpe)
            for vuln in nvd_vulns:
                vuln["target"] = target
                vuln["port"] = port
                vuln["service"] = svc_name
            all_vulns.extend(nvd_vulns)

            # Method 2: ExploitDB search via searchsploit
            if self.use_exploitdb:
                exploit_vulns = await self._exploitdb_search(product, version)
                for vuln in exploit_vulns:
                    vuln["target"] = target
                    vuln["port"] = port
                    vuln["service"] = svc_name
                all_vulns.extend(exploit_vulns)

        # Deduplicate by CVE ID
        seen_cves = set()
        unique_vulns = []
        for vuln in all_vulns:
            cve_id = vuln.get("cve_id", "")
            if cve_id and cve_id in seen_cves:
                continue
            if cve_id:
                seen_cves.add(cve_id)
            unique_vulns.append(vuln)

        logger.info(f"Found {len(unique_vulns)} vulnerabilities for {target}")

        await self.event_bus.emit("scan_complete", {
            "module": "vuln_scanner",
            "target": target,
            "vulnerability_count": len(unique_vulns),
        }, source="vuln_scanner")

        return unique_vulns

    async def _nvd_lookup(self, product: str, version: str, cpe: str) -> list[dict]:
        """Look up CVEs from the NVD API."""
        vulns = []

        try:
            loop = asyncio.get_event_loop()

            # Build search query
            params = {}
            if cpe:
                params["cpeName"] = cpe
            elif product:
                keyword = f"{product} {version}".strip()
                params["keywordSearch"] = keyword
                params["keywordExactMatch"] = ""

            params["resultsPerPage"] = 20

            response = await loop.run_in_executor(
                None,
                lambda: requests.get(
                    self.nvd_api_url,
                    params=params,
                    timeout=30,
                    headers={
                        "User-Agent": "RedTeam-Framework/1.0",
                        "Accept": "application/json",
                    }
                )
            )

            if response.status_code == 200:
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Extract CVSS score
                    cvss = 0.0
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

                    # Extract description
                    descriptions = cve.get("descriptions", [])
                    desc = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    vulns.append({
                        "cve_id": cve_id,
                        "description": desc[:300],
                        "cvss": cvss,
                        "product": product,
                        "version": version,
                        "source": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })

            elif response.status_code == 403:
                logger.warning("NVD API rate limited — consider using an API key")
            else:
                logger.warning(f"NVD API returned status {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"NVD API request failed: {e}")
        except Exception as e:
            logger.warning(f"NVD lookup error: {e}")

        return vulns

    async def _exploitdb_search(self, product: str, version: str) -> list[dict]:
        """Search ExploitDB via searchsploit CLI."""
        vulns = []

        if not shutil.which("searchsploit"):
            logger.debug("searchsploit not found — skipping ExploitDB search")
            return vulns

        search_term = f"{product} {version}".strip()
        if not search_term:
            return vulns

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ["searchsploit", "--json", search_term],
                    capture_output=True, text=True, timeout=30
                )
            )

            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for exploit in data.get("RESULTS_EXPLOIT", []):
                    vulns.append({
                        "cve_id": exploit.get("Codes", "N/A"),
                        "description": exploit.get("Title", ""),
                        "cvss": 7.5,  # Default score for ExploitDB entries
                        "product": product,
                        "version": version,
                        "source": "ExploitDB",
                        "exploit_path": exploit.get("Path", ""),
                        "url": f"https://www.exploit-db.com/exploits/{exploit.get('EDB-ID', '')}",
                    })

        except subprocess.TimeoutExpired:
            logger.warning("searchsploit timed out")
        except json.JSONDecodeError:
            logger.warning("searchsploit output was not valid JSON")
        except Exception as e:
            logger.warning(f"ExploitDB search error: {e}")

        return vulns
