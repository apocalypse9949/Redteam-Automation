"""
Subdomain Enumeration Module.
Discovers subdomains via DNS brute-force and Certificate Transparency logs.

MITRE ATT&CK: T1596 - Search Open Technical Databases
"""

import asyncio
import json
import logging
import socket
from typing import Any

import requests

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.recon.subdomain_enum")

# Built-in mini wordlist for subdomain brute-force
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "admin", "api", "dev",
    "staging", "test", "demo", "portal", "app", "blog", "shop", "store",
    "forum", "wiki", "support", "help", "docs", "status", "monitor",
    "dashboard", "panel", "cpanel", "whm", "webdisk", "autodiscover",
    "remote", "gateway", "proxy", "cdn", "media", "static", "assets",
    "img", "images", "video", "download", "upload", "backup", "db",
    "database", "mysql", "postgres", "redis", "elastic", "kibana",
    "grafana", "prometheus", "jenkins", "gitlab", "git", "svn", "ci",
    "cd", "deploy", "build", "staging2", "uat", "qa", "preprod",
    "prod", "production", "internal", "intranet", "extranet", "corp",
    "auth", "sso", "login", "oauth", "id", "identity", "accounts",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "files",
    "secure", "ssl", "tls", "wss", "ws", "socket", "realtime",
]


class SubdomainEnumerator:
    """Discovers subdomains via DNS brute-force and Certificate Transparency."""

    def __init__(self, config: Any, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus
        self.max_concurrent = getattr(config, 'subdomain_concurrency', 50)
        self.use_ct_logs = getattr(config, 'use_ct_logs', True)

    async def enumerate(self, domain: str) -> list[str]:
        """
        Enumerate subdomains for a given domain.
        
        Args:
            domain: Target domain (e.g., 'example.com')
            
        Returns:
            List of discovered subdomains.
        """
        logger.info(f"Starting subdomain enumeration for: {domain}")
        found_subdomains = set()

        # Skip if target is an IP address
        if self._is_ip(domain):
            logger.info(f"Target '{domain}' is an IP address — skipping subdomain enum.")
            return []

        # Method 1: DNS brute-force
        dns_subs = await self._dns_brute_force(domain)
        found_subdomains.update(dns_subs)
        logger.info(f"DNS brute-force found {len(dns_subs)} subdomains")

        # Method 2: Certificate Transparency logs
        if self.use_ct_logs:
            ct_subs = await self._ct_log_search(domain)
            found_subdomains.update(ct_subs)
            logger.info(f"CT log search found {len(ct_subs)} subdomains")

        result = sorted(found_subdomains)
        logger.info(f"Total unique subdomains found: {len(result)}")

        await self.event_bus.emit("scan_complete", {
            "module": "subdomain_enum",
            "target": domain,
            "count": len(result),
            "subdomains": result[:20],
        }, source="subdomain_enum")

        return result

    async def _dns_brute_force(self, domain: str) -> set[str]:
        """Brute-force subdomains via DNS resolution."""
        found = set()
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_subdomain(sub: str):
            async with semaphore:
                fqdn = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None, socket.getaddrinfo, fqdn, None
                    )
                    found.add(fqdn)
                    logger.debug(f"Found subdomain: {fqdn}")
                except socket.gaierror:
                    pass
                except Exception as e:
                    logger.debug(f"Error resolving {fqdn}: {e}")

        # Load wordlist or use defaults
        wordlist = self._load_wordlist()
        tasks = [check_subdomain(sub) for sub in wordlist]
        await asyncio.gather(*tasks)

        return found

    async def _ct_log_search(self, domain: str) -> set[str]:
        """Search Certificate Transparency logs via crt.sh."""
        found = set()
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=15,
                    headers={"User-Agent": "RedTeam-Framework/1.0"},
                )
            )

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(domain):
                            found.add(sub)
        except requests.exceptions.RequestException as e:
            logger.warning(f"CT log search failed: {e}")
        except json.JSONDecodeError:
            logger.warning("CT log response was not valid JSON")

        return found

    def _load_wordlist(self) -> list[str]:
        """Load subdomain wordlist from file or use built-in defaults."""
        wordlist_path = getattr(self.config, 'subdomain_wordlist', '')
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except (FileNotFoundError, TypeError):
            return DEFAULT_SUBDOMAINS

    @staticmethod
    def _is_ip(target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except socket.error:
                return False
