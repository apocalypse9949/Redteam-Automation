"""
Web Reconnaissance Module.
Directory brute-force, technology detection, and web application fingerprinting.

MITRE ATT&CK: T1592 - Gather Victim Host Information
"""

import asyncio
import logging
import shutil
import subprocess
from typing import Any

import requests
from bs4 import BeautifulSoup

from redteam.core.event_bus import EventBus


logger = logging.getLogger("redteam.recon.web_recon")

# Common web technologies and their detection signatures
TECH_SIGNATURES = {
    "Apache": {"headers": ["Server: Apache"], "body": []},
    "Nginx": {"headers": ["Server: nginx"], "body": []},
    "IIS": {"headers": ["Server: Microsoft-IIS"], "body": []},
    "PHP": {"headers": ["X-Powered-By: PHP"], "body": []},
    "ASP.NET": {"headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"], "body": []},
    "WordPress": {"headers": [], "body": ["wp-content", "wp-includes", "WordPress"]},
    "Drupal": {"headers": ["X-Drupal-Cache", "X-Generator: Drupal"], "body": ["Drupal.settings"]},
    "Joomla": {"headers": [], "body": ["/media/jui/", "Joomla!"]},
    "Django": {"headers": [], "body": ["csrfmiddlewaretoken", "__admin__"]},
    "Flask": {"headers": ["Server: Werkzeug"], "body": []},
    "Express": {"headers": ["X-Powered-By: Express"], "body": []},
    "React": {"headers": [], "body": ["react-root", "_reactRoot", "data-reactroot"]},
    "Vue.js": {"headers": [], "body": ["data-v-", "__vue__"]},
    "Angular": {"headers": [], "body": ["ng-version", "ng-app"]},
    "jQuery": {"headers": [], "body": ["jquery.min.js", "jQuery"]},
    "Bootstrap": {"headers": [], "body": ["bootstrap.min.css", "bootstrap.min.js"]},
    "Cloudflare": {"headers": ["Server: cloudflare", "cf-ray"], "body": []},
    "Tomcat": {"headers": ["Server: Apache-Coyote"], "body": ["Apache Tomcat"]},
    "Spring": {"headers": [], "body": ["Whitelabel Error Page"]},
}


class WebRecon:
    """
    Web application reconnaissance module.
    Performs directory enumeration, technology detection, and web fingerprinting.
    """

    def __init__(self, config: Any, event_bus: EventBus):
        self.config = config
        self.event_bus = event_bus
        self.user_agent = getattr(config, 'user_agent',
                                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedTeam/1.0')
        self.extensions = getattr(config, 'web_extensions',
                                   ['.php', '.html', '.js', '.asp', '.aspx', '.jsp'])

    async def scan(self, target: str, web_ports: list[dict]) -> dict:
        """
        Perform web reconnaissance on a target.
        
        Args:
            target: Target IP or hostname.
            web_ports: List of HTTP/HTTPS port dictionaries.
            
        Returns:
            Dictionary with directories, technologies, headers, etc.
        """
        logger.info(f"Starting web reconnaissance on {target}")
        result = {
            "directories": [],
            "technologies": [],
            "headers": {},
            "title": "",
            "forms": [],
            "links": [],
            "comments": [],
        }

        for port_info in web_ports:
            port = port_info.get("port", 80)
            scheme = "https" if port in [443, 8443] or "ssl" in str(port_info.get("service", "")) else "http"
            base_url = f"{scheme}://{target}:{port}" if port not in [80, 443] else f"{scheme}://{target}"

            # Fingerprint the web application
            fingerprint = await self._fingerprint(base_url)
            result["headers"].update(fingerprint.get("headers", {}))
            result["title"] = fingerprint.get("title", "")
            result["technologies"].extend(fingerprint.get("technologies", []))
            result["forms"].extend(fingerprint.get("forms", []))
            result["links"].extend(fingerprint.get("links", []))
            result["comments"].extend(fingerprint.get("comments", []))

            # Directory brute-force
            dirs = await self._directory_bruteforce(base_url)
            result["directories"].extend(dirs)

        # Deduplicate
        result["technologies"] = list(set(result["technologies"]))
        result["directories"] = list(set(result["directories"]))

        await self.event_bus.emit("scan_complete", {
            "module": "web_recon",
            "target": target,
            "directories": len(result["directories"]),
            "technologies": result["technologies"],
        }, source="web_recon")

        return result

    async def _fingerprint(self, base_url: str) -> dict:
        """Fingerprint a web application by analyzing HTTP response."""
        info = {
            "headers": {},
            "title": "",
            "technologies": [],
            "forms": [],
            "links": [],
            "comments": [],
        }

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(
                    base_url,
                    timeout=10,
                    verify=False,
                    headers={"User-Agent": self.user_agent},
                    allow_redirects=True,
                )
            )

            # Analyze headers
            info["headers"] = dict(response.headers)

            # Detect technologies from headers
            headers_str = str(response.headers).lower()
            for tech, sigs in TECH_SIGNATURES.items():
                for header_sig in sigs["headers"]:
                    if header_sig.lower() in headers_str:
                        info["technologies"].append(tech)
                        break

            # Parse HTML
            soup = BeautifulSoup(response.text, "html.parser")

            # Title
            title_tag = soup.find("title")
            if title_tag:
                info["title"] = title_tag.get_text().strip()

            # Detect technologies from body
            body_lower = response.text.lower()
            for tech, sigs in TECH_SIGNATURES.items():
                if tech not in info["technologies"]:
                    for body_sig in sigs["body"]:
                        if body_sig.lower() in body_lower:
                            info["technologies"].append(tech)
                            break

            # Extract forms (potential attack surfaces)
            for form in soup.find_all("form"):
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_info["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                info["forms"].append(form_info)

            # Extract links
            for a in soup.find_all("a", href=True)[:50]:
                info["links"].append(a["href"])

            # Extract HTML comments (may contain sensitive info)
            import re
            comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
            info["comments"] = [c.strip() for c in comments if len(c.strip()) > 5][:20]

            logger.info(f"Fingerprinted {base_url}: title='{info['title']}', techs={info['technologies']}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fingerprint {base_url}: {e}")
        except Exception as e:
            logger.warning(f"Error fingerprinting {base_url}: {e}")

        return info

    async def _directory_bruteforce(self, base_url: str) -> list[str]:
        """Brute-force web directories using gobuster or built-in fallback."""
        found = []

        # Try gobuster first
        if shutil.which("gobuster"):
            found = await self._run_gobuster(base_url)
        else:
            # Fallback: built-in brute force
            found = await self._builtin_dirbrute(base_url)

        return found

    async def _run_gobuster(self, base_url: str) -> list[str]:
        """Run gobuster for directory enumeration."""
        found = []
        wordlist_path = getattr(self.config, 'web_wordlist', '')

        try:
            cmd = [
                "gobuster", "dir",
                "-u", base_url,
                "-w", wordlist_path if wordlist_path else "/usr/share/wordlists/dirb/common.txt",
                "-t", "20",
                "-q",
                "--no-error",
                "-o", "-",
            ]

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            )

            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.split()
                        if parts:
                            found.append(parts[0])

        except subprocess.TimeoutExpired:
            logger.warning("Gobuster timed out")
        except Exception as e:
            logger.warning(f"Gobuster failed: {e}")

        return found

    async def _builtin_dirbrute(self, base_url: str) -> list[str]:
        """Built-in directory brute-force fallback."""
        common_dirs = [
            "/admin", "/login", "/dashboard", "/api", "/config", "/backup",
            "/uploads", "/images", "/css", "/js", "/static", "/media",
            "/wp-admin", "/wp-login.php", "/wp-content", "/administrator",
            "/phpmyadmin", "/phpinfo.php", "/.env", "/.git", "/.htaccess",
            "/robots.txt", "/sitemap.xml", "/server-status", "/server-info",
            "/console", "/debug", "/test", "/temp", "/tmp", "/log",
            "/logs", "/error", "/errors", "/cgi-bin", "/bin", "/etc",
            "/.well-known", "/xmlrpc.php", "/feed", "/rss",
            "/wp-json", "/api/v1", "/api/v2", "/graphql", "/swagger",
            "/docs", "/redoc", "/health", "/status", "/metrics",
        ]

        found = []
        semaphore = asyncio.Semaphore(20)

        async def check_dir(path: str):
            async with semaphore:
                url = f"{base_url}{path}"
                try:
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: requests.get(
                            url, timeout=5, verify=False,
                            headers={"User-Agent": self.user_agent},
                            allow_redirects=False,
                        )
                    )
                    if response.status_code in [200, 301, 302, 403]:
                        found.append(f"{path} [{response.status_code}]")
                        logger.debug(f"Found: {path} [{response.status_code}]")
                except Exception:
                    pass

        tasks = [check_dir(d) for d in common_dirs]
        await asyncio.gather(*tasks)

        return found
