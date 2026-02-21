"""
Plugin Loader - Dynamic discovery and loading of attack modules.
"""

import importlib
import logging
from typing import Any
from pathlib import Path


logger = logging.getLogger("redteam.plugin_loader")


class PluginRegistry:
    """Registry for tracking available attack modules."""

    def __init__(self):
        self._plugins: dict[str, dict] = {}

    def register(self, name: str, module: Any, category: str,
                 description: str = "", mitre_ids: list[str] = None) -> None:
        """Register a plugin module."""
        self._plugins[name] = {
            "module": module,
            "category": category,
            "description": description,
            "mitre_ids": mitre_ids or [],
        }
        logger.info(f"Registered plugin: {name} [{category}]")

    def get(self, name: str) -> dict | None:
        return self._plugins.get(name)

    def get_by_category(self, category: str) -> dict[str, dict]:
        return {k: v for k, v in self._plugins.items() if v["category"] == category}

    def list_plugins(self) -> list[dict]:
        return [
            {"name": k, **{kk: vv for kk, vv in v.items() if kk != "module"}}
            for k, v in self._plugins.items()
        ]


def load_all_plugins(registry: PluginRegistry) -> None:
    """Load all built-in attack modules into the registry."""

    modules_to_load = [
        # Recon modules
        ("subdomain_enum", "redteam.recon.subdomain_enum", "recon",
         "Subdomain enumeration via DNS and CT logs", ["T1596"]),
        ("port_scanner", "redteam.recon.port_scanner", "recon",
         "Port scanning and service fingerprinting", ["T1046"]),
        ("vuln_scanner", "redteam.recon.vuln_scanner", "recon",
         "Vulnerability identification via CVE matching", ["T1595"]),
        ("web_recon", "redteam.recon.web_recon", "recon",
         "Web directory brute-force and tech detection", ["T1592"]),
        ("os_fingerprint", "redteam.recon.os_fingerprint", "recon",
         "OS detection and banner grabbing", ["T1082"]),

        # Exploit modules
        ("exploit_selector", "redteam.exploit.exploit_selector", "exploit",
         "AI-driven exploit selection engine", []),
        ("brute_force", "redteam.exploit.brute_force", "exploit",
         "Credential brute-force attacks", ["T1110"]),
        ("web_exploits", "redteam.exploit.web_exploits", "exploit",
         "Web application exploitation", ["T1190"]),
        ("cve_exploits", "redteam.exploit.cve_exploits", "exploit",
         "Known CVE exploit integration", ["T1203"]),

        # Post-exploit modules
        ("priv_escalation", "redteam.post_exploit.priv_escalation", "post_exploit",
         "Privilege escalation checks", ["T1068"]),
        ("lateral_movement", "redteam.post_exploit.lateral_movement", "post_exploit",
         "Lateral movement simulation", ["T1021"]),
        ("persistence", "redteam.post_exploit.persistence", "post_exploit",
         "Persistence mechanism analysis", ["T1053"]),
        ("credential_harvest", "redteam.post_exploit.credential_harvest", "post_exploit",
         "Credential harvesting simulation", ["T1003"]),
    ]

    for name, module_path, category, description, mitre_ids in modules_to_load:
        try:
            module = importlib.import_module(module_path)
            registry.register(name, module, category, description, mitre_ids)
        except ImportError as e:
            logger.warning(f"Failed to load plugin '{name}': {e}")
        except Exception as e:
            logger.error(f"Error loading plugin '{name}': {e}")


# Global registry
plugin_registry = PluginRegistry()
