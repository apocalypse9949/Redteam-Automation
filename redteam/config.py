"""
Configuration loader for RedTeam Framework.
Loads YAML config with defaults and CLI overrides.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


@dataclass
class ReconConfig:
    subdomain_wordlist: str = "wordlists/subdomains.txt"
    use_ct_logs: bool = True
    subdomain_concurrency: int = 50
    scan_type: str = "SYN"
    port_range: str = "1-1024"
    full_port_range: str = "1-65535"
    service_detection: bool = True
    os_detection: bool = True
    script_scan: bool = True
    timing: int = 4
    web_wordlist: str = "wordlists/directories.txt"
    web_extensions: list = field(default_factory=lambda: [".php", ".html", ".js"])
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedTeam/1.0"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    exploitdb_search: bool = True


@dataclass
class ExploitConfig:
    ssh_wordlist: str = "wordlists/passwords.txt"
    username_list: str = "wordlists/usernames.txt"
    max_brute_attempts: int = 100
    parallel_tasks: int = 4
    brute_timeout: int = 10
    sqlmap_level: int = 3
    sqlmap_risk: int = 2
    test_xss: bool = True
    test_lfi: bool = True
    test_rfi: bool = True
    test_cmdi: bool = True
    auto_exploit: bool = True
    max_cvss: float = 10.0
    min_cvss: float = 5.0


@dataclass
class PostExploitConfig:
    check_suid: bool = True
    check_sudo: bool = True
    check_kernel: bool = True
    check_services: bool = True
    scan_internal: bool = True
    reuse_creds: bool = True
    lateral_protocols: list = field(default_factory=lambda: ["ssh", "smb", "rdp", "winrm"])
    check_cron: bool = True
    check_registry: bool = True
    check_startup: bool = True


@dataclass
class ReportConfig:
    formats: list = field(default_factory=lambda: ["html", "json"])
    include_attack_graph: bool = True
    include_mitre_navigator: bool = True
    executive_summary: bool = True
    risk_matrix: bool = True


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False


@dataclass
class FrameworkConfig:
    engagement_name: str = "RedTeam Assessment"
    output_dir: str = "./output"
    log_level: str = "INFO"
    max_threads: int = 10
    timeout: int = 30
    recon: ReconConfig = field(default_factory=ReconConfig)
    exploit: ExploitConfig = field(default_factory=ExploitConfig)
    post_exploit: PostExploitConfig = field(default_factory=PostExploitConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)


def load_config(config_path: str | None = None) -> FrameworkConfig:
    """Load configuration from YAML file with defaults."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if not path.exists():
        return FrameworkConfig()

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    cfg = FrameworkConfig()

    # General
    general = raw.get("general", {})
    cfg.engagement_name = general.get("engagement_name", cfg.engagement_name)
    cfg.output_dir = general.get("output_dir", cfg.output_dir)
    cfg.log_level = general.get("log_level", cfg.log_level)
    cfg.max_threads = general.get("max_threads", cfg.max_threads)
    cfg.timeout = general.get("timeout", cfg.timeout)

    # Recon
    recon = raw.get("recon", {})
    sub = recon.get("subdomain", {})
    cfg.recon.subdomain_wordlist = sub.get("wordlist", cfg.recon.subdomain_wordlist)
    cfg.recon.use_ct_logs = sub.get("use_ct_logs", cfg.recon.use_ct_logs)
    cfg.recon.subdomain_concurrency = sub.get("max_concurrent", cfg.recon.subdomain_concurrency)

    ps = recon.get("port_scan", {})
    cfg.recon.scan_type = ps.get("scan_type", cfg.recon.scan_type)
    cfg.recon.port_range = ps.get("port_range", cfg.recon.port_range)
    cfg.recon.full_port_range = ps.get("full_range", cfg.recon.full_port_range)
    cfg.recon.service_detection = ps.get("service_detection", cfg.recon.service_detection)
    cfg.recon.os_detection = ps.get("os_detection", cfg.recon.os_detection)
    cfg.recon.script_scan = ps.get("script_scan", cfg.recon.script_scan)
    cfg.recon.timing = ps.get("timing", cfg.recon.timing)

    web = recon.get("web", {})
    cfg.recon.web_wordlist = web.get("wordlist", cfg.recon.web_wordlist)
    cfg.recon.web_extensions = web.get("extensions", cfg.recon.web_extensions)
    cfg.recon.user_agent = web.get("user_agent", cfg.recon.user_agent)

    vuln = recon.get("vuln", {})
    cfg.recon.nvd_api_url = vuln.get("nvd_api_url", cfg.recon.nvd_api_url)
    cfg.recon.exploitdb_search = vuln.get("exploitdb_search", cfg.recon.exploitdb_search)

    # Exploit
    exploit = raw.get("exploit", {})
    bf = exploit.get("brute_force", {})
    cfg.exploit.ssh_wordlist = bf.get("ssh_wordlist", cfg.exploit.ssh_wordlist)
    cfg.exploit.username_list = bf.get("username_list", cfg.exploit.username_list)
    cfg.exploit.max_brute_attempts = bf.get("max_attempts", cfg.exploit.max_brute_attempts)
    cfg.exploit.parallel_tasks = bf.get("parallel_tasks", cfg.exploit.parallel_tasks)
    cfg.exploit.brute_timeout = bf.get("timeout", cfg.exploit.brute_timeout)

    eweb = exploit.get("web", {})
    cfg.exploit.sqlmap_level = eweb.get("sqlmap_level", cfg.exploit.sqlmap_level)
    cfg.exploit.sqlmap_risk = eweb.get("sqlmap_risk", cfg.exploit.sqlmap_risk)
    cfg.exploit.test_xss = eweb.get("test_xss", cfg.exploit.test_xss)
    cfg.exploit.test_lfi = eweb.get("test_lfi", cfg.exploit.test_lfi)
    cfg.exploit.test_rfi = eweb.get("test_rfi", cfg.exploit.test_rfi)
    cfg.exploit.test_cmdi = eweb.get("test_cmdi", cfg.exploit.test_cmdi)

    ae = exploit.get("auto_exploit", {})
    cfg.exploit.auto_exploit = ae.get("enabled", cfg.exploit.auto_exploit)
    cfg.exploit.max_cvss = ae.get("max_cvss_threshold", cfg.exploit.max_cvss)
    cfg.exploit.min_cvss = ae.get("min_cvss_threshold", cfg.exploit.min_cvss)

    # Dashboard
    dash = raw.get("dashboard", {})
    cfg.dashboard.host = dash.get("host", cfg.dashboard.host)
    cfg.dashboard.port = dash.get("port", cfg.dashboard.port)
    cfg.dashboard.debug = dash.get("debug", cfg.dashboard.debug)

    return cfg
