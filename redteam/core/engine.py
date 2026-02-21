"""
RedTeam Engine - Main orchestration engine for the attack lifecycle.
Drives the entire engagement from reconnaissance through post-exploitation.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from redteam.config import FrameworkConfig, load_config
from redteam.core.attack_lifecycle import (
    AttackPhase, AttackStep, StepStatus, Severity,
    Engagement, Target, PHASE_TRANSITIONS,
)
from redteam.core.event_bus import event_bus, Event
from redteam.core.plugin_loader import load_all_plugins, plugin_registry
from redteam.mitre.attack_map import get_technique


logger = logging.getLogger("redteam.engine")


class RedTeamEngine:
    """
    Main orchestration engine for the red team simulation.
    
    Drives the attack lifecycle state machine:
    INIT → RECON → SCANNING → ENUMERATION → EXPLOITATION → 
    PRIV_ESCALATION → LATERAL_MOVEMENT → PERSISTENCE → REPORTING → COMPLETE
    """

    def __init__(self, config: FrameworkConfig = None):
        self.config = config or load_config()
        self.engagement = Engagement(name=self.config.engagement_name)
        self._running = False
        self._setup_logging()
        self._setup_output_dir()

    def _setup_logging(self):
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def _setup_output_dir(self):
        self.output_dir = Path(self.config.output_dir) / self.engagement.id[:8]
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")

    def add_target(self, target_str: str) -> list[str]:
        """
        Add targets from input string.
        Supports: single IP, CIDR range, hostname, comma-separated list.
        """
        targets = []
        for item in target_str.split(","):
            item = item.strip()
            if not item:
                continue

            if "/" in item and not item.startswith("http"):
                # CIDR notation — expand to individual IPs
                try:
                    import ipaddress
                    network = ipaddress.ip_network(item, strict=False)
                    for ip in network.hosts():
                        ip_str = str(ip)
                        self.engagement.add_target(ip_str)
                        targets.append(ip_str)
                except ValueError:
                    self.engagement.add_target(item, hostname=item)
                    targets.append(item)
            else:
                self.engagement.add_target(item)
                targets.append(item)

        logger.info(f"Added {len(targets)} target(s): {targets}")
        return targets

    async def _transition_phase(self, new_phase: AttackPhase) -> bool:
        """Transition to a new attack phase."""
        current = self.engagement.current_phase
        allowed = PHASE_TRANSITIONS.get(current, [])

        if new_phase not in allowed:
            logger.warning(f"Invalid transition: {current.value} → {new_phase.value}")
            return False

        old_phase = current
        self.engagement.current_phase = new_phase
        logger.info(f"Phase transition: {old_phase.value} → {new_phase.value}")

        await event_bus.emit("phase_change", {
            "from": old_phase.value,
            "to": new_phase.value,
        }, source="engine")

        return True

    def _record_step(self, phase: AttackPhase, technique_id: str,
                     module: str, target: str, action: str,
                     result: dict, status: StepStatus,
                     severity: Severity = Severity.INFO,
                     parent_id: str = None) -> AttackStep:
        """Record an attack step in the engagement."""
        technique = get_technique(technique_id)
        step = AttackStep(
            phase=phase,
            technique_id=technique_id,
            technique_name=technique.get("name", "") if technique else "",
            module=module,
            target=target,
            action=action,
            result=result,
            status=status,
            severity=severity,
            parent_step_id=parent_id,
        )
        self.engagement.add_step(step)
        event_bus.emit_sync("step_added", step.to_dict(), source=module)
        return step

    async def run_full_engagement(self, target_str: str) -> Engagement:
        """
        Run a complete automated red team engagement.
        
        Args:
            target_str: Target IP, hostname, CIDR, or comma-separated list.
            
        Returns:
            Completed Engagement object with all findings.
        """
        self._running = True
        logger.info(f"Starting engagement: {self.engagement.name}")
        logger.info(f"Engagement ID: {self.engagement.id}")

        # Load plugins
        load_all_plugins(plugin_registry)

        # Parse targets
        targets = self.add_target(target_str)
        if not targets:
            logger.error("No valid targets specified.")
            return self.engagement

        try:
            # Phase 1: Reconnaissance
            await self._run_recon(targets)

            # Phase 2: Scanning & Enumeration
            await self._run_scanning(targets)

            # Phase 3: Exploitation
            await self._run_exploitation(targets)

            # Phase 4: Post-Exploitation
            await self._run_post_exploitation(targets)

            # Phase 5: Reporting
            await self._run_reporting()

        except KeyboardInterrupt:
            logger.warning("Engagement interrupted by user.")
        except Exception as e:
            logger.error(f"Engagement error: {e}", exc_info=True)
        finally:
            self.engagement.end_time = datetime.now().isoformat()
            self.engagement.current_phase = AttackPhase.COMPLETE
            self._running = False
            self._save_engagement_data()

        return self.engagement

    async def run_recon_only(self, target_str: str) -> Engagement:
        """Run only the reconnaissance phase."""
        self._running = True
        load_all_plugins(plugin_registry)
        targets = self.add_target(target_str)

        try:
            await self._run_recon(targets)
            await self._run_scanning(targets)
        finally:
            self.engagement.end_time = datetime.now().isoformat()
            self._running = False
            self._save_engagement_data()

        return self.engagement

    async def _run_recon(self, targets: list[str]):
        """Execute reconnaissance phase."""
        await self._transition_phase(AttackPhase.RECON)

        for target_ip in targets:
            target = self.engagement.get_target(target_ip)

            # Subdomain enumeration (if target is a hostname)
            try:
                from redteam.recon.subdomain_enum import SubdomainEnumerator
                enumerator = SubdomainEnumerator(self.config.recon, event_bus)
                subs = await enumerator.enumerate(target_ip)
                target.subdomains = subs

                self._record_step(
                    AttackPhase.RECON, "T1596", "subdomain_enum", target_ip,
                    f"Subdomain enumeration found {len(subs)} subdomains",
                    {"subdomains": subs[:20]},  # Cap output
                    StepStatus.SUCCESS if subs else StepStatus.SKIPPED,
                    Severity.INFO,
                )
            except Exception as e:
                logger.warning(f"Subdomain enum failed for {target_ip}: {e}")
                self._record_step(
                    AttackPhase.RECON, "T1596", "subdomain_enum", target_ip,
                    f"Subdomain enumeration failed: {e}",
                    {"error": str(e)},
                    StepStatus.ERROR,
                )

    async def _run_scanning(self, targets: list[str]):
        """Execute scanning and enumeration phase."""
        await self._transition_phase(AttackPhase.SCANNING)

        for target_ip in targets:
            target = self.engagement.get_target(target_ip)

            # Port scanning
            try:
                from redteam.recon.port_scanner import PortScanner
                scanner = PortScanner(self.config.recon, event_bus)
                scan_result = await scanner.scan(target_ip)
                target.open_ports = scan_result.get("ports", [])
                target.services = scan_result.get("services", [])
                target.os = scan_result.get("os", "")

                self._record_step(
                    AttackPhase.SCANNING, "T1046", "port_scanner", target_ip,
                    f"Port scan found {len(target.open_ports)} open ports",
                    scan_result,
                    StepStatus.SUCCESS,
                    Severity.MEDIUM,
                )
            except Exception as e:
                logger.warning(f"Port scan failed for {target_ip}: {e}")
                self._record_step(
                    AttackPhase.SCANNING, "T1046", "port_scanner", target_ip,
                    f"Port scan failed: {e}",
                    {"error": str(e)},
                    StepStatus.ERROR,
                )

            # OS Fingerprinting
            try:
                from redteam.recon.os_fingerprint import OSFingerprinter
                fingerprinter = OSFingerprinter(self.config.recon, event_bus)
                os_info = await fingerprinter.fingerprint(target_ip)
                target.os = os_info.get("os", target.os)
                target.os_version = os_info.get("version", "")

                self._record_step(
                    AttackPhase.SCANNING, "T1082", "os_fingerprint", target_ip,
                    f"OS detection: {target.os} {target.os_version}",
                    os_info,
                    StepStatus.SUCCESS,
                    Severity.LOW,
                )
            except Exception as e:
                logger.warning(f"OS fingerprint failed for {target_ip}: {e}")

            # Vulnerability scanning
            try:
                from redteam.recon.vuln_scanner import VulnScanner
                vuln_scanner = VulnScanner(self.config.recon, event_bus)
                vulns = await vuln_scanner.scan(target_ip, target.services)
                target.vulnerabilities = vulns

                for vuln in vulns:
                    severity = Severity.CRITICAL if vuln.get("cvss", 0) >= 9.0 \
                        else Severity.HIGH if vuln.get("cvss", 0) >= 7.0 \
                        else Severity.MEDIUM if vuln.get("cvss", 0) >= 4.0 \
                        else Severity.LOW

                    self._record_step(
                        AttackPhase.SCANNING, "T1595", "vuln_scanner", target_ip,
                        f"Vulnerability found: {vuln.get('cve_id', 'Unknown')} (CVSS: {vuln.get('cvss', 'N/A')})",
                        vuln,
                        StepStatus.SUCCESS,
                        severity,
                    )
                    await event_bus.emit("vuln_found", vuln, source="vuln_scanner")

            except Exception as e:
                logger.warning(f"Vuln scan failed for {target_ip}: {e}")

            # Web reconnaissance (if HTTP/HTTPS services found)
            web_ports = [p for p in target.open_ports
                         if p.get("service", "").startswith("http") or p.get("port") in [80, 443, 8080, 8443]]
            if web_ports:
                try:
                    from redteam.recon.web_recon import WebRecon
                    web_recon = WebRecon(self.config.recon, event_bus)
                    web_info = await web_recon.scan(target_ip, web_ports)
                    target.web_directories = web_info.get("directories", [])

                    self._record_step(
                        AttackPhase.SCANNING, "T1592", "web_recon", target_ip,
                        f"Web recon: {len(target.web_directories)} directories, {len(web_info.get('technologies', []))} technologies",
                        web_info,
                        StepStatus.SUCCESS,
                        Severity.MEDIUM,
                    )
                except Exception as e:
                    logger.warning(f"Web recon failed for {target_ip}: {e}")

        # Transition to enumeration
        await self._transition_phase(AttackPhase.ENUMERATION)

    async def _run_exploitation(self, targets: list[str]):
        """Execute exploitation phase."""
        await self._transition_phase(AttackPhase.EXPLOITATION)

        for target_ip in targets:
            target = self.engagement.get_target(target_ip)

            # Auto-select exploits based on discovered vulnerabilities
            try:
                from redteam.exploit.exploit_selector import ExploitSelector
                selector = ExploitSelector(self.config.exploit, event_bus)
                selected = selector.select_exploits(target)

                for exploit_info in selected:
                    await event_bus.emit("exploit_attempt", {
                        "target": target_ip,
                        "exploit": exploit_info.get("name", ""),
                    }, source="exploit_selector")

                    self._record_step(
                        AttackPhase.EXPLOITATION,
                        exploit_info.get("technique_id", "T1190"),
                        exploit_info.get("module", "exploit_selector"),
                        target_ip,
                        f"Exploit selected: {exploit_info.get('name', 'Unknown')}",
                        exploit_info,
                        StepStatus.SUCCESS,
                        Severity.HIGH,
                    )
            except Exception as e:
                logger.warning(f"Exploit selection failed for {target_ip}: {e}")

            # Brute force attacks on discovered services
            brute_services = [s for s in target.services
                              if s.get("name", "") in ["ssh", "ftp", "smb", "rdp", "telnet"]]
            if brute_services:
                try:
                    from redteam.exploit.brute_force import BruteForcer
                    bruteforcer = BruteForcer(self.config.exploit, event_bus)
                    creds = await bruteforcer.attack(target_ip, brute_services)

                    if creds:
                        target.credentials.extend(creds)
                        target.compromised = True
                        target.access_level = "user"

                        self._record_step(
                            AttackPhase.EXPLOITATION, "T1110", "brute_force", target_ip,
                            f"Brute force: {len(creds)} credential(s) found",
                            {"credentials": [{"user": c["user"], "service": c["service"]} for c in creds]},
                            StepStatus.SUCCESS,
                            Severity.CRITICAL,
                        )
                        await event_bus.emit("shell_obtained", {
                            "target": target_ip,
                            "method": "brute_force",
                        }, source="brute_force")
                except Exception as e:
                    logger.warning(f"Brute force failed for {target_ip}: {e}")

            # Web exploitation
            web_ports = [p for p in target.open_ports
                         if p.get("service", "").startswith("http") or p.get("port") in [80, 443, 8080, 8443]]
            if web_ports:
                try:
                    from redteam.exploit.web_exploits import WebExploiter
                    exploiter = WebExploiter(self.config.exploit, event_bus)
                    web_results = await exploiter.exploit(target_ip, web_ports, target.web_directories)

                    for result in web_results:
                        sev = Severity.CRITICAL if result.get("type") in ["sqli", "rce"] else Severity.HIGH
                        self._record_step(
                            AttackPhase.EXPLOITATION, "T1190", "web_exploits", target_ip,
                            f"Web exploit: {result.get('type', 'unknown')} on {result.get('url', '')}",
                            result,
                            StepStatus.SUCCESS if result.get("vulnerable") else StepStatus.FAILED,
                            sev,
                        )
                        if result.get("vulnerable"):
                            target.compromised = True
                except Exception as e:
                    logger.warning(f"Web exploitation failed for {target_ip}: {e}")

            # CVE-based exploitation
            if target.vulnerabilities:
                try:
                    from redteam.exploit.cve_exploits import CVEExploiter
                    cve_exploiter = CVEExploiter(self.config.exploit, event_bus)
                    cve_results = await cve_exploiter.exploit(target_ip, target.vulnerabilities)

                    for result in cve_results:
                        self._record_step(
                            AttackPhase.EXPLOITATION, "T1203", "cve_exploits", target_ip,
                            f"CVE exploit: {result.get('cve_id', 'Unknown')} - {result.get('status', '')}",
                            result,
                            StepStatus.SUCCESS if result.get("exploited") else StepStatus.FAILED,
                            Severity.CRITICAL,
                        )
                except Exception as e:
                    logger.warning(f"CVE exploitation failed for {target_ip}: {e}")

    async def _run_post_exploitation(self, targets: list[str]):
        """Execute post-exploitation phase on compromised targets."""
        compromised = [t for t in targets if self.engagement.get_target(t).compromised]

        if not compromised:
            logger.info("No compromised targets - skipping post-exploitation.")
            return

        # Privilege Escalation
        await self._transition_phase(AttackPhase.PRIV_ESCALATION)
        for target_ip in compromised:
            target = self.engagement.get_target(target_ip)
            try:
                from redteam.post_exploit.priv_escalation import PrivEscalation
                priv_esc = PrivEscalation(self.config.post_exploit, event_bus)
                esc_results = await priv_esc.check(target_ip, target)

                for result in esc_results:
                    self._record_step(
                        AttackPhase.PRIV_ESCALATION, "T1068", "priv_escalation", target_ip,
                        f"Priv esc: {result.get('method', 'Unknown')}",
                        result,
                        StepStatus.SUCCESS if result.get("exploitable") else StepStatus.FAILED,
                        Severity.HIGH,
                    )
                    if result.get("exploitable"):
                        target.access_level = result.get("new_level", "admin")
                        await event_bus.emit("priv_escalated", {
                            "target": target_ip,
                            "method": result.get("method"),
                            "new_level": target.access_level,
                        }, source="priv_escalation")
            except Exception as e:
                logger.warning(f"Priv escalation failed for {target_ip}: {e}")

        # Persistence
        await self._transition_phase(AttackPhase.PERSISTENCE)
        for target_ip in compromised:
            target = self.engagement.get_target(target_ip)
            try:
                from redteam.post_exploit.persistence import PersistenceChecker
                persistence = PersistenceChecker(self.config.post_exploit, event_bus)
                persist_results = await persistence.check(target_ip, target)

                for result in persist_results:
                    self._record_step(
                        AttackPhase.PERSISTENCE, "T1053", "persistence", target_ip,
                        f"Persistence: {result.get('mechanism', 'Unknown')}",
                        result,
                        StepStatus.SUCCESS,
                        Severity.HIGH,
                    )
            except Exception as e:
                logger.warning(f"Persistence check failed for {target_ip}: {e}")

        # Credential Harvesting
        await self._transition_phase(AttackPhase.CREDENTIAL_ACCESS)
        for target_ip in compromised:
            target = self.engagement.get_target(target_ip)
            try:
                from redteam.post_exploit.credential_harvest import CredentialHarvester
                harvester = CredentialHarvester(self.config.post_exploit, event_bus)
                creds = await harvester.harvest(target_ip, target)

                if creds:
                    target.credentials.extend(creds)
                    self._record_step(
                        AttackPhase.CREDENTIAL_ACCESS, "T1003", "credential_harvest", target_ip,
                        f"Credentials harvested: {len(creds)} found",
                        {"count": len(creds)},
                        StepStatus.SUCCESS,
                        Severity.CRITICAL,
                    )
                    await event_bus.emit("credentials_found", {
                        "target": target_ip,
                        "count": len(creds),
                    }, source="credential_harvest")
            except Exception as e:
                logger.warning(f"Credential harvesting failed for {target_ip}: {e}")

        # Lateral Movement
        await self._transition_phase(AttackPhase.LATERAL_MOVEMENT)
        for target_ip in compromised:
            target = self.engagement.get_target(target_ip)
            try:
                from redteam.post_exploit.lateral_movement import LateralMovement
                lateral = LateralMovement(self.config.post_exploit, event_bus)
                move_results = await lateral.move(target_ip, target, self.engagement)

                for result in move_results:
                    self._record_step(
                        AttackPhase.LATERAL_MOVEMENT, "T1021", "lateral_movement", target_ip,
                        f"Lateral movement: {result.get('method', '')} → {result.get('new_target', '')}",
                        result,
                        StepStatus.SUCCESS if result.get("success") else StepStatus.FAILED,
                        Severity.HIGH,
                    )
                    if result.get("success"):
                        await event_bus.emit("lateral_move", result, source="lateral_movement")
            except Exception as e:
                logger.warning(f"Lateral movement failed for {target_ip}: {e}")

    async def _run_reporting(self):
        """Generate final reports."""
        await self._transition_phase(AttackPhase.REPORTING)

        try:
            from redteam.reporting.report_generator import ReportGenerator
            generator = ReportGenerator(self.config.report, self.output_dir)
            report_path = generator.generate(self.engagement)

            self._record_step(
                AttackPhase.REPORTING, "", "report_generator", "all",
                f"Report generated: {report_path}",
                {"path": str(report_path)},
                StepStatus.SUCCESS,
                Severity.INFO,
            )
            logger.info(f"Report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Report generation failed: {e}")

        try:
            from redteam.reporting.attack_graph import AttackGraphBuilder
            graph_builder = AttackGraphBuilder()
            graph_path = graph_builder.build_and_export(self.engagement, self.output_dir)

            self._record_step(
                AttackPhase.REPORTING, "", "attack_graph", "all",
                f"Attack graph exported: {graph_path}",
                {"path": str(graph_path)},
                StepStatus.SUCCESS,
                Severity.INFO,
            )
        except Exception as e:
            logger.error(f"Attack graph generation failed: {e}")

        try:
            from redteam.mitre.navigator import NavigatorExporter
            exporter = NavigatorExporter()
            nav_path = exporter.export(self.engagement, self.output_dir)
            logger.info(f"MITRE Navigator layer saved to: {nav_path}")
        except Exception as e:
            logger.error(f"Navigator export failed: {e}")

    def _save_engagement_data(self):
        """Save raw engagement data as JSON."""
        data_path = self.output_dir / "engagement_data.json"
        with open(data_path, "w") as f:
            json.dump(self.engagement.to_dict(), f, indent=2, default=str)
        logger.info(f"Engagement data saved to: {data_path}")


def run_engine(target: str, config_path: str = None, recon_only: bool = False) -> Engagement:
    """Convenience function to run the engine synchronously."""
    config = load_config(config_path)
    engine = RedTeamEngine(config)

    if recon_only:
        return asyncio.run(engine.run_recon_only(target))
    return asyncio.run(engine.run_full_engagement(target))
