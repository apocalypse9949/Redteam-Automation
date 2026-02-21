"""
Attack Lifecycle - Phase definitions and attack step data structures.
Defines the state machine for the red team engagement.
"""

import uuid
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class AttackPhase(Enum):
    """Phases of the attack lifecycle mapped to MITRE ATT&CK tactics."""
    INIT = "Initialization"
    RECON = "Reconnaissance"
    SCANNING = "Discovery"
    ENUMERATION = "Enumeration"
    EXPLOITATION = "Initial Access"
    PRIV_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    CREDENTIAL_ACCESS = "Credential Access"
    EXFILTRATION = "Collection"
    REPORTING = "Reporting"
    COMPLETE = "Complete"


class StepStatus(Enum):
    """Status of an individual attack step."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class Severity(Enum):
    """Vulnerability / finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AttackStep:
    """Represents a single step in the attack chain."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    phase: AttackPhase = AttackPhase.INIT
    technique_id: str = ""          # MITRE ATT&CK technique ID (e.g., T1046)
    technique_name: str = ""        # Human-readable technique name
    module: str = ""                # Module that executed this step
    target: str = ""                # Target IP/hostname/URL
    action: str = ""                # Description of what was done
    result: dict = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    severity: Severity = Severity.INFO
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    parent_step_id: str | None = None  # For building attack chains
    children: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # Screenshots, logs, output

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "phase": self.phase.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "module": self.module,
            "target": self.target,
            "action": self.action,
            "result": self.result,
            "status": self.status.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "parent_step_id": self.parent_step_id,
            "children": self.children,
            "evidence": self.evidence,
        }


@dataclass
class Target:
    """Represents a target host in the engagement."""
    ip: str
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    open_ports: list[dict] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    access_level: str = "none"  # none, user, admin, root, system
    compromised: bool = False
    subdomains: list[str] = field(default_factory=list)
    web_directories: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "os_version": self.os_version,
            "open_ports": self.open_ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "credentials": self.credentials,
            "access_level": self.access_level,
            "compromised": self.compromised,
            "subdomains": self.subdomains,
            "web_directories": self.web_directories,
            "notes": self.notes,
        }


@dataclass
class Engagement:
    """Represents a complete red team engagement session."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "RedTeam Engagement"
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str | None = None
    current_phase: AttackPhase = AttackPhase.INIT
    targets: dict[str, Target] = field(default_factory=dict)  # ip -> Target
    attack_steps: list[AttackStep] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    mitre_techniques_used: set = field(default_factory=set)

    def add_target(self, ip: str, hostname: str = "") -> Target:
        if ip not in self.targets:
            self.targets[ip] = Target(ip=ip, hostname=hostname)
        return self.targets[ip]

    def add_step(self, step: AttackStep) -> None:
        self.attack_steps.append(step)
        if step.technique_id:
            self.mitre_techniques_used.add(step.technique_id)

    def get_target(self, ip: str) -> Target | None:
        return self.targets.get(ip)

    def get_compromised_targets(self) -> list[Target]:
        return [t for t in self.targets.values() if t.compromised]

    def get_steps_by_phase(self, phase: AttackPhase) -> list[AttackStep]:
        return [s for s in self.attack_steps if s.phase == phase]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "current_phase": self.current_phase.value,
            "targets": {ip: t.to_dict() for ip, t in self.targets.items()},
            "attack_steps": [s.to_dict() for s in self.attack_steps],
            "findings": self.findings,
            "mitre_techniques_used": list(self.mitre_techniques_used),
        }


# Phase transition rules
PHASE_TRANSITIONS = {
    AttackPhase.INIT: [AttackPhase.RECON],
    AttackPhase.RECON: [AttackPhase.SCANNING],
    AttackPhase.SCANNING: [AttackPhase.ENUMERATION],
    AttackPhase.ENUMERATION: [AttackPhase.EXPLOITATION, AttackPhase.REPORTING],
    AttackPhase.EXPLOITATION: [AttackPhase.PRIV_ESCALATION, AttackPhase.LATERAL_MOVEMENT, AttackPhase.REPORTING],
    AttackPhase.PRIV_ESCALATION: [AttackPhase.LATERAL_MOVEMENT, AttackPhase.PERSISTENCE, AttackPhase.REPORTING],
    AttackPhase.LATERAL_MOVEMENT: [AttackPhase.EXPLOITATION, AttackPhase.CREDENTIAL_ACCESS, AttackPhase.REPORTING],
    AttackPhase.PERSISTENCE: [AttackPhase.CREDENTIAL_ACCESS, AttackPhase.REPORTING],
    AttackPhase.CREDENTIAL_ACCESS: [AttackPhase.LATERAL_MOVEMENT, AttackPhase.REPORTING],
    AttackPhase.EXFILTRATION: [AttackPhase.REPORTING],
    AttackPhase.REPORTING: [AttackPhase.COMPLETE],
    AttackPhase.COMPLETE: [],
}
