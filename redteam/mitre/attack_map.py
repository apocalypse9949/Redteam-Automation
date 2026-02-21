"""
MITRE ATT&CK Technique Database.
Provides lookup for common ATT&CK techniques used in red team operations.
"""

from typing import Any


# Comprehensive MITRE ATT&CK technique database
# Source: https://attack.mitre.org/techniques/enterprise/
ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    # Reconnaissance
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1595.001": {
        "name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victim IP blocks to gather information for targeting.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1595/002/",
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's hosts that can be used during targeting.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1592/",
    },
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic": "Reconnaissance",
        "description": "Adversaries may search freely available technical databases for information about victims.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1596/",
    },
    "T1593": {
        "name": "Search Open Websites/Domains",
        "tactic": "Reconnaissance",
        "description": "Adversaries may search freely available websites and/or domains for information about victims.",
        "platforms": ["PRE"],
        "url": "https://attack.mitre.org/techniques/T1593/",
    },

    # Discovery
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories or may search in specific locations of a host.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1049/",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other information.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about network configuration and settings.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1016/",
    },

    # Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
        "platforms": ["Windows", "Linux", "macOS", "Containers"],
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1133/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Google Workspace"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },

    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1203/",
    },

    # Credential Access
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD", "Google Workspace"],
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries with no prior knowledge of legitimate credentials may guess passwords to attempt access.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD"],
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in the Local Security Authority Subsystem Service.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1003.002": {
        "name": "OS Credential Dumping: Security Account Manager",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to extract credential material from the SAM database.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1003/002/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1552/",
    },

    # Privilege Escalation
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1548.002": {
        "name": "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may bypass UAC mechanisms to elevate process privileges on system.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1548/002/",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1134/",
    },

    # Lateral Movement
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a service that accepts remote connections.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into a computer using RDP.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to interact with a remote network share using SMB.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into remote machines using SSH.",
        "platforms": ["Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, etc.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1550/",
    },
    "T1550.002": {
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "tactic": "Lateral Movement",
        "description": "Adversaries may 'pass the hash' using stolen password hashes to lateral move.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1550/002/",
    },

    # Persistence
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for execution.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "description": "Adversaries may abuse the cron utility to perform task scheduling for execution.",
        "platforms": ["Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1547/",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
        "platforms": ["Windows"],
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create an account to maintain access to victim systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.",
        "platforms": ["Windows", "Linux", "macOS", "Azure AD"],
        "url": "https://attack.mitre.org/techniques/T1098/",
    },

    # Defense Evasion
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1027/",
    },

    # Collection
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system sources, such as file systems and configuration files.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1005/",
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactic": "Collection",
        "description": "Adversaries may search network shares on computers they have compromised to find files of interest.",
        "platforms": ["Windows", "Linux", "macOS"],
        "url": "https://attack.mitre.org/techniques/T1039/",
    },
}


def get_technique(technique_id: str) -> dict | None:
    """Look up a MITRE ATT&CK technique by ID."""
    return ATTACK_TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> list[dict]:
    """Get all techniques for a given tactic."""
    return [
        {"id": tid, **info}
        for tid, info in ATTACK_TECHNIQUES.items()
        if info["tactic"].lower() == tactic.lower()
    ]


def get_all_tactics() -> list[str]:
    """Get unique list of all tactics."""
    return sorted(set(t["tactic"] for t in ATTACK_TECHNIQUES.values()))


def search_techniques(keyword: str) -> list[dict]:
    """Search techniques by name or description keyword."""
    keyword_lower = keyword.lower()
    return [
        {"id": tid, **info}
        for tid, info in ATTACK_TECHNIQUES.items()
        if keyword_lower in info["name"].lower() or keyword_lower in info["description"].lower()
    ]
