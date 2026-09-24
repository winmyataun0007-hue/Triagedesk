"""
MITRE ATT&CK (Enterprise) technique reference — the subset used by TriageDesk.

Alerts carry an ATT&CK technique id so the analyst sees the adversary's intent,
not just a tool-specific rule name. The dashboard's coverage view and the
incident summaries read from this table.

Source: MITRE ATT&CK Enterprise matrix (https://attack.mitre.org/).
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command and Control"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1486": {"name": "Data Encrypted for Impact (Ransomware)", "tactic": "Impact"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1021": {"name": "Remote Services (Lateral Movement)", "tactic": "Lateral Movement"},
    "T1567": {"name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration"},
}

# Analyst response playbooks, keyed by technique. Kept short and practical —
# these are the first moves a tier-1 analyst should make.
PLAYBOOKS: dict[str, list[str]] = {
    "T1110": [
        "Confirm the number of failed logons and whether any succeeded (check for a success after the burst).",
        "Identify the targeted account(s) and whether they are privileged.",
        "If a logon succeeded, treat as compromise: disable the account and reset credentials.",
        "Block the source IP at the perimeter and enable MFA if not already enforced.",
    ],
    "T1078": [
        "Verify whether the account activity matches the user's normal hours, location and device.",
        "Check for impossible travel and concurrent sessions.",
        "If unauthorized, revoke sessions, reset credentials and review what the account accessed.",
    ],
    "T1566": [
        "Pull the email headers and confirm sender spoofing / lookalike domain.",
        "Identify all recipients and whether any clicked or entered credentials.",
        "Quarantine the message tenant-wide and reset credentials for anyone who interacted.",
    ],
    "T1486": [
        "Isolate the affected host from the network immediately.",
        "Identify the ransomware family and check for a known decryptor.",
        "Confirm backup integrity before any recovery; preserve evidence.",
        "Escalate to incident lead — this is a P1.",
    ],
    "T1071": [
        "Confirm the destination is a known-bad or newly-registered domain/IP.",
        "Identify the process and host initiating the beacon.",
        "Block the C2 destination and isolate the host for forensics.",
    ],
    "T1046": [
        "Confirm the scan source and whether it is an internal asset.",
        "Determine scope: how many hosts/ports were touched.",
        "If external, block at the firewall; if internal, treat as possible lateral movement.",
    ],
    "T1190": [
        "Identify the targeted application and whether the exploit attempt succeeded.",
        "Check the application logs for follow-on activity (web shell, new files).",
        "Patch or virtually-patch the vulnerability; block the source.",
    ],
    "T1048": [
        "Quantify the volume and destination of the outbound transfer.",
        "Confirm whether the destination is sanctioned.",
        "Contain the host and preserve netflow evidence; assess data exposure.",
    ],
}

DEFAULT_PLAYBOOK = [
    "Validate the alert against the raw event and enrichment before escalating.",
    "Confirm whether the source and destination are known assets.",
    "Assess impact and scope; check for related alerts on the same host or user.",
    "Escalate to a senior analyst if the activity cannot be explained.",
]


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, {}).get("name", "Unknown Technique")


def tactic(tid: str) -> str:
    return TECHNIQUES.get(tid, {}).get("tactic", "Unknown")


def playbook_for(techniques: list[str]) -> list[str]:
    for t in techniques:
        if t in PLAYBOOKS:
            return PLAYBOOKS[t]
    return DEFAULT_PLAYBOOK
