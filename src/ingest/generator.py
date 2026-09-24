"""
Synthetic alert generator.

A SOC platform is impossible to demonstrate without a stream of alerts, and real
feeds cannot be shipped in a student project. This generator produces realistic,
varied alerts in the *native formats* of different tools (Wazuh JSON, Suricata
EVE, generic), so it exercises the normalizer end-to-end rather than shortcutting
it. Some alerts deliberately reference known-bad IPs from the bundled threat feed
and crown-jewel assets from the inventory, so enrichment and risk scoring have
something real to act on.

Timestamps are spread across the recent past so that, the moment the dashboard
loads, incidents already show realistic SLA states — some on track, some at risk,
some breached. All randomness is seeded for reproducibility.
"""

from __future__ import annotations

import random
from typing import Any

from src.common.util import now

# Known-bad sources from the bundled feed (see enrich/intel/threat_iocs.json).
BAD_IPS = ["45.146.164.110", "91.240.118.172", "193.106.191.22", "146.70.199.30",
           "62.204.41.15", "5.188.206.18", "185.220.101.45"]
# Genuinely public IPs with no threat-feed match (note: the 203.0.113.0/24 and
# 198.51.100.0/24 documentation ranges are treated as private by Python 3.11+,
# so they cannot be used as "external clean" addresses).
CLEAN_EXT_IPS = ["77.75.120.5", "104.244.42.65", "151.101.1.140", "129.21.1.40"]
ASSETS = ["10.0.10.5", "10.0.10.20", "10.0.20.10", "10.0.30.15", "10.0.40.100",
          "10.0.40.101", "10.0.40.102", "10.0.50.5"]
USERS = ["jsmith", "achen", "mpatel", "ssuzuki", "admin", "svc_backup", "ceo"]

# Alert templates: (weight, builder). Each builder returns a native-format event.


def _brute_force(rng, ts):
    src = rng.choice(["91.240.118.172", "91.240.118.172", rng.choice(CLEAN_EXT_IPS)])
    return "wazuh", {
        "timestamp_epoch": ts,
        "rule": {"id": "5710", "level": 10, "description": "sshd: Multiple authentication failures",
                 "groups": ["authentication_failures", "syslog", "sshd"],
                 "mitre": {"id": ["T1110"]}},
        "data": {"srcip": src, "dstuser": rng.choice(USERS), "dstport": "22"},
        "agent": {"name": "DC01", "ip": "10.0.10.20"},
    }


def _successful_login_after_bf(rng, ts):
    return "wazuh", {
        "timestamp_epoch": ts,
        "rule": {"id": "5715", "level": 12, "description": "sshd: authentication success after brute force",
                 "groups": ["authentication_success"], "mitre": {"id": ["T1078"]}},
        "data": {"srcip": "91.240.118.172", "dstuser": "svc_backup", "dstport": "22"},
        "agent": {"name": "FILE-SRV", "ip": "10.0.30.15"},
    }


def _c2_beacon(rng, ts):
    return "suricata", {
        "timestamp_epoch": ts,
        "src_ip": rng.choice(ASSETS[:6]),
        "dest_ip": "45.146.164.110",
        "dest_port": 443,
        "alert": {"signature_id": "2028700", "severity": 1,
                  "signature": "ET MALWARE Cobalt Strike Beacon Observed",
                  "category": "c2"},
    }


def _port_scan(rng, ts):
    return "suricata", {
        "timestamp_epoch": ts,
        "src_ip": "193.106.191.22",
        "dest_ip": rng.choice(ASSETS),
        "dest_port": rng.choice([22, 445, 3389, 8080]),
        "alert": {"signature_id": "2001219", "severity": 2,
                  "signature": "ET SCAN Potential SSH/Port Scan", "category": "recon"},
    }


def _phishing(rng, ts):
    return "generic", {
        "ts": ts, "source": "email_gw", "rule_id": "PHISH-002",
        "title": "Credential phishing email delivered",
        "severity": "high", "src_ip": "62.204.41.15",
        "dst_ip": rng.choice(["10.0.40.100", "10.0.40.102"]),
        "user": rng.choice(USERS), "category": "phishing", "technique": "T1566",
        "description": "Email with credential-harvesting link to secure-login-verify.info",
    }


def _ransomware(rng, ts):
    return "generic", {
        "ts": ts, "source": "edr", "rule_id": "EDR-RANSOM-01",
        "title": "Mass file encryption behaviour detected",
        "severity": "critical", "src_ip": "", "dst_ip": "10.0.30.15",
        "host": "FILE-SRV", "user": "svc_backup", "category": "malware",
        "technique": "T1486",
        "description": "Rapid rename of 4,000+ files to .locked extension",
    }


def _exfil(rng, ts):
    return "generic", {
        "ts": ts, "source": "firewall", "rule_id": "FW-EXFIL-09",
        "title": "Large outbound transfer to untrusted host",
        "severity": "high", "src_ip": "10.0.10.5", "dst_ip": "5.188.206.18",
        "dst_port": 443, "host": "PAYROLL-DB", "category": "exfiltration",
        "technique": "T1048",
        "description": "1.8 GB outbound over 20 minutes to external endpoint",
    }


def _exploit(rng, ts):
    return "suricata", {
        "timestamp_epoch": ts,
        "src_ip": rng.choice(BAD_IPS + CLEAN_EXT_IPS),
        "dest_ip": rng.choice(["10.0.20.10", "10.0.20.11"]),
        "dest_port": 443,
        "alert": {"signature_id": "2016184", "severity": 1,
                  "signature": "ET WEB_SERVER Possible SQL Injection / RCE attempt",
                  "category": "web-application-attack"},
    }


def _malware_download(rng, ts):
    return "wazuh", {
        "timestamp_epoch": ts,
        "rule": {"id": "554", "level": 9, "description": "Suspicious executable downloaded",
                 "groups": ["malware"], "mitre": {"id": ["T1105"]}},
        "data": {"srcip": "146.70.199.30", "dstip": rng.choice(ASSETS[4:]), "dstport": "80"},
        "agent": {"name": "WKS-DEV-12", "ip": "10.0.40.101"},
    }


def _benign_policy(rng, ts):
    # Low-value noise to prove the platform handles routine, low-severity events.
    return "wazuh", {
        "timestamp_epoch": ts,
        "rule": {"id": "5401", "level": 3, "description": "USB storage device connected",
                 "groups": ["policy"], "mitre": {}},
        "data": {"srcip": "", "dstuser": rng.choice(USERS)},
        "agent": {"name": "WKS-DEV-12", "ip": "10.0.40.101"},
    }


TEMPLATES = [
    (6, _brute_force), (1, _successful_login_after_bf), (3, _c2_beacon),
    (4, _port_scan), (3, _phishing), (1, _ransomware), (2, _exfil),
    (3, _exploit), (2, _malware_download), (5, _benign_policy),
]


def _weighted(rng):
    pool = [t for w, fn in TEMPLATES for t in [fn] * w]
    return rng.choice(pool)


def generate(count: int = 60, seed: int = 7, span_hours: float = 6.0,
             guaranteed: bool = True) -> list[tuple[str, dict[str, Any]]]:
    """Return a list of (source_hint, raw_event) spread over the recent past.

    When guaranteed is True (seeding), the marquee scenarios are appended so the
    demo always has a ransomware/exfil/brute-force case to show. For live
    injection (the Simulate button) it is False, so exactly `count` are produced.
    """
    rng = random.Random(seed)
    t_end = now()
    t_start = t_end - span_hours * 3600
    out: list[tuple[str, dict]] = []
    for _ in range(count):
        ts = rng.uniform(t_start, t_end)
        builder = _weighted(rng)
        source, ev = builder(rng, ts)
        out.append((source, ev))
    # Guarantee the marquee scenarios appear at least once for the demo.
    if guaranteed:
        for fn in (_brute_force, _successful_login_after_bf, _c2_beacon, _ransomware, _exfil, _phishing):
            source, ev = fn(rng, rng.uniform(t_start, t_end))
            out.append((source, ev))
    out.sort(key=lambda x: x[1].get("timestamp_epoch", x[1].get("ts", 0)))
    return out
