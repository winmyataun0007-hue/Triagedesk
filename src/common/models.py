"""
Core data structures for TriageDesk.

Everything downstream — ingestion, enrichment, correlation, SLA, the API — speaks
in terms of these objects. The central idea is that alerts arrive from many
different security tools in many different formats, and the FIRST job of the
platform is to normalize them all into one `Alert` shape. Once normalized, the
rest of the pipeline never has to care where an alert came from.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from src.common.util import new_id, now

# Ordered severities. Index is used for comparisons and scoring.
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_SCORE = {"info": 10, "low": 30, "medium": 55, "high": 78, "critical": 95}


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 0


@dataclass
class Alert:
    """A single, normalized security alert from any source."""

    ts: float                       # when the event happened (event time)
    source: str                     # tool of origin: wazuh, suricata, edr, firewall, csv...
    rule_id: str                    # source rule/signature id
    title: str                      # human-readable alert name
    severity: str                   # normalized severity
    src_ip: str = ""                # attacker / origin IP
    dst_ip: str = ""                # target IP
    dst_port: Optional[int] = None
    user: str = ""                  # associated account, if any
    host: str = ""                  # affected host name
    category: str = ""              # e.g. malware, intrusion, recon, policy
    technique: str = ""             # MITRE ATT&CK technique id, if known
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)   # original event, preserved
    # Populated by the enrichment stage:
    enrichment: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    # Set by correlation:
    incident_id: Optional[str] = None
    alert_id: str = field(default_factory=lambda: new_id("al_"))
    ingested_at: float = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# SLA / workflow state ------------------------------------------------------

INCIDENT_STATUSES = ["new", "acknowledged", "investigating", "resolved"]
VERDICTS = ["undetermined", "true_positive", "false_positive", "benign"]


@dataclass
class Incident:
    """A correlated group of alerts that an analyst works as one case."""

    incident_id: str
    created_at: float
    updated_at: float
    title: str
    severity: str
    risk_score: int
    src_ip: str = ""
    alert_count: int = 1
    techniques: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    summary: str = ""

    # Workflow
    status: str = "new"
    verdict: str = "undetermined"
    assignee: str = ""              # analyst username
    priority: str = ""             # P1..P4, derived from severity + asset value

    # SLA clocks (epoch seconds; None until the event happens)
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    ack_due_at: Optional[float] = None
    resolve_due_at: Optional[float] = None
    ack_breached: bool = False
    resolve_breached: bool = False
    escalated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Comment:
    incident_id: str
    author: str
    text: str
    ts: float = field(default_factory=now)
    comment_id: str = field(default_factory=lambda: new_id("cm_"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEvent:
    """Immutable record of every analyst action — the case's chain of custody."""

    incident_id: str
    actor: str
    action: str                     # e.g. "acknowledged", "assigned", "verdict:true_positive"
    detail: str = ""
    ts: float = field(default_factory=now)
    audit_id: str = field(default_factory=lambda: new_id("au_"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Analyst:
    username: str
    display_name: str
    role: str = "analyst"           # analyst | senior | lead

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
