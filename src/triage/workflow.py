"""
Analyst workflow — the actions a SOC analyst performs on an incident.

Enforces a sane status lifecycle, records who did what (audit trail), stamps the
SLA milestone timestamps that the SLA engine measures against, and attaches the
right ATT&CK playbook. Every state change is auditable, which is the difference
between a toy and something that models a real incident-response process.

Lifecycle:  new -> acknowledged -> investigating -> resolved
Resolving requires a verdict (true_positive / false_positive / benign).
"""

from __future__ import annotations

from typing import Optional

from src.common import attack
from src.common.db import Database
from src.common.models import (AuditEvent, Comment, Incident, INCIDENT_STATUSES,
                               VERDICTS)
from src.common.util import now
from src.triage.sla import SlaEngine


class WorkflowError(Exception):
    pass


class Workflow:
    def __init__(self, db: Database, sla: SlaEngine):
        self.db = db
        self.sla = sla

    # -- helpers ------------------------------------------------------------

    def _load(self, incident_id: str) -> Incident:
        row = self.db.get_incident_row(incident_id)
        if not row:
            raise WorkflowError(f"incident {incident_id} not found")
        d = self.db._incident(row)
        return Incident(**{k: v for k, v in d.items() if k in Incident.__dataclass_fields__})

    def _save(self, inc: Incident) -> None:
        inc.updated_at = now()
        self.sla.refresh(inc)
        self.db.save_incident(inc)

    def _audit(self, incident_id: str, actor: str, action: str, detail: str = "") -> None:
        self.db.save_audit(AuditEvent(incident_id=incident_id, actor=actor,
                                      action=action, detail=detail))

    # -- actions ------------------------------------------------------------

    def acknowledge(self, incident_id: str, actor: str) -> Incident:
        inc = self._load(incident_id)
        if inc.acknowledged_at is None:
            inc.acknowledged_at = now()
        if inc.status == "new":
            inc.status = "acknowledged"
        if not inc.assignee:
            inc.assignee = actor
        self._save(inc)
        self._audit(incident_id, actor, "acknowledged")
        return inc

    def assign(self, incident_id: str, actor: str, assignee: str) -> Incident:
        inc = self._load(incident_id)
        inc.assignee = assignee
        if inc.status == "new":
            inc.status = "acknowledged"
            if inc.acknowledged_at is None:
                inc.acknowledged_at = now()
        self._save(inc)
        self._audit(incident_id, actor, "assigned", f"to {assignee}")
        return inc

    def set_status(self, incident_id: str, actor: str, status: str) -> Incident:
        if status not in INCIDENT_STATUSES:
            raise WorkflowError(f"invalid status {status}")
        inc = self._load(incident_id)
        if status == "resolved" and inc.verdict == "undetermined":
            raise WorkflowError("cannot resolve without a verdict")
        inc.status = status
        if status in ("acknowledged", "investigating") and inc.acknowledged_at is None:
            inc.acknowledged_at = now()
        if status == "resolved" and inc.resolved_at is None:
            inc.resolved_at = now()
        self._save(inc)
        self._audit(incident_id, actor, f"status:{status}")
        return inc

    def set_verdict(self, incident_id: str, actor: str, verdict: str,
                    resolve: bool = True) -> Incident:
        if verdict not in VERDICTS:
            raise WorkflowError(f"invalid verdict {verdict}")
        inc = self._load(incident_id)
        inc.verdict = verdict
        if inc.acknowledged_at is None:
            inc.acknowledged_at = now()
        if resolve and verdict != "undetermined":
            inc.status = "resolved"
            if inc.resolved_at is None:
                inc.resolved_at = now()
        self._save(inc)
        self._audit(incident_id, actor, f"verdict:{verdict}")
        return inc

    def comment(self, incident_id: str, actor: str, text: str) -> Comment:
        c = Comment(incident_id=incident_id, author=actor, text=text)
        self.db.save_comment(c)
        self._audit(incident_id, actor, "commented", text[:60])
        return c

    def playbook(self, incident_id: str) -> list[str]:
        inc = self._load(incident_id)
        return attack.playbook_for(inc.techniques)
