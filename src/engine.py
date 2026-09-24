"""
TriageDesk pipeline orchestrator.

One object that runs the whole flow and holds the shared state the API serves:

    raw event -> normalize -> enrich -> score -> correlate -> apply SLA -> persist

It also seeds a realistic starting state: a roster of analysts and a batch of
historical alerts, with some incidents already acknowledged or resolved so the
dashboard shows live SLA metrics (MTTA, MTTR, compliance) the instant it loads.
"""

from __future__ import annotations

import random
from typing import Optional

from src.common.db import Database
from src.common.models import Alert, Analyst, Incident
from src.common.util import now
from src.enrich.enrichment import Enricher
from src.ingest import generator
from src.ingest.normalizer import normalize
from src.triage.correlation import Correlator
from src.triage.risk import score_alert
from src.triage.sla import SlaEngine
from src.triage.workflow import Workflow

ANALYSTS = [
    Analyst("zane", "Zane (You)", "senior"),
    Analyst("achen", "Alice Chen", "analyst"),
    Analyst("mpatel", "Meera Patel", "analyst"),
    Analyst("lead", "SOC Lead", "lead"),
]


class Engine:
    def __init__(self, db: Optional[Database] = None, online_enrichment: bool = False):
        self.db = db or Database(":memory:")
        self.enricher = Enricher(online=online_enrichment)
        self.correlator = Correlator()
        self.sla = SlaEngine()
        self.workflow = Workflow(self.db, self.sla)
        for a in ANALYSTS:
            self.db.save_analyst(a)

    # -- core pipeline ------------------------------------------------------

    def ingest_event(self, raw: dict, source: Optional[str] = None) -> Alert:
        alert = normalize(raw, source)
        self.enricher.enrich(alert)
        boost = self.enricher.asset_boost(alert)
        alert.risk_score = score_alert(alert, asset_boost_levels=boost)
        inc = self.correlator.add(alert, asset_boost_levels=boost)

        # First time we see this incident, stamp its SLA deadlines.
        existing = self.db.get_incident_row(inc.incident_id)
        if existing is None:
            self.sla.apply_new(inc)
        self.sla.refresh(inc)

        self.db.save_alert(alert)
        self.db.save_incident(inc)
        return alert

    def refresh_all_sla(self) -> None:
        """Re-evaluate SLA state and escalation for every incident.

        Resolved incidents are refreshed too so their breach flags reflect the
        actual acknowledge/resolve times and their escalation flag is cleared.
        """
        for row in self.db.all_incidents_raw():
            d = self.db._incident(row)
            inc = Incident(**{k: v for k, v in d.items() if k in Incident.__dataclass_fields__})
            self.sla.refresh(inc)
            self.db.save_incident(inc)

    # -- metrics ------------------------------------------------------------

    def all_incident_objects(self) -> list[Incident]:
        out = []
        for row in self.db.all_incidents_raw():
            d = self.db._incident(row)
            out.append(Incident(**{k: v for k, v in d.items() if k in Incident.__dataclass_fields__}))
        return out

    def metrics(self) -> dict:
        incs = self.all_incident_objects()
        m = self.sla.metrics(incs)
        by_sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        by_status = {}
        open_breached = 0
        for i in incs:
            by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
            by_status[i.status] = by_status.get(i.status, 0) + 1
            if i.status != "resolved" and (i.ack_breached or i.resolve_breached):
                open_breached += 1
        m.update({
            "total_incidents": len(incs),
            "open_incidents": sum(1 for i in incs if i.status != "resolved"),
            "escalated": sum(1 for i in incs if i.escalated and i.status != "resolved"),
            "open_breached": open_breached,
            "by_severity": by_sev, "by_status": by_status,
            "total_alerts": len(self.db.recent_alerts(limit=100000)),
        })
        return m

    def technique_coverage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for i in self.all_incident_objects():
            for t in i.techniques:
                counts[t] = counts.get(t, 0) + 1
        return counts

    # -- seeding ------------------------------------------------------------

    def seed(self, count: int = 60, seed: int = 7) -> None:
        """Load historical alerts and simulate analyst activity for realism."""
        for source, raw in generator.generate(count=count, seed=seed):
            self.ingest_event(raw, source)

        rng = random.Random(seed)
        incs = self.all_incident_objects()
        # Simulate that some incidents were already worked, producing SLA history.
        for inc in incs:
            r = rng.random()
            actor = rng.choice([a.username for a in ANALYSTS[:3]])
            # Acknowledge most non-new incidents shortly after creation.
            if r < 0.75:
                ack_delay = self._ack_delay(rng, inc)
                self._backdated_ack(inc, actor, ack_delay)
            # Resolve a subset with a verdict.
            if r < 0.45:
                self._backdated_resolve(inc, actor, rng)
        self.refresh_all_sla()

    def _ack_delay(self, rng, inc: Incident) -> float:
        # Critical/high usually acked within SLA; lower severities sometimes breach.
        p = self.sla.policy(inc.severity)
        win = p["ack_minutes"] * 60
        if inc.severity in ("critical", "high"):
            return rng.uniform(0.1, 0.9) * win
        return rng.uniform(0.3, 1.6) * win   # can exceed window -> realistic breaches

    def _backdated_ack(self, inc: Incident, actor: str, delay: float) -> None:
        from src.common.models import AuditEvent
        inc.acknowledged_at = inc.created_at + delay
        inc.assignee = actor
        if inc.status == "new":
            inc.status = "investigating"
        self.db.save_incident(inc)
        self.db.save_audit(AuditEvent(incident_id=inc.incident_id, actor=actor,
                                      action="acknowledged", detail="(historical)",
                                      ts=inc.acknowledged_at))

    def _backdated_resolve(self, inc: Incident, actor: str, rng) -> None:
        p = self.sla.policy(inc.severity)
        win = p["resolve_minutes"] * 60
        base = inc.acknowledged_at or inc.created_at
        inc.resolved_at = base + rng.uniform(0.2, 1.3) * win
        # Verdict distribution: most true or benign, some false positives.
        inc.verdict = rng.choices(
            ["true_positive", "false_positive", "benign"], weights=[5, 3, 2])[0]
        inc.status = "resolved"
        self.db.save_incident(inc)
