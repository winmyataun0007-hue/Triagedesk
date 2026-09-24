"""Tests for the SLA engine — deadlines, breach detection, escalation, metrics."""

from src.common.models import Incident
from src.common.util import now
from src.triage.sla import SlaEngine

SLA = SlaEngine()


def _incident(severity="high", created_offset=0.0):
    t = now() + created_offset
    inc = Incident(incident_id="x", created_at=t, updated_at=t, title="t",
                   severity=severity, risk_score=50)
    SLA.apply_new(inc)
    return inc


def test_due_times_from_policy():
    inc = _incident("critical")
    assert inc.priority == "P1"
    # critical ack window is 15 min
    assert abs((inc.ack_due_at - inc.created_at) - 15 * 60) < 1


def test_on_track_when_fresh():
    inc = _incident("high")
    st = SLA.refresh(inc)
    assert st.ack_status in ("on_track", "at_risk")
    assert not inc.ack_breached


def test_breach_and_escalation_when_overdue_unacked():
    # created 2 hours ago, high severity (30-min ack window) => breached
    inc = _incident("high", created_offset=-2 * 3600)
    SLA.refresh(inc)
    assert inc.ack_breached is True
    assert inc.escalated is True          # overdue AND unacknowledged


def test_ack_clears_escalation():
    inc = _incident("high", created_offset=-2 * 3600)
    inc.acknowledged_at = inc.created_at + 60   # acknowledged quickly
    SLA.refresh(inc)
    assert inc.escalated is False
    assert inc.ack_breached is False            # acked within window


def test_late_ack_counts_as_breach_not_escalation():
    inc = _incident("high", created_offset=-2 * 3600)
    inc.acknowledged_at = inc.created_at + 90 * 60   # acked 90 min in (> 30 min window)
    SLA.refresh(inc)
    assert inc.ack_breached is True
    assert inc.escalated is False        # escalation is only for UNacknowledged


def test_metrics_mtta_mttr_and_compliance():
    incs = []
    a = _incident("high", created_offset=-3600)
    a.acknowledged_at = a.created_at + 300      # 5 min -> within 30 min window
    a.resolved_at = a.created_at + 3600
    incs.append(a)
    b = _incident("critical", created_offset=-3600)
    b.acknowledged_at = b.created_at + 1800     # 30 min -> exceeds 15 min window (breach)
    incs.append(b)
    for i in incs:
        SLA.refresh(i)
    m = SLA.metrics(incs)
    assert m["acknowledged"] == 2
    assert m["mtta_seconds"] == (300 + 1800) / 2
    assert 0 <= m["ack_compliance_pct"] <= 100
    assert m["ack_compliance_pct"] == 50.0      # one met, one breached
