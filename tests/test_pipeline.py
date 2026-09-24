"""End-to-end pipeline and workflow tests."""

import pytest

from src.common.db import Database
from src.engine import Engine
from src.triage.workflow import WorkflowError


def _engine():
    return Engine(db=Database(":memory:"))


def test_ingest_creates_alert_and_incident():
    e = _engine()
    a = e.ingest_event({"source": "generic", "title": "C2 beacon", "severity": "high",
                        "src_ip": "45.146.164.110", "dst_ip": "10.0.10.5",
                        "category": "c2", "technique": "T1071"})
    assert a.incident_id
    assert a.risk_score > 70                      # IOC + crown-jewel target
    detail = e.db.incident_detail(a.incident_id)
    assert detail["alert_count"] == 1
    assert "T1071" in detail["techniques"]


def test_correlation_groups_same_source():
    e = _engine()
    ids = set()
    for i in range(5):
        a = e.ingest_event({"source": "wazuh", "title": "brute force", "severity": "medium",
                            "src_ip": "91.240.118.172", "dst_ip": "10.0.10.20",
                            "category": "authentication", "technique": "T1110",
                            "ts": 1000.0 + i * 10})
        ids.add(a.incident_id)
    assert len(ids) == 1                           # all correlated into one incident
    detail = e.db.incident_detail(next(iter(ids)))
    assert detail["alert_count"] == 5


def test_different_sources_are_separate_incidents():
    e = _engine()
    a1 = e.ingest_event({"source": "generic", "title": "x", "severity": "low",
                         "src_ip": "1.1.1.1", "ts": 1000.0})
    a2 = e.ingest_event({"source": "generic", "title": "y", "severity": "low",
                         "src_ip": "2.2.2.2", "ts": 1000.0})
    assert a1.incident_id != a2.incident_id


def test_workflow_lifecycle_and_audit():
    e = _engine()
    a = e.ingest_event({"source": "generic", "title": "x", "severity": "high",
                        "src_ip": "45.146.164.110"})
    iid = a.incident_id
    e.workflow.acknowledge(iid, "zane")
    d = e.db.incident_detail(iid)
    assert d["status"] == "acknowledged"
    assert d["acknowledged_at"] is not None
    assert any(ev["action"] == "acknowledged" for ev in d["audit"])


def test_cannot_resolve_without_verdict():
    e = _engine()
    a = e.ingest_event({"source": "generic", "title": "x", "severity": "high",
                        "src_ip": "1.1.1.1"})
    with pytest.raises(WorkflowError):
        e.workflow.set_status(a.incident_id, "zane", "resolved")


def test_verdict_resolves_and_stamps_time():
    e = _engine()
    a = e.ingest_event({"source": "generic", "title": "x", "severity": "high",
                        "src_ip": "1.1.1.1"})
    inc = e.workflow.set_verdict(a.incident_id, "zane", "true_positive")
    assert inc.status == "resolved"
    d = e.db.incident_detail(a.incident_id)
    assert d["resolved_at"] is not None
    assert d["verdict"] == "true_positive"


def test_comment_recorded():
    e = _engine()
    a = e.ingest_event({"source": "generic", "title": "x", "severity": "low",
                        "src_ip": "1.1.1.1"})
    e.workflow.comment(a.incident_id, "achen", "Looks like a scanner, monitoring.")
    d = e.db.incident_detail(a.incident_id)
    assert len(d["comments"]) == 1
    assert d["comments"][0]["author"] == "achen"


def test_seed_produces_realistic_state():
    e = _engine()
    e.seed(count=40, seed=7)
    m = e.metrics()
    assert m["total_incidents"] > 0
    assert m["total_alerts"] >= 40
    assert m["ack_compliance_pct"] is not None
    # escalated incidents must all be unacknowledged and open
    for i in e.all_incident_objects():
        if i.escalated:
            assert i.acknowledged_at is None and i.status != "resolved"
