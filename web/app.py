"""
FastAPI backend for TriageDesk.

Serves the analyst console and the REST API. The API doubles as the Phase-3 API
design deliverable, so endpoints are small and single-purpose. SLA state is
refreshed on read so timers always reflect the current time.

The "acting analyst" is passed as the `actor` query parameter — a deliberate
simplification standing in for real authentication, which is listed as future
work. It is enough to demonstrate assignment, workload and audit attribution.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from src.common import attack
from src.engine import Engine
from src.ingest import generator
from src.triage.sla import SlaEngine
from src.triage.workflow import WorkflowError

app = FastAPI(title="TriageDesk",
              description="SOC Alert Triage & Incident Management platform", version="1.0")

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
engine: Engine | None = None
_sim_seed = [1000]


@app.on_event("startup")
def _startup() -> None:
    global engine
    engine = Engine(online_enrichment=os.environ.get("TD_ONLINE", "0") == "1")
    engine.seed(count=int(os.environ.get("TD_SEED_COUNT", "60")), seed=7)


def _e() -> Engine:
    if engine is None:
        raise HTTPException(503, "engine not ready")
    return engine


# -- UI ---------------------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(WEB_DIR, "dashboard.html"))


# -- read endpoints ---------------------------------------------------------

@app.get("/api/metrics")
def metrics() -> dict:
    e = _e()
    e.refresh_all_sla()
    return e.metrics()


@app.get("/api/incidents")
def incidents(status: Optional[str] = None, assignee: Optional[str] = None) -> list:
    e = _e()
    e.refresh_all_sla()
    rows = e.db.incidents(status=status, assignee=assignee)
    # attach a compact live SLA view for the queue
    sla = e.sla
    for r in rows:
        _attach_sla_view(r, sla)
    return rows


@app.get("/api/incident/{incident_id}")
def incident(incident_id: str) -> dict:
    e = _e()
    d = e.db.incident_detail(incident_id)
    if not d:
        raise HTTPException(404, "not found")
    _attach_sla_view(d, e.sla)
    d["playbook"] = attack.playbook_for(d.get("techniques", []))
    d["technique_names"] = {t: attack.name(t) for t in d.get("techniques", [])}
    return d


@app.get("/api/alerts")
def alerts(limit: int = 60) -> list:
    return _e().db.recent_alerts(limit=limit)


@app.get("/api/analysts")
def analysts() -> list:
    return _e().db.analysts()


@app.get("/api/coverage")
def coverage() -> dict:
    e = _e()
    seen = e.technique_coverage()
    return {tid: {"name": m["name"], "tactic": m["tactic"],
                  "count": seen.get(tid, 0), "detected": tid in seen}
            for tid, m in attack.TECHNIQUES.items()}


@app.get("/api/workload")
def workload() -> list:
    """Open incidents per analyst — for the workload panel."""
    e = _e()
    out = {a["username"]: {"display_name": a["display_name"], "open": 0, "total": 0}
           for a in e.db.analysts()}
    for i in e.all_incident_objects():
        if i.assignee in out:
            out[i.assignee]["total"] += 1
            if i.status != "resolved":
                out[i.assignee]["open"] += 1
    return list(out.values())


# -- write endpoints (analyst actions) --------------------------------------

@app.post("/api/incident/{incident_id}/acknowledge")
def acknowledge(incident_id: str, actor: str = "zane") -> dict:
    return _wf(lambda w: w.acknowledge(incident_id, actor))


@app.post("/api/incident/{incident_id}/assign")
def assign(incident_id: str, actor: str = "zane", assignee: str = "zane") -> dict:
    return _wf(lambda w: w.assign(incident_id, actor, assignee))


@app.post("/api/incident/{incident_id}/status/{status}")
def set_status(incident_id: str, status: str, actor: str = "zane") -> dict:
    return _wf(lambda w: w.set_status(incident_id, actor, status))


@app.post("/api/incident/{incident_id}/verdict/{verdict}")
def set_verdict(incident_id: str, verdict: str, actor: str = "zane") -> dict:
    return _wf(lambda w: w.set_verdict(incident_id, actor, verdict))


@app.post("/api/incident/{incident_id}/comment")
def comment(incident_id: str, actor: str = "zane", body: dict = Body(...)) -> dict:
    text = (body or {}).get("text", "").strip()
    if not text:
        raise HTTPException(400, "empty comment")
    c = _e().workflow.comment(incident_id, actor, text)
    return {"ok": True, "comment_id": c.comment_id}


# -- demo / ingestion -------------------------------------------------------

@app.post("/api/ingest")
def ingest(body: dict = Body(...), source: Optional[str] = None) -> dict:
    """Ingest a raw alert via API — demonstrates external tool integration."""
    a = _e().ingest_event(body, source)
    return {"ok": True, "alert_id": a.alert_id, "incident_id": a.incident_id,
            "risk_score": a.risk_score, "severity": a.severity}


@app.post("/api/simulate")
def simulate(n: int = 5) -> dict:
    """Inject a fresh burst of live alerts (created now) for the demo."""
    e = _e()
    _sim_seed[0] += 1
    made = 0
    for src, raw in generator.generate(count=n, seed=_sim_seed[0], span_hours=0.02, guaranteed=False):
        raw["timestamp_epoch"] = time.time()
        raw["ts"] = time.time()
        e.ingest_event(raw, src)
        made += 1
    return {"ok": True, "created": made}


# -- helpers ----------------------------------------------------------------

def _wf(fn) -> dict:
    try:
        inc = fn(_e().workflow)
        return {"ok": True, "incident_id": inc.incident_id, "status": inc.status}
    except WorkflowError as exc:
        raise HTTPException(400, str(exc))


def _attach_sla_view(d: dict, sla: SlaEngine) -> None:
    from src.common.models import Incident
    inc = Incident(**{k: v for k, v in d.items() if k in Incident.__dataclass_fields__})
    st = sla.refresh(inc)
    d["sla"] = {
        "ack_status": st.ack_status, "resolve_status": st.resolve_status,
        "ack_remaining": st.ack_remaining, "resolve_remaining": st.resolve_remaining,
    }
    d["escalated"] = inc.escalated
    d["ack_breached"] = inc.ack_breached
    d["resolve_breached"] = inc.resolve_breached


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
