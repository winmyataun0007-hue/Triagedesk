"""
SQLite persistence for TriageDesk.

Chosen for the same reasons as the rest of the stack: zero-configuration,
file-based, no separate server, fits a student laptop. Every analyst action is
written here so the case history survives a restart and can be audited.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Optional

from src.common.models import (Alert, Analyst, AuditEvent, Comment, Incident)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, ts REAL, ingested_at REAL, source TEXT, rule_id TEXT,
    title TEXT, severity TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, user TEXT,
    host TEXT, category TEXT, technique TEXT, description TEXT, risk_score INTEGER,
    incident_id TEXT, enrichment TEXT, raw TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, created_at REAL, updated_at REAL, title TEXT,
    severity TEXT, risk_score INTEGER, src_ip TEXT, alert_count INTEGER,
    techniques TEXT, categories TEXT, hosts TEXT, summary TEXT, status TEXT,
    verdict TEXT, assignee TEXT, priority TEXT, acknowledged_at REAL, resolved_at REAL,
    ack_due_at REAL, resolve_due_at REAL, ack_breached INTEGER, resolve_breached INTEGER,
    escalated INTEGER
);
CREATE TABLE IF NOT EXISTS comments (
    comment_id TEXT PRIMARY KEY, incident_id TEXT, author TEXT, text TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS audit (
    audit_id TEXT PRIMARY KEY, incident_id TEXT, actor TEXT, action TEXT, detail TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS analysts (
    username TEXT PRIMARY KEY, display_name TEXT, role TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
"""


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- writes -------------------------------------------------------------

    def save_alert(self, a: Alert) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.alert_id, a.ts, a.ingested_at, a.source, a.rule_id, a.title, a.severity,
                 a.src_ip, a.dst_ip, a.dst_port, a.user, a.host, a.category, a.technique,
                 a.description, a.risk_score, a.incident_id, json.dumps(a.enrichment),
                 json.dumps(a.raw)),
            )
            self.conn.commit()

    def save_incident(self, i: Incident) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (i.incident_id, i.created_at, i.updated_at, i.title, i.severity, i.risk_score,
                 i.src_ip, i.alert_count, json.dumps(i.techniques), json.dumps(i.categories),
                 json.dumps(i.hosts), i.summary, i.status, i.verdict, i.assignee, i.priority,
                 i.acknowledged_at, i.resolved_at, i.ack_due_at, i.resolve_due_at,
                 int(i.ack_breached), int(i.resolve_breached), int(i.escalated)),
            )
            self.conn.commit()

    def save_comment(self, c: Comment) -> None:
        with self._lock:
            self.conn.execute("INSERT INTO comments VALUES (?,?,?,?,?)",
                              (c.comment_id, c.incident_id, c.author, c.text, c.ts))
            self.conn.commit()

    def save_audit(self, e: AuditEvent) -> None:
        with self._lock:
            self.conn.execute("INSERT INTO audit VALUES (?,?,?,?,?,?)",
                              (e.audit_id, e.incident_id, e.actor, e.action, e.detail, e.ts))
            self.conn.commit()

    def save_analyst(self, a: Analyst) -> None:
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO analysts VALUES (?,?,?)",
                              (a.username, a.display_name, a.role))
            self.conn.commit()

    # -- reads --------------------------------------------------------------

    def get_incident_row(self, incident_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM incidents WHERE incident_id=?",
                                     (incident_id,)).fetchone()

    def incidents(self, status: Optional[str] = None, assignee: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM incidents"
        conds, args = [], []
        if status:
            conds.append("status=?"); args.append(status)
        if assignee:
            conds.append("assignee=?"); args.append(assignee)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY (status='resolved') ASC, risk_score DESC, created_at DESC"
        with self._lock:
            rows = self.conn.execute(q, args).fetchall()
        return [self._incident(r) for r in rows]

    def incident_detail(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM incidents WHERE incident_id=?",
                                    (incident_id,)).fetchone()
            if not row:
                return None
            alerts = self.conn.execute(
                "SELECT * FROM alerts WHERE incident_id=? ORDER BY ts", (incident_id,)).fetchall()
            comments = self.conn.execute(
                "SELECT * FROM comments WHERE incident_id=? ORDER BY ts", (incident_id,)).fetchall()
            audit = self.conn.execute(
                "SELECT * FROM audit WHERE incident_id=? ORDER BY ts", (incident_id,)).fetchall()
        d = self._incident(row)
        d["alerts"] = [self._alert(a) for a in alerts]
        d["comments"] = [dict(c) for c in comments]
        d["audit"] = [dict(a) for a in audit]
        return d

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM alerts ORDER BY ingested_at DESC LIMIT ?",
                                     (limit,)).fetchall()
        return [self._alert(r) for r in rows]

    def analysts(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM analysts ORDER BY role, username").fetchall()
        return [dict(r) for r in rows]

    def all_incidents_raw(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM incidents").fetchall()

    # -- deserialisers ------------------------------------------------------

    @staticmethod
    def _alert(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["enrichment"] = json.loads(d.get("enrichment") or "{}")
        d["raw"] = json.loads(d.get("raw") or "{}")
        return d

    @staticmethod
    def _incident(r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("techniques", "categories", "hosts"):
            d[k] = json.loads(d.get(k) or "[]")
        for k in ("ack_breached", "resolve_breached", "escalated"):
            d[k] = bool(d.get(k))
        return d
