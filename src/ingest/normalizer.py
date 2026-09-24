"""
Alert normalization — the front door of the platform.

Security tools each speak their own dialect. Wazuh emits nested JSON with a
`rule.level` 0-15; Suricata's EVE JSON uses `alert.severity` 1-3; a firewall CSV
has yet another shape. This module converts every one of them into the single
`Alert` schema so nothing downstream needs source-specific code.

Adding support for a new tool means writing one `parse_*` function here and
registering it — the rest of the system is untouched. That is the extensibility
argument for the design.
"""

from __future__ import annotations

from typing import Any, Callable

from src.common.models import Alert
from src.common.util import now

# -- severity mapping -------------------------------------------------------

def _from_wazuh_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def _from_suricata_sev(sev: int) -> str:
    return {1: "high", 2: "medium", 3: "low"}.get(sev, "medium")


def _norm_sev(value: str) -> str:
    v = str(value).strip().lower()
    aliases = {"crit": "critical", "warn": "medium", "warning": "medium",
               "err": "high", "error": "high", "notice": "low", "informational": "info"}
    v = aliases.get(v, v)
    return v if v in ("info", "low", "medium", "high", "critical") else "medium"


# -- per-source parsers -----------------------------------------------------

def parse_wazuh(ev: dict[str, Any]) -> Alert:
    rule = ev.get("rule", {})
    data = ev.get("data", {})
    agent = ev.get("agent", {})
    tech = ""
    mitre = rule.get("mitre", {})
    if isinstance(mitre, dict) and mitre.get("id"):
        tech = mitre["id"][0] if isinstance(mitre["id"], list) else mitre["id"]
    return Alert(
        ts=ev.get("timestamp_epoch", now()),
        source="wazuh",
        rule_id=str(rule.get("id", "")),
        title=rule.get("description", "Wazuh alert"),
        severity=_from_wazuh_level(int(rule.get("level", 5))),
        src_ip=data.get("srcip", ""),
        dst_ip=data.get("dstip", "") or agent.get("ip", ""),
        dst_port=_to_int(data.get("dstport")),
        user=data.get("dstuser", "") or data.get("srcuser", ""),
        host=agent.get("name", ""),
        category=(rule.get("groups", [""])[0] if rule.get("groups") else ""),
        technique=tech,
        description=rule.get("description", ""),
        raw=ev,
    )


def parse_suricata(ev: dict[str, Any]) -> Alert:
    alert = ev.get("alert", {})
    return Alert(
        ts=ev.get("timestamp_epoch", now()),
        source="suricata",
        rule_id=str(alert.get("signature_id", "")),
        title=alert.get("signature", "Suricata alert"),
        severity=_from_suricata_sev(int(alert.get("severity", 2))),
        src_ip=ev.get("src_ip", ""),
        dst_ip=ev.get("dest_ip", ""),
        dst_port=_to_int(ev.get("dest_port")),
        host=ev.get("host", ""),
        category=alert.get("category", "intrusion"),
        description=alert.get("signature", ""),
        raw=ev,
    )


def parse_generic(ev: dict[str, Any]) -> Alert:
    """A flat, tool-agnostic dict (also used for CSV rows and the API)."""
    return Alert(
        ts=float(ev.get("ts", now())),
        source=ev.get("source", "generic"),
        rule_id=str(ev.get("rule_id", "")),
        title=ev.get("title", "Alert"),
        severity=_norm_sev(ev.get("severity", "medium")),
        src_ip=ev.get("src_ip", ""),
        dst_ip=ev.get("dst_ip", ""),
        dst_port=_to_int(ev.get("dst_port")),
        user=ev.get("user", ""),
        host=ev.get("host", ""),
        category=ev.get("category", ""),
        technique=ev.get("technique", ""),
        description=ev.get("description", ""),
        raw=ev,
    )


PARSERS: dict[str, Callable[[dict], Alert]] = {
    "wazuh": parse_wazuh,
    "suricata": parse_suricata,
    "generic": parse_generic,
}


def normalize(ev: dict[str, Any], source: str | None = None) -> Alert:
    """Normalize one raw event. `source` forces a parser; otherwise it is sniffed."""
    if source and source in PARSERS:
        return PARSERS[source](ev)
    if "rule" in ev and isinstance(ev["rule"], dict) and "level" in ev["rule"]:
        return parse_wazuh(ev)
    if "alert" in ev and isinstance(ev["alert"], dict) and "signature" in ev["alert"]:
        return parse_suricata(ev)
    return parse_generic(ev)


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
