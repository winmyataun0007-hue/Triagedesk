"""
Alert enrichment.

An alert on its own says "IP X did Y". Enrichment answers the questions an analyst
would otherwise look up by hand: Is X on a threat feed? Is the target one of our
important systems? Is the source inside or outside our network? Good enrichment is
what turns a raw alert into a triage decision in seconds instead of minutes.

Design goals:
  * Works FULLY OFFLINE using a bundled threat feed and asset inventory, so the
    project runs on any laptop with no API keys and no internet.
  * Pluggable ONLINE providers (ip-api.com for geo, AbuseIPDB for reputation) that
    are used only if enabled in config AND reachable, and that fail silently back
    to offline data. No online provider is required.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import yaml

from src.common.models import Alert
from src.common.util import is_internal_ip

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


class Enricher:
    def __init__(self, iocs_path: Optional[str] = None, assets_path: Optional[str] = None,
                 online: bool = False):
        self.online = online
        with open(iocs_path or os.path.join(HERE, "intel", "threat_iocs.json")) as fh:
            self.iocs = json.load(fh)
        with open(assets_path or os.path.join(ROOT, "config", "assets.yaml")) as fh:
            cfg = yaml.safe_load(fh)
        self.assets = cfg.get("assets", {})
        self.boost = cfg.get("criticality_boost", {})

    # -- offline lookups ----------------------------------------------------

    def _threat_lookup(self, ip: str) -> Optional[dict[str, Any]]:
        if not ip:
            return None
        hit = self.iocs.get("ips", {}).get(ip)
        return dict(hit) if hit else None

    def _asset_lookup(self, ip: str) -> Optional[dict[str, Any]]:
        a = self.assets.get(ip)
        return dict(a) if a else None

    # -- optional online providers (graceful, non-blocking) -----------------

    def _geo_online(self, ip: str) -> Optional[dict[str, Any]]:
        """ip-api.com free endpoint (no key). Only used when online=True."""
        if not self.online or is_internal_ip(ip) or not ip:
            return None
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org"
            with urllib.request.urlopen(url, timeout=2.5) as r:
                data = json.loads(r.read().decode())
            if data.get("status") == "success":
                return {"country": data.get("country"), "city": data.get("city"),
                        "isp": data.get("isp"), "org": data.get("org")}
        except Exception:
            return None  # offline / rate-limited / blocked — degrade silently
        return None

    # -- main ---------------------------------------------------------------

    def enrich(self, alert: Alert) -> Alert:
        e: dict[str, Any] = {}

        # Source-side: reputation + direction
        e["src_internal"] = is_internal_ip(alert.src_ip) if alert.src_ip else None
        threat = self._threat_lookup(alert.src_ip)
        if threat:
            e["threat_intel"] = threat
        geo = self._geo_online(alert.src_ip)
        if geo:
            e["geo"] = geo

        # Destination-side: is the target one of our important assets?
        asset = self._asset_lookup(alert.dst_ip)
        if asset:
            e["target_asset"] = asset

        # File hash reputation, if the raw event carried one.
        h = alert.raw.get("data", {}).get("hash") or alert.raw.get("file_hash")
        if h and h in self.iocs.get("hashes", {}):
            e["hash_intel"] = self.iocs["hashes"][h]

        # A concise, human-readable enrichment note for the analyst UI.
        e["notes"] = self._notes(alert, e)
        alert.enrichment = e
        return alert

    def _notes(self, alert: Alert, e: dict[str, Any]) -> list[str]:
        notes: list[str] = []
        if e.get("threat_intel"):
            ti = e["threat_intel"]
            notes.append(f"Source IP on threat feed: {ti['category']} "
                         f"({ti['confidence']}% confidence, {ti.get('actor','')})")
        if e.get("src_internal") is True:
            notes.append("Source is an INTERNAL host — possible compromise or insider activity")
        elif e.get("src_internal") is False and not e.get("threat_intel"):
            notes.append("Source is external with no threat-feed match")
        if e.get("target_asset"):
            a = e["target_asset"]
            notes.append(f"Target is {a['name']} ({a['type']}, criticality {a['criticality']}, "
                         f"owner {a['owner']})")
        if e.get("geo"):
            g = e["geo"]
            notes.append(f"Source geo: {g.get('city','?')}, {g.get('country','?')} ({g.get('isp','?')})")
        if e.get("hash_intel"):
            notes.append(f"File hash matches known malware: {e['hash_intel']['malware']}")
        return notes

    # -- severity/asset influence used by risk scoring ----------------------

    def asset_boost(self, alert: Alert) -> int:
        asset = self._asset_lookup(alert.dst_ip)
        if not asset:
            return 0
        return int(self.boost.get(asset.get("criticality", ""), 0))
