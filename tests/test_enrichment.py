"""Tests for enrichment and risk scoring."""

from src.enrich.enrichment import Enricher
from src.ingest.normalizer import normalize
from src.triage.risk import score_alert

E = Enricher(online=False)   # offline only — deterministic, no network


def _alert(**kw):
    base = {"source": "generic", "title": "t", "severity": "medium"}
    base.update(kw)
    return normalize(base)


def test_threat_intel_match():
    a = E.enrich(_alert(src_ip="45.146.164.110"))
    assert a.enrichment["threat_intel"]["category"] == "c2"
    assert any("threat feed" in n for n in a.enrichment["notes"])


def test_clean_ip_no_match():
    a = E.enrich(_alert(src_ip="77.75.120.5"))
    assert "threat_intel" not in a.enrichment
    assert a.enrichment["src_internal"] is False


def test_internal_source_flagged():
    a = E.enrich(_alert(src_ip="10.0.40.101"))
    assert a.enrichment["src_internal"] is True


def test_asset_context_added():
    a = E.enrich(_alert(dst_ip="10.0.10.5"))
    assert a.enrichment["target_asset"]["name"] == "PAYROLL-DB"
    assert a.enrichment["target_asset"]["criticality"] == "crown_jewel"
    assert E.asset_boost(a) == 2


def test_risk_scoring_escalates_with_context():
    plain = _alert(severity="medium", src_ip="77.75.120.5")
    E.enrich(plain)
    low = score_alert(plain, asset_boost_levels=0)

    loaded = _alert(severity="medium", src_ip="45.146.164.110", dst_ip="10.0.10.5",
                    category="c2")
    E.enrich(loaded)
    high = score_alert(loaded, asset_boost_levels=E.asset_boost(loaded))

    assert high > low                 # threat-intel + crown-jewel target raises risk
    assert 1 <= high <= 100


def test_offline_never_calls_network():
    # online=False must not attempt any lookup even for external IPs
    a = E.enrich(_alert(src_ip="8.8.8.8"))
    assert "geo" not in a.enrichment
