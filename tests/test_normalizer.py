"""Tests for multi-source alert normalization."""

from src.ingest.normalizer import normalize


def test_wazuh_normalization_and_severity():
    ev = {"timestamp_epoch": 1000.0,
          "rule": {"id": "5710", "level": 12, "description": "Multiple auth failures",
                   "groups": ["authentication_failures"], "mitre": {"id": ["T1110"]}},
          "data": {"srcip": "1.2.3.4", "dstuser": "root", "dstport": "22"},
          "agent": {"name": "DC01", "ip": "10.0.10.20"}}
    a = normalize(ev)
    assert a.source == "wazuh"
    assert a.severity == "critical"       # level 12 -> critical
    assert a.src_ip == "1.2.3.4"
    assert a.technique == "T1110"
    assert a.dst_port == 22


def test_suricata_normalization_and_severity():
    ev = {"timestamp_epoch": 1000.0, "src_ip": "9.9.9.9", "dest_ip": "10.0.20.10",
          "dest_port": 443,
          "alert": {"signature_id": "2028700", "severity": 1,
                    "signature": "ET MALWARE Beacon", "category": "c2"}}
    a = normalize(ev)
    assert a.source == "suricata"
    assert a.severity == "high"           # suricata sev 1 -> high
    assert a.category == "c2"


def test_generic_and_severity_aliases():
    a = normalize({"source": "edr", "title": "x", "severity": "warning",
                   "src_ip": "5.5.5.5"})
    assert a.severity == "medium"         # 'warning' aliased
    a2 = normalize({"source": "edr", "title": "y", "severity": "CRIT"})
    assert a2.severity == "critical"


def test_source_autodetection():
    wz = normalize({"rule": {"level": 5, "description": "x"}, "data": {}, "agent": {}})
    assert wz.source == "wazuh"
    su = normalize({"alert": {"signature": "s", "severity": 2}, "src_ip": "1.1.1.1"})
    assert su.source == "suricata"
