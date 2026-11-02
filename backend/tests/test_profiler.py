from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.models.threat import ThreatLevel
from app.services.ml_profiler import (
    _calculate_threat_score,
    _detect_human_or_bot,
    _extract_features,
    _get_cluster,
    score_to_level,
)


def attacker(**overrides):
    values = {"ip_address": "192.0.2.10", "is_known_malicious": 0, "abuse_confidence": 0, "ssh_attempts": 0, "commands_executed": 0}
    values.update(overrides)
    return SimpleNamespace(**values)


def event(event_type, minutes=0, **overrides):
    values = {"event_type": event_type, "dst_port": None, "tool_detected": None, "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minutes)}
    values.update(overrides)
    return SimpleNamespace(**values)


def test_score_boundaries():
    assert score_to_level(0) == ThreatLevel.MINIMAL
    assert score_to_level(20) == ThreatLevel.LOW
    assert score_to_level(40) == ThreatLevel.MEDIUM
    assert score_to_level(60) == ThreatLevel.HIGH
    assert score_to_level(80) == ThreatLevel.CRITICAL


def test_feature_extraction_and_score():
    events = [event("port_scan", dst_port=22, tool_detected="nmap"), event("ssh_login", minutes=1)]
    features = _extract_features(attacker(ssh_attempts=2, abuse_confidence=80), events)
    assert features["total_events"] == 2
    assert features["unique_ports"] == 1
    assert features["unique_tools"] == 1
    assert 0 < _calculate_threat_score(features, attacker(ssh_attempts=2, abuse_confidence=80)) <= 100


def test_cluster_prioritizes_behavior():
    assert _get_cluster({"recon_ratio": 0.8, "ssh_ratio": 0, "lure_accessed": 0, "known_malicious": 0}) == 0
    assert _get_cluster({"recon_ratio": 0, "ssh_ratio": 0.8, "lure_accessed": 0, "known_malicious": 0}) == 1


def test_regular_intervals_are_more_likely_bot():
    events = [event("http_request", minutes=minute) for minute in (0, 1, 2, 3)]
    is_human, confidence = _detect_human_or_bot(events)
    assert not is_human
    assert confidence > 0.9