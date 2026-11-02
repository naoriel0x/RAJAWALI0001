import logging
import hashlib
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.attacker import Attacker
from app.models.event import Event, EventType
from app.models.threat import Threat, ThreatLevel
from app.services.mitre_mapper import map_to_mitre

logger = logging.getLogger(__name__)
SCORE_THRESHOLDS = {
    ThreatLevel.MINIMAL:  (0,  20),
    ThreatLevel.LOW:      (20, 40),
    ThreatLevel.MEDIUM:   (40, 60),
    ThreatLevel.HIGH:     (60, 80),
    ThreatLevel.CRITICAL: (80, 100),
}

def score_to_level(score: float) -> ThreatLevel:
    for level, (low, high) in SCORE_THRESHOLDS.items():
        if low <= score < high:
            return level
    return ThreatLevel.CRITICAL


async def profile_attacker(attacker_id: str, db: AsyncSession) -> dict:
    attacker_uuid = str(attacker_id)
    attacker_res = await db.execute(
        select(Attacker).where(Attacker.id == attacker_uuid)
    )
    attacker = attacker_res.scalar_one_or_none()
    if not attacker:
        return {}

    events_res = await db.execute(
        select(Event)
        .where(Event.attacker_id == attacker_uuid)
        .order_by(Event.timestamp.asc())
    )
    events = events_res.scalars().all()

    if not events:
        return {"threat_score": 0.0, "threat_level": ThreatLevel.MINIMAL}

    features = _extract_features(attacker, events)
    threat_score = _calculate_threat_score(features, attacker)
    threat_level = score_to_level(threat_score)
    is_human, human_confidence = _detect_human_or_bot(events)
    cluster_id = _get_cluster(features)
    sig = _generate_signature(attacker, features)
    mitre_techniques = list(set([
        e.mitre_technique for e in events if e.mitre_technique
    ]))
    mitre_tactics = list(set([
        map_to_mitre(e.event_type.value).get("tactic", "")
        for e in events
    ]))

    tools = list(set([e.tool_detected for e in events if e.tool_detected]))
    attacker.threat_score = threat_score
    attacker.mitre_ttps = mitre_techniques
    await db.flush()

    summary = _generate_summary(attacker, threat_score, is_human, tools, mitre_tactics)
    recommendations = _generate_recommendations(threat_score, features)

    threat_res = await db.execute(
        select(Threat).where(Threat.attacker_id == attacker.id)
    )
    threat = threat_res.scalar_one_or_none()
    if threat is None:
        threat = Threat(attacker_id=attacker.id)
        db.add(threat)

    threat.threat_level = threat_level
    threat.threat_score = threat_score
    threat.cluster_id = cluster_id
    threat.behavior_signature = sig
    threat.is_human = int(is_human)
    threat.human_confidence = human_confidence
    threat.ml_features = features
    threat.mitre_techniques = mitre_techniques
    threat.mitre_tactics = mitre_tactics
    threat.detected_tools = tools
    threat.summary = summary
    threat.recommendations = recommendations
    await db.flush()

    return {
        "threat_score":         threat_score,
        "threat_level":         threat_level,
        "is_human":             int(is_human),
        "human_confidence":     human_confidence,
        "cluster_id":           cluster_id,
        "behavior_signature":   sig,
        "features":             features,
        "mitre_techniques":     mitre_techniques,
        "mitre_tactics":        mitre_tactics,
        "tools":                tools,
        "summary":              summary,
        "recommendations":      recommendations,
    }


def _extract_features(attacker: Attacker, events: list) -> dict:
    total = len(events)
    event_types = [
        e.event_type.value if isinstance(e.event_type, EventType) else str(e.event_type)
        for e in events
    ]

    recon_count     = event_types.count("port_scan") + event_types.count("dns_recon")
    ssh_count       = sum(1 for t in event_types if "ssh" in t)
    http_count      = sum(1 for t in event_types if "http" in t)
    lure_count      = event_types.count("lure_access")
    unique_ports    = len(set([e.dst_port for e in events if e.dst_port]))
    unique_tools    = len(set([e.tool_detected for e in events if e.tool_detected]))
    known_malicious = attacker.is_known_malicious or 0
    abuse_conf      = attacker.abuse_confidence or 0.0
    commands        = attacker.commands_executed or 0

    return {
        "total_events":     total,
        "recon_ratio":      recon_count / max(total, 1),
        "ssh_ratio":        ssh_count / max(total, 1),
        "http_ratio":       http_count / max(total, 1),
        "lure_accessed":    int(lure_count > 0),
        "unique_ports":     unique_ports,
        "unique_tools":     unique_tools,
        "known_malicious":  known_malicious,
        "abuse_confidence": abuse_conf / 100.0,
        "commands_run":     commands,
    }


def _calculate_threat_score(features: dict, attacker: Attacker) -> float:
    score = 0.0

    score += min(features["total_events"] * 2, 20)
    score += features["recon_ratio"] * 15
    score += min(attacker.ssh_attempts * 0.5, 20) if attacker.ssh_attempts else 0
    score += 15 if features["lure_accessed"] else 0
    score += features["unique_tools"] * 3
    score += 20 if features["known_malicious"] else 0
    score += features["abuse_confidence"] * 15
    return min(round(score, 2), 100.0)


def _detect_human_or_bot(events: list) -> tuple:
    if len(events) < 3:
        return True, 0.5

    timestamps = [e.timestamp for e in events if e.timestamp]
    if len(timestamps) < 3:
        return True, 0.5

    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds() * 1000
        if delta > 0:
            intervals.append(delta)

    if not intervals:
        return True, 0.5

    mean_interval   = np.mean(intervals)
    std_interval    = np.std(intervals)
    cv              = std_interval / max(mean_interval, 1)
    is_human            = cv > 0.5
    human_confidence    = min(cv, 1.0) if is_human else 1.0 - min(cv, 1.0)

    return is_human, round(human_confidence, 3)


def _get_cluster(features: dict) -> int:
    if features.get("recon_ratio", 0) > 0.5:
        return 0
    elif features.get("ssh_ratio", 0) > 0.5:
        return 1
    elif features.get("lure_accessed"):
        return 2
    elif features.get("known_malicious"):
        return 3
    else:
        return 4


def _generate_signature(attacker: Attacker, features: dict) -> str:
    sig_input = f"{attacker.ip_address}:{features['unique_tools']}:{features['recon_ratio']:.2f}:{features['ssh_ratio']:.2f}"
    return hashlib.md5(sig_input.encode()).hexdigest()[:16]


def _generate_summary(attacker, score, is_human, tools, tactics) -> str:
    actor_type  = "human operator" if is_human else "automated bot"
    tool_str    = ", ".join(tools[:3]) if tools else "unknown tools"
    tactic_str  = ", ".join(set(tactics[:3])) if tactics else "unknown tactics"
    return (
        f"Attacker {attacker.ip_address} identified as {actor_type} "
        f"with threat score {score:.1f}/100. "
        f"Primary tactics: {tactic_str}. "
        f"Tools detected: {tool_str}."
    )


def _generate_recommendations(score: float, features: dict) -> list:
    recs = []
    if score >= 80:
        recs.append("Immediately block IP at firewall level")
        recs.append("Escalate to SOC for manual investigation")
    if score >= 60:
        recs.append("Enable tarpit on all connections from this IP")
        recs.append("Feed decoy credentials to waste attacker time")
    if features.get("ssh_ratio", 0) > 0.3:
        recs.append("Enforce SSH key-only authentication")
    if features.get("known_malicious"):
        recs.append("Cross-reference with national threat intel feeds")
    if not recs:
        recs.append("Continue monitoring — no immediate action needed")
    return recs