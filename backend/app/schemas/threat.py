from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID

from app.models.threat import ThreatLevel, ThreatCategory


class ThreatResponse(BaseModel):
    id: UUID
    attacker_id: UUID
    threat_level: ThreatLevel
    threat_category: ThreatCategory
    threat_score: float
    cluster_id: Optional[int]
    behavior_signature: Optional[str]
    is_human: int
    human_confidence: float
    ml_features: Dict[str, Any]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    kill_chain_phase: Optional[str]
    detected_tools: List[str]
    tool_signatures: Dict[str, Any]
    avg_interval_ms: Optional[float]
    min_interval_ms: Optional[float]
    max_interval_ms: Optional[float]
    timing_pattern: Optional[str]
    known_apt_group: Optional[str]
    ioc_matches: List[str]
    summary: Optional[str]
    recommendations: List[str]
    analyzed_at: datetime
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ThreatIntelCacheResponse(BaseModel):
    id: UUID
    ip_address: str
    is_malicious: int
    abuse_confidence: float
    abuse_reports: int
    categories: List[str]
    last_reported: Optional[datetime]
    cached_at: datetime
    expires_at: Optional[datetime]

    model_config = {"from_attributes": True}


class DashboardStats(BaseModel):
    total_attackers: int
    active_threats: int
    blocked_ips: int
    events_last_24h: int
    critical_threats: int
    top_countries: List[Dict[str, Any]]
    attack_types_breakdown: Dict[str, int]
    mitre_heatmap: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]
    threat_score_avg: float
    telemetry: List[Dict[str, Any]]
    severity_mix: Dict[str, int]