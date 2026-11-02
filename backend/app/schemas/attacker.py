from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from uuid import UUID

from app.models.attacker import AttackerType, SkillLevel, AttackerStatus


class AttackerBase(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None


class AttackerCreate(AttackerBase):
    pass


class AttackerUpdate(BaseModel):
    threat_score: Optional[float] = None
    attacker_type: Optional[AttackerType] = None
    skill_level: Optional[SkillLevel] = None
    status: Optional[AttackerStatus] = None
    tools_detected: Optional[List[str]] = None
    mitre_ttps: Optional[List[str]] = None
    mitre_stages: Optional[List[str]] = None
    is_blocked: Optional[int] = None
    is_tarpitted: Optional[int] = None


class AttackerResponse(AttackerBase):
    id: UUID
    threat_score: float
    attacker_type: AttackerType
    skill_level: SkillLevel
    status: AttackerStatus
    tools_detected: List[str]
    mitre_ttps: List[str]
    mitre_stages: List[str]
    total_events: int
    ssh_attempts: int
    http_attempts: int
    login_attempts: int
    commands_executed: int
    is_known_malicious: int
    abuse_confidence: float
    blacklist_sources: List[str]
    is_blocked: int
    is_tarpitted: int
    fake_intel_fed: int
    first_seen: datetime
    last_seen: Optional[datetime] = None
    blocked_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AttackerSummary(BaseModel):
    id: UUID
    ip_address: str
    country_code: Optional[str]
    country_name: Optional[str]
    isp: Optional[str]
    org: Optional[str]
    threat_score: float
    attacker_type: AttackerType
    skill_level: SkillLevel
    status: AttackerStatus
    total_events: int
    is_blocked: int
    first_seen: datetime
    last_seen: Optional[datetime]

    model_config = {"from_attributes": True}


class AttackerListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[AttackerSummary]