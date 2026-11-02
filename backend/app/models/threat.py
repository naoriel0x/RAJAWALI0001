from sqlalchemy import Column, String, Integer, Float, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.attacker import JSONEncodedDict, JSONEncodedList
from app.core.timezone import WIBDateTime, now_wib
import uuid
import enum

class ThreatLevel(str, enum.Enum):
    MINIMAL  = "minimal"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class ThreatCategory(str, enum.Enum):
    RECONNAISSANCE  = "reconnaissance"
    BRUTE_FORCE     = "brute_force"
    EXPLOITATION    = "exploitation"
    LATERAL_MOVE    = "lateral_movement"
    EXFILTRATION    = "exfiltration"
    APT             = "apt"
    BOTNET          = "botnet"
    UNKNOWN         = "unknown"

class Threat(Base):
    __tablename__ = "threats"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    attacker_id = Column(String(36), ForeignKey("attackers.id"), nullable=False, index=True)
    attacker    = relationship("Attacker", backref="threats")
    threat_level    = Column(Enum(ThreatLevel), default=ThreatLevel.LOW)
    threat_category = Column(Enum(ThreatCategory), default=ThreatCategory.UNKNOWN)
    threat_score    = Column(Float, default=0.0)
    cluster_id          = Column(Integer, nullable=True)
    behavior_signature  = Column(String(255), nullable=True)
    is_human            = Column(Integer, default=1)
    human_confidence    = Column(Float, default=0.5)
    ml_features         = Column(JSONEncodedDict, default=dict)
    mitre_tactics       = Column(JSONEncodedList, default=list)
    mitre_techniques    = Column(JSONEncodedList, default=list)
    kill_chain_phase    = Column(String(100), nullable=True)
    detected_tools      = Column(JSONEncodedList, default=list)
    tool_signatures     = Column(JSONEncodedDict, default=dict)
    avg_interval_ms     = Column(Float, nullable=True)
    min_interval_ms     = Column(Float, nullable=True)
    max_interval_ms     = Column(Float, nullable=True)
    timing_pattern      = Column(String(50), nullable=True)
    known_apt_group     = Column(String(255), nullable=True)
    ioc_matches         = Column(JSONEncodedList, default=list)
    summary             = Column(Text, nullable=True)
    recommendations     = Column(JSONEncodedList, default=list)
    analyzed_at = Column(WIBDateTime, default=now_wib)
    updated_at  = Column(WIBDateTime, onupdate=now_wib)

    def __repr__(self):
        return f"<Threat level={self.threat_level} score={self.threat_score}>"

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id          = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address  = Column(String(45), nullable=False, unique=True, index=True)
    is_malicious        = Column(Integer, default=0)
    abuse_confidence    = Column(Float, default=0.0)
    abuse_reports       = Column(Integer, default=0)
    categories          = Column(JSONEncodedList, default=list)
    last_reported       = Column(WIBDateTime, nullable=True)
    raw_response    = Column(JSONEncodedDict, default=dict)
    cached_at   = Column(WIBDateTime, default=now_wib)
    expires_at  = Column(WIBDateTime, nullable=True)

    def __repr__(self):
        return f"<ThreatIntel {self.ip_address} malicious={self.is_malicious}>"