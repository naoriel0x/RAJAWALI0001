import json
import uuid
import enum

from sqlalchemy import Column, String, Integer, Float, Enum, Text, TypeDecorator
from app.core.database import Base
from app.core.timezone import WIBDateTime, now_wib


class JSONEncodedList(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return json.dumps([] if value is None else value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return []


class JSONEncodedDict(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return json.dumps({} if value is None else value)

    def process_result_value(self, value, dialect):
        if value is None:
            return {}
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return {}

class AttackerType(str, enum.Enum):
    HUMAN = "human"
    BOT = "bot"
    UNKNOWN = "unknown"

class SkillLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"

class AttackerStatus(str, enum.Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    MONITORING = "monitoring"
    RESOLVED = "resolved"

class Attacker(Base):
    __tablename__ = "attackers"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address      = Column(String(45), nullable=False, unique=True, index=True)
    hostname        = Column(String(255), nullable=True)
    country_code    = Column(String(10), nullable=True)
    country_name    = Column(String(100), nullable=True)
    isp             = Column(String(255), nullable=True)
    org             = Column(String(255), nullable=True)
    threat_score    = Column(Float, default=0.0)
    attacker_type   = Column(Enum(AttackerType), default=AttackerType.UNKNOWN)
    skill_level     = Column(Enum(SkillLevel), default=SkillLevel.LOW)
    status          = Column(Enum(AttackerStatus), default=AttackerStatus.MONITORING)
    tools_detected  = Column(JSONEncodedList, default=list)
    mitre_ttps      = Column(JSONEncodedList, default=list)
    mitre_stages    = Column(JSONEncodedList, default=list)
    total_events        = Column(Integer, default=0)
    ssh_attempts        = Column(Integer, default=0)
    http_attempts       = Column(Integer, default=0)
    login_attempts      = Column(Integer, default=0)
    commands_executed   = Column(Integer, default=0)
    is_known_malicious  = Column(Integer, default=0)
    abuse_confidence    = Column(Float, default=0.0)
    blacklist_sources   = Column(JSONEncodedList, default=list)
    is_blocked          = Column(Integer, default=0)
    is_tarpitted        = Column(Integer, default=0)
    fake_intel_fed      = Column(Integer, default=0)
    first_seen  = Column(WIBDateTime, default=now_wib)
    last_seen   = Column(WIBDateTime, onupdate=now_wib)
    blocked_at  = Column(WIBDateTime, nullable=True)

    def __repr__(self):
        return f"<Attacker {self.ip_address} score={self.threat_score}>"