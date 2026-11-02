from sqlalchemy import Column, String, Integer, Float, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.core.timezone import WIBDateTime, now_wib
from app.models.attacker import JSONEncodedDict
import enum
import uuid

class EventType(str, enum.Enum):
    PORT_SCAN       = "port_scan"
    DNS_RECON       = "dns_recon"
    THREAT_INTEL    = "threat_intel"
    BANNER_GRAB     = "banner_grab"
    SSH_CONNECT     = "ssh_connect"
    SSH_LOGIN       = "ssh_login"
    SSH_COMMAND     = "ssh_command"
    HTTP_REQUEST    = "http_request"
    HTTP_CRAWL      = "http_crawl"
    LURE_ACCESS     = "lure_access"
    IP_BLOCKED      = "ip_blocked"
    TARPIT_APPLIED  = "tarpit_applied"
    FAKE_INTEL_FED  = "fake_intel_fed"

class EventSeverity(str, enum.Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"
    
class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    attacker_id = Column(String(36), ForeignKey("attackers.id"), nullable=False, index=True)
    attacker    = relationship("Attacker", backref="events")
    event_type  = Column(Enum(EventType), nullable=False, index=True)
    severity    = Column(Enum(EventSeverity), default=EventSeverity.INFO)
    src_ip      = Column(String(45), nullable=False)
    src_port    = Column(Integer, nullable=True)
    dst_port    = Column(Integer, nullable=True)
    protocol    = Column(String(10), nullable=True)
    raw_payload = Column(Text, nullable=True)
    parsed_data = Column(JSONEncodedDict, default=dict)
    username    = Column(String(255), nullable=True)
    password    = Column(String(255), nullable=True)
    command     = Column(Text, nullable=True)
    http_method = Column(String(10), nullable=True)
    http_path   = Column(String(1024), nullable=True)
    user_agent  = Column(String(512), nullable=True)
    headers     = Column(JSONEncodedDict, default=dict)
    mitre_technique     = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(255), nullable=True)
    tool_detected = Column(String(100), nullable=True)
    timestamp       = Column(WIBDateTime, default=now_wib, index=True)
    interval_ms     = Column(Float, nullable=True)

    def __repr__(self):
        return f"<Event {self.event_type} from {self.src_ip}>"