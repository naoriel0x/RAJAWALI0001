from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID

from app.models.event import EventType, EventSeverity


class EventCreate(BaseModel):
    attacker_id: UUID
    event_type: EventType
    severity: EventSeverity = EventSeverity.INFO
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    raw_payload: Optional[str] = None
    parsed_data: Dict[str, Any] = {}
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, Any] = {}
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    tool_detected: Optional[str] = None
    interval_ms: Optional[float] = None


class EventIngest(BaseModel):
    """Payload sent from the honeypot to the backend."""
    event_type: str
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    raw_payload: Optional[str] = None
    parsed_data: Dict[str, Any] = {}
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, Any] = {}
    tool_detected: Optional[str] = None


class EventResponse(BaseModel):
    id: UUID
    attacker_id: UUID
    event_type: EventType
    severity: EventSeverity
    src_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    raw_payload: Optional[str]
    parsed_data: Dict[str, Any]
    username: Optional[str]
    command: Optional[str]
    http_method: Optional[str]
    http_path: Optional[str]
    user_agent: Optional[str]
    mitre_technique: Optional[str]
    mitre_technique_name: Optional[str]
    tool_detected: Optional[str]
    timestamp: datetime
    interval_ms: Optional[float]

    model_config = {"from_attributes": True}


class EventListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[EventResponse]