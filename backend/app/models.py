from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address
import re
from typing import Literal
from pydantic import BaseModel, Field, field_validator


def now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Mode(str, Enum):
    monitoring = "monitoring"
    enforcement = "enforcement"


class Device(BaseModel):
    id: str
    name: str
    ip: str
    mac: str
    role: str
    trust: str


class Observation(BaseModel):
    ip: str
    mac: str
    source: str = "simulation"
    unsolicited: bool = False
    scenario: str | None = None
    label: Literal["positive", "negative"] | None = None
    legitimate: bool = False

    @field_validator("ip")
    @classmethod
    def valid_ipv4(cls, value: str) -> str:
        try:
            IPv4Address(value)
        except ValueError as exc:
            raise ValueError("ip must be a valid IPv4 address") from exc
        return value

    @field_validator("mac")
    @classmethod
    def valid_mac(cls, value: str) -> str:
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
            raise ValueError("mac must be six hexadecimal octets separated by colons")
        return value.lower()


class Mapping(BaseModel):
    ip: str
    mac: str
    trusted_mac: str | None
    status: str
    updated_at: datetime = Field(default_factory=now)


class Alert(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=now)
    severity: Severity
    type: str
    status: str = "open"
    affected_ip: str
    previous_mac: str | None = None
    observed_mac: str
    reason: str
    scenario: str | None = None
    label: str | None = None
    latency_ms: float | None = None


class Decision(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=now)
    ip: str
    mac: str
    action: str
    reason: str


class Event(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=now)
    type: str
    severity: Severity
    status: str
    message: str
    ip: str | None = None
    mac: str | None = None
    alert_id: str | None = None
    scenario: str | None = None
    label: str | None = None


class Evaluation(BaseModel):
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float | None
    recall: float | None
    latency_ms_mean: float | None
    labelled_positives: int
    labelled_negatives: int
    unknown_events: int
    note: str


class Snapshot(BaseModel):
    devices: list[Device]
    mappings: list[Mapping]
    alerts: list[Alert]
    events: list[Event]
    decisions: list[Decision]
    mode: Mode
    monitoring: bool
    evaluation: Evaluation
