"""Alert schemas for CRUD and analysis responses."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    """Full alert details."""

    id: uuid.UUID
    agent_id: uuid.UUID
    title: str
    description: str
    severity: str
    confidence: float
    status: str
    detection_source: str
    rule_id: str | None
    rule_name: str | None
    mitre_tactics: list[str] | None
    mitre_techniques: list[str] | None
    related_cves: list[str] | None
    llm_analysis: str | None
    llm_recommendation: str | None
    llm_confidence: float | None
    correlation_group: str | None
    related_alert_count: int
    detected_at: datetime
    first_event_at: datetime | None
    last_event_at: datetime | None
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""

    alerts: list[AlertResponse]
    total: int
    page: int
    page_size: int


class AlertUpdateRequest(BaseModel):
    """Update alert status or assignment."""

    status: str | None = Field(
        None,
        pattern=r"^(new|investigating|resolved|false_positive|escalated)$",
    )
    assigned_to: str | None = None
    notes: str | None = None


class AlertSeverityCount(BaseModel):
    """Count of alerts by severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
