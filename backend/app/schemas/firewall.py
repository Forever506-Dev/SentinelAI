"""Firewall schemas for request/response validation."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── Rule Schemas ────────────────────────────────────────────

class FirewallRuleBase(BaseModel):
    """Base schema for firewall rule fields."""
    name: str = Field(..., max_length=255)
    direction: str = Field(..., pattern=r"^(inbound|outbound)$")
    action: str = Field(..., pattern=r"^(allow|block)$")
    protocol: str = Field("any", pattern=r"^(tcp|udp|any|icmp)$")
    local_port: str = Field("any", max_length=100)
    remote_port: str = Field("any", max_length=100)
    local_address: str = Field("any", max_length=255)
    remote_address: str = Field("any", max_length=255)
    enabled: bool = True
    profile: str = Field("any", max_length=50)


class FirewallRuleCreate(FirewallRuleBase):
    """Create a new firewall rule."""
    reason: str = Field("", max_length=1000)


class FirewallRuleUpdate(BaseModel):
    """Update an existing firewall rule (partial)."""
    name: str | None = Field(None, max_length=255)
    direction: str | None = Field(None, pattern=r"^(inbound|outbound)$")
    action: str | None = Field(None, pattern=r"^(allow|block)$")
    protocol: str | None = Field(None, pattern=r"^(tcp|udp|any|icmp)$")
    local_port: str | None = Field(None, max_length=100)
    remote_port: str | None = Field(None, max_length=100)
    local_address: str | None = Field(None, max_length=255)
    remote_address: str | None = Field(None, max_length=255)
    enabled: bool | None = None
    profile: str | None = Field(None, max_length=50)
    reason: str = Field("", max_length=1000)


class FirewallRuleResponse(FirewallRuleBase):
    """Full firewall rule details."""
    id: uuid.UUID
    agent_id: uuid.UUID
    policy_id: uuid.UUID | None = None
    synced_at: datetime | None = None
    drift_detected: bool = False
    current_version: int = 1
    created_by: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FirewallRuleListResponse(BaseModel):
    """Paginated list of firewall rules."""
    rules: list[FirewallRuleResponse]
    total: int
    page: int
    page_size: int


class FirewallRuleToggleRequest(BaseModel):
    """Toggle a firewall rule enabled/disabled."""
    enabled: bool
    reason: str = Field("", max_length=1000)


# ── Policy Schemas ──────────────────────────────────────────

class FirewallPolicyCreate(BaseModel):
    """Create a new firewall policy."""
    name: str = Field(..., max_length=255)
    description: str = Field("", max_length=2000)
    rules: list[FirewallRuleBase] = []
    default_inbound_action: str = Field("block", pattern=r"^(allow|block)$")
    default_outbound_action: str = Field("allow", pattern=r"^(allow|block)$")


class FirewallPolicyResponse(BaseModel):
    """Firewall policy details."""
    id: uuid.UUID
    name: str
    description: str | None
    rules: dict | None
    default_inbound_action: str
    default_outbound_action: str
    assigned_agent_count: int
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FirewallPolicyListResponse(BaseModel):
    """List of firewall policies."""
    policies: list[FirewallPolicyResponse]
    total: int


# ── Snapshot Schemas ────────────────────────────────────────

class FirewallSnapshotRequest(BaseModel):
    """Request a snapshot of live firewall rules from the agent."""
    pass


class FirewallSnapshotResponse(BaseModel):
    """Snapshot comparison result."""
    agent_id: str
    hostname: str
    live_rule_count: int
    tracked_rule_count: int
    drift_count: int
    new_rules: list[dict] = []
    missing_rules: list[dict] = []
    modified_rules: list[dict] = []


# ── Live Rules Response (agent relay) ───────────────────────

class LiveFirewallRulesResponse(BaseModel):
    """Live firewall rules fetched directly from agent."""
    agent_id: str
    hostname: str
    os_type: str
    status: str
    output: str
    rules: list[dict]
    total: int
