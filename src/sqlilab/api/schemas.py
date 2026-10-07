"""Pydantic schemas for the REST API microservice."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from sqlilab.models.query import LabQueryResult, QueryAuditResult


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="healthy", description="Service health state")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Current server UTC timestamp",
    )


class AuditRequest(BaseModel):
    """Request payload to audit a SQL statement or input string."""

    input_text: str = Field(..., min_length=1, description="SQL query or parameter string to audit")


class RuleDetail(BaseModel):
    """Metadata describing an active detection signature rule."""

    rule_id: str
    name: str
    category: str
    confidence: str
    cwe_id: str
    explanation: str
    remediation: str


class RulesListResponse(BaseModel):
    """Response containing all registered detection rules."""

    total_rules: int
    rules: list[RuleDetail]


__all__ = [
    "AuditRequest",
    "HealthResponse",
    "LabQueryResult",
    "QueryAuditResult",
    "RuleDetail",
    "RulesListResponse",
]
