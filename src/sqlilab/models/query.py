"""Domain models for query audit verdicts, execution traces, and lab payloads."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from sqlilab.models.finding import DetectionFinding


class QueryAuditResult(BaseModel):
    """Consolidated assessment verdict for an inspected query or payload string."""

    input_text: str = Field(..., description="Original input text analyzed")
    is_malicious: bool = Field(..., description="True if input is assessed as malicious SQLi")
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated risk score from 0.0 (clean) to 100.0 (critical attack)",
    )
    risk_level: str = Field(
        default="CLEAN",
        description="Qualitative risk categorization: CLEAN, SUSPICIOUS, or MALICIOUS",
    )
    findings: list[DetectionFinding] = Field(
        default_factory=list,
        description="List of specific detection triggers and anomalies",
    )
    entropy: float = Field(
        default=0.0,
        description="Calculated Shannon entropy of the input string",
    )
    token_count: int = Field(
        default=0,
        description="Total tokens identified during lexical parsing",
    )
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC analysis timestamp",
    )


class LabQueryRequest(BaseModel):
    """Request payload to execute a query against the simulated laboratory database."""

    param_value: str = Field(..., description="User-supplied parameter value to test")
    mode: str = Field(
        default="insecure",
        description="Lab execution mode: 'insecure' (concatenation) or 'hardened' (parameterized)",
    )
    endpoint: str = Field(
        default="user_lookup",
        description="Lab target endpoint: 'user_lookup', 'product_search', or 'auth_login'",
    )


class LabQueryResult(BaseModel):
    """Result of query execution within the simulated laboratory database."""

    raw_input: str
    mode: str
    endpoint: str
    constructed_sql: str
    executed_safely: bool
    rows_returned: list[dict[str, Any]]
    row_count: int
    error_message: str | None = None
    detection_verdict: QueryAuditResult | None = None
