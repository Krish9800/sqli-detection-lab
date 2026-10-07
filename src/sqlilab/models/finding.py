"""Domain models representing SQL injection detection taxonomy and findings."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SQLiCategory(StrEnum):
    """Classification of SQL Injection technique categories."""

    UNION_BASED = "UNION_BASED"
    ERROR_BASED = "ERROR_BASED"
    BOOLEAN_BLIND = "BOOLEAN_BLIND"
    TIME_BLIND = "TIME_BLIND"
    STACKED_QUERIES = "STACKED_QUERIES"
    TAUTOLOGY = "TAUTOLOGY"
    COMMENT_INJECTION = "COMMENT_INJECTION"
    HEURISTIC_ANOMALY = "HEURISTIC_ANOMALY"


class ConfidenceLevel(StrEnum):
    """Detection confidence rating."""

    CERTAIN = "CERTAIN"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class DetectionFinding(BaseModel):
    """Individual detection rule match or syntactic anomaly finding."""

    finding_id: str = Field(..., description="Unique finding or rule identifier")
    rule_name: str = Field(..., description="Human-readable rule name")
    category: SQLiCategory = Field(..., description="Vulnerability category")
    confidence: ConfidenceLevel = Field(..., description="Detection confidence level")
    cwe_id: str = Field(default="CWE-89", description="Mitre Common Weakness Enumeration ID")
    matched_payload: str = Field(..., description="Substring or pattern that triggered the rule")
    explanation: str = Field(..., description="Technical explanation of the detected flaw")
    remediation: str = Field(
        default="Utilize parameterized queries (prepared statements) with bound variables.",
        description="Actionable mitigation guidance",
    )
    ast_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional AST node information or token inspection metadata",
    )
