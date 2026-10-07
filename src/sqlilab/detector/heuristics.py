"""Heuristic and information-theoretic entropy analyzer for SQL injection payloads."""

from dataclasses import dataclass
import math
import re
from typing import ClassVar

from sqlilab.models.finding import ConfidenceLevel, DetectionFinding, SQLiCategory


@dataclass(frozen=True)
class HeuristicMetrics:
    """Statistical and information-theoretic metrics for an analyzed string."""

    entropy: float
    special_char_density: float
    keyword_density: float
    anomaly_score: float


class SQLHeuristicAnalyzer:
    """Analyzes character distributions, Shannon entropy, and special operator density."""

    SPECIAL_CHARS: ClassVar[set[str]] = {
        "'",
        '"',
        ";",
        "-",
        "*",
        "/",
        "=",
        ">",
        "<",
        "%",
        "(",
        ")",
        "\\",
        "|",
        "&",
        "^",
        "~",
        "#",
    }

    SQL_KEYWORDS_SET: ClassVar[set[str]] = {
        "select",
        "insert",
        "update",
        "delete",
        "union",
        "where",
        "from",
        "and",
        "or",
        "having",
        "group",
        "order",
        "limit",
        "drop",
        "alter",
        "create",
        "exec",
        "execute",
        "sleep",
        "benchmark",
        "waitfor",
        "cast",
        "convert",
        "null",
        "like",
    }

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculate Shannon entropy (bits per character) of input string."""
        if not text:
            return 0.0

        length = len(text)
        freqs: dict[str, int] = {}
        for char in text:
            freqs[char] = freqs.get(char, 0) + 1

        entropy = 0.0
        for count in freqs.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return round(entropy, 4)

    @classmethod
    def calculate_special_char_density(cls, text: str) -> float:
        """Calculate ratio of SQL-relevant punctuation and operators to string length."""
        if not text:
            return 0.0

        special_count = sum(1 for c in text if c in cls.SPECIAL_CHARS)
        return round(special_count / len(text), 4)

    @classmethod
    def calculate_keyword_density(cls, text: str) -> float:
        """Calculate ratio of SQL keywords to total whitespace-delimited words."""
        if not text:
            return 0.0

        words = re.findall(r"\b[a-zA-Z_]+\b", text.lower())
        if not words:
            return 0.0

        kw_count = sum(1 for w in words if w in cls.SQL_KEYWORDS_SET)
        return round(kw_count / len(words), 4)

    @classmethod
    def analyze_heuristics(
        cls,
        text: str,
        entropy_threshold: float = 4.5,
        density_threshold: float = 0.25,
    ) -> tuple[float, list[DetectionFinding]]:
        """Compute heuristic anomaly score and produce findings if thresholds are exceeded."""
        findings: list[DetectionFinding] = []
        if not text or not text.strip():
            return 0.0, findings

        entropy = cls.calculate_shannon_entropy(text)
        special_density = cls.calculate_special_char_density(text)
        keyword_density = cls.calculate_keyword_density(text)

        # Base anomaly score between 0.0 and 1.0
        # High special char density + SQL keywords is a very strong injection signal
        score = min(
            1.0,
            (special_density * 1.5) + (keyword_density * 0.8) + (max(0.0, entropy - 3.5) * 0.2),
        )

        # Flag 1: Abnormally high special character density or keyword density
        if len(text) >= 6 and (
            (special_density >= density_threshold and keyword_density > 0.0)
            or (keyword_density >= 0.4 and special_density > 0.05)
        ):
            findings.append(
                DetectionFinding(
                    finding_id="FIND-HEUR-DENSITY-01",
                    rule_name="Abnormal SQL Operator and Quote Density",
                    category=SQLiCategory.HEURISTIC_ANOMALY,
                    confidence=ConfidenceLevel.MEDIUM,
                    matched_payload=text,
                    explanation=(
                        f"Detected high concentration of SQL operator characters "
                        f"({special_density:.1%}) combined with SQL keywords."
                    ),
                    ast_details={"special_char_density": special_density},
                )
            )

        # Flag 2: Extreme entropy with hex / character sequences
        if (
            len(text) >= 16
            and entropy >= entropy_threshold
            and bool(re.search(r"0x[0-9a-fA-F]+", text))
        ):
            findings.append(
                DetectionFinding(
                    finding_id="FIND-HEUR-ENTROPY-01",
                    rule_name="High Entropy Obfuscated Hex Payload",
                    category=SQLiCategory.HEURISTIC_ANOMALY,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=text,
                    explanation=(
                        f"Detected elevated Shannon entropy ({entropy:.2f} bits/char) "
                        "with hex-encoded character buffers."
                    ),
                    ast_details={"entropy": entropy},
                )
            )

        return round(score, 4), findings

    def analyze(
        self,
        text: str,
        entropy_threshold: float = 4.5,
        density_threshold: float = 0.25,
    ) -> tuple[HeuristicMetrics, list[DetectionFinding]]:
        """Compute full statistical heuristics and generate findings."""
        entropy = self.calculate_shannon_entropy(text)
        special_density = self.calculate_special_char_density(text)
        keyword_density = self.calculate_keyword_density(text)
        score, findings = self.analyze_heuristics(
            text,
            entropy_threshold=entropy_threshold,
            density_threshold=density_threshold,
        )
        metrics = HeuristicMetrics(
            entropy=entropy,
            special_char_density=special_density,
            keyword_density=keyword_density,
            anomaly_score=score,
        )
        return metrics, findings
