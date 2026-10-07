"""Lexical tokenizer and Abstract Syntax Tree (AST) analyzer for SQL injection patterns."""

from dataclasses import dataclass
import re

import sqlparse
from sqlparse.tokens import Comment as CommentToken, Keyword, Operator

from sqlilab.models.finding import ConfidenceLevel, DetectionFinding, SQLiCategory


@dataclass
class TokenSummary:
    """Statistical and structural summary of tokenized SQL input."""

    total_tokens: int
    keyword_count: int
    operator_count: int
    comment_count: int
    semicolon_count: int
    has_tautology: bool
    unbalanced_quotes: bool
    unbalanced_parens: bool


class SQLASTAnalyzer:
    """Parses and audits SQL statements and input parameter fragments for structural anomalies."""

    TAUTOLOGY_PATTERN = re.compile(
        r"(?i)\b(or|and)\b\s+(['\"]?)([\w\d]+)\2\s*(=|!=|<>|like)\s*(['\"]?)\3\5?",
    )
    NUMERIC_TAUTOLOGY_PATTERN = re.compile(
        r"(?i)\b(or|and)\b\s+(\d+)\s*(=|!=|<>|>|<)\s*(\d+)",
    )
    COMMENT_PATTERN = re.compile(
        r"(--[^\r\n]*|/\*[\s\S]*?\*/|#[^\r\n]*)",
    )

    @classmethod
    def analyze_input(cls, input_text: str) -> list[DetectionFinding]:
        """Analyze raw input string for AST-level injection signatures."""
        findings: list[DetectionFinding] = []
        if not input_text or not input_text.strip():
            return findings

        clean_text = input_text.strip()

        # 1. Tautology Detection (e.g. ' OR '1'='1, 1=1)
        tautology_findings = cls._detect_tautologies(clean_text)
        findings.extend(tautology_findings)

        # 2. Comment Injection Detection (e.g. --, /* */, #)
        comment_findings = cls._detect_comment_injection(clean_text)
        findings.extend(comment_findings)

        # 3. Stacked Statement Detection (e.g. ; DROP TABLE ...)
        stacked_findings = cls._detect_stacked_statements(clean_text)
        findings.extend(stacked_findings)

        # 4. AST-based UNION Analysis using sqlparse
        union_findings = cls._detect_union_ast(clean_text)
        findings.extend(union_findings)

        # 5. Quote and Parenthesis Syntax Imbalance
        imbalance_findings = cls._detect_syntax_imbalances(clean_text)
        findings.extend(imbalance_findings)

        return findings

    @classmethod
    def _detect_tautologies(cls, text: str) -> list[DetectionFinding]:
        """Detect injected boolean conditions that unconditionally evaluate to True."""
        findings: list[DetectionFinding] = []

        # String or alphanumeric equality: 'a'='a', 1=1, '1'='1'
        match = cls.TAUTOLOGY_PATTERN.search(text)
        if match:
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-TAUTOLOGY-01",
                    rule_name="Boolean Tautology Expression Injection",
                    category=SQLiCategory.TAUTOLOGY,
                    confidence=ConfidenceLevel.CERTAIN,
                    matched_payload=match.group(0),
                    explanation=(
                        f"Detected injected boolean tautology '{match.group(0)}' "
                        "which alters query logic to evaluate unconditionally true."
                    ),
                    ast_details={"clause": match.group(0), "operator": match.group(4)},
                )
            )
            return findings

        # Numeric tautology comparison: e.g. 1=1, 2=2, or 1!=2
        num_match = cls.NUMERIC_TAUTOLOGY_PATTERN.search(text)
        if num_match:
            op = num_match.group(3)
            left = int(num_match.group(2))
            right = int(num_match.group(4))
            is_always_true = (
                (op == "=" and left == right)
                or (op in ("!=", "<>") and left != right)
                or (op == ">" and left > right)
                or (op == "<" and left < right)
            )
            if is_always_true:
                findings.append(
                    DetectionFinding(
                        finding_id="FIND-AST-TAUTOLOGY-02",
                        rule_name="Numeric Tautology Condition",
                        category=SQLiCategory.TAUTOLOGY,
                        confidence=ConfidenceLevel.CERTAIN,
                        matched_payload=num_match.group(0),
                        explanation=(
                            f"Detected numeric tautology '{num_match.group(0)}' "
                            "designed to bypass WHERE clause filters."
                        ),
                        ast_details={"clause": num_match.group(0), "left": left, "right": right},
                    )
                )

        return findings

    @classmethod
    def _detect_comment_injection(cls, text: str) -> list[DetectionFinding]:
        """Detect inline or terminating SQL comments used to truncate downstream query code."""
        findings: list[DetectionFinding] = []
        match = cls.COMMENT_PATTERN.search(text)
        if match:
            # Check context: If comment follows a quote or suspicious sequence
            matched = match.group(0)
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-COMMENT-01",
                    rule_name="SQL Comment Termination Injection",
                    category=SQLiCategory.COMMENT_INJECTION,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=matched,
                    explanation=(
                        f"Detected SQL comment sequence '{matched}' which neutralizes "
                        "subsequent clauses or password checks in dynamic queries."
                    ),
                    ast_details={"comment": matched},
                )
            )
        return findings

    @classmethod
    def _detect_stacked_statements(cls, text: str) -> list[DetectionFinding]:
        """Detect semicolon statement terminators indicating stacked query execution."""
        findings: list[DetectionFinding] = []
        parsed = sqlparse.parse(text)
        if len(parsed) > 1:
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-STACKED-01",
                    rule_name="Stacked Query Injection",
                    category=SQLiCategory.STACKED_QUERIES,
                    confidence=ConfidenceLevel.HIGH,
                    matched_payload=text,
                    explanation=(
                        "Multiple distinct SQL statements detected in a single input parameter, "
                        "indicating an attempt to execute stacked administrative commands."
                    ),
                    ast_details={"statement_count": len(parsed)},
                )
            )
        elif ";" in text:
            # Check if semicolon is followed by SQL keywords
            after_semi = text.split(";", 1)[1].strip()
            if re.search(
                r"(?i)\b(select|insert|update|delete|drop|alter|create|exec)\b", after_semi
            ):
                findings.append(
                    DetectionFinding(
                        finding_id="FIND-AST-STACKED-02",
                        rule_name="Stacked SQL Command Terminator",
                        category=SQLiCategory.STACKED_QUERIES,
                        confidence=ConfidenceLevel.CERTAIN,
                        matched_payload=text,
                        explanation=(
                            "Detected semicolon followed by SQL command keyword, "
                            "representing a stacked query injection vector."
                        ),
                        ast_details={"stacked_command": after_semi[:50]},
                    )
                )
        return findings

    @classmethod
    def _detect_union_ast(cls, text: str) -> list[DetectionFinding]:
        """Inspect token stream for UNION / UNION ALL statement operators."""
        findings: list[DetectionFinding] = []
        # Pattern matching for UNION combined with SELECT or ALL
        if re.search(r"(?i)\bunion\s+(all\s+)?select\b", text):
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-UNION-01",
                    rule_name="UNION-Based Query Chaining",
                    category=SQLiCategory.UNION_BASED,
                    confidence=ConfidenceLevel.CERTAIN,
                    matched_payload=text,
                    explanation=(
                        "Detected UNION SELECT injection structure used to extract data "
                        "from alternate tables."
                    ),
                    ast_details={"type": "UNION_SELECT"},
                )
            )
        return findings

    @classmethod
    def _detect_syntax_imbalances(cls, text: str) -> list[DetectionFinding]:
        """Check for unmatched quote characters or parentheses signifying syntax escapes."""
        findings: list[DetectionFinding] = []

        # Count quotes outside escapes
        single_quotes = text.count("'")
        double_quotes = text.count('"')

        # If odd number of single or double quotes, could be deliberate break out
        if (single_quotes % 2 != 0) or (double_quotes % 2 != 0):
            has_sql_hints = bool(
                re.search(
                    r"(?i)\b(or|and|select|union|where|from|having|group|order|limit)\b",
                    text,
                )
            )
            confidence = ConfidenceLevel.HIGH if has_sql_hints else ConfidenceLevel.LOW
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-IMBALANCE-01",
                    rule_name="Unbalanced Quote Syntax Escape",
                    category=SQLiCategory.HEURISTIC_ANOMALY,
                    confidence=confidence,
                    matched_payload="'" if single_quotes % 2 != 0 else '"',
                    explanation=(
                        "Detected unbalanced quote character, commonly utilized "
                        "to escape string delimiters in vulnerable SQL statements."
                    ),
                    ast_details={
                        "single_quote_count": single_quotes,
                        "double_quote_count": double_quotes,
                    },
                )
            )

        # Check parentheses balance
        open_parens = text.count("(")
        close_parens = text.count(")")
        if open_parens != close_parens and (open_parens > 0 or close_parens > 0):
            findings.append(
                DetectionFinding(
                    finding_id="FIND-AST-IMBALANCE-02",
                    rule_name="Unbalanced Parenthesis Delimiter",
                    category=SQLiCategory.HEURISTIC_ANOMALY,
                    confidence=ConfidenceLevel.MEDIUM,
                    matched_payload=f"({open_parens} open vs {close_parens} close)",
                    explanation="Parentheses are unbalanced, signaling syntax breakout attempts.",
                    ast_details={"open_parens": open_parens, "close_parens": close_parens},
                )
            )

        return findings

    @classmethod
    def extract_token_summary(cls, text: str) -> TokenSummary:
        """Extract lexical statistical metrics from input string."""
        tokens = list(sqlparse.lexer.tokenize(text))  # type: ignore[no-untyped-call]
        keyword_count = sum(1 for tok_type, _ in tokens if tok_type in Keyword)
        operator_count = sum(1 for tok_type, _ in tokens if tok_type in Operator)
        comment_count = sum(1 for tok_type, _ in tokens if tok_type in CommentToken)
        semicolon_count = text.count(";")
        has_tautology = bool(
            cls.TAUTOLOGY_PATTERN.search(text) or cls.NUMERIC_TAUTOLOGY_PATTERN.search(text)
        )
        unbalanced_quotes = (text.count("'") % 2 != 0) or (text.count('"') % 2 != 0)
        unbalanced_parens = text.count("(") != text.count(")")

        return TokenSummary(
            total_tokens=len(tokens),
            keyword_count=keyword_count,
            operator_count=operator_count,
            comment_count=comment_count,
            semicolon_count=semicolon_count,
            has_tautology=has_tautology,
            unbalanced_quotes=unbalanced_quotes,
            unbalanced_parens=unbalanced_parens,
        )

    def analyze(self, input_text: str) -> list[DetectionFinding]:
        """Instance method alias for analyze_input."""
        return self.analyze_input(input_text)

    def extract_tokens(self, text: str) -> TokenSummary:
        """Instance method alias for extract_token_summary."""
        return self.extract_token_summary(text)
