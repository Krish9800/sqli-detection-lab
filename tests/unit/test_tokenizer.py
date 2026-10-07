"""Unit tests for SQLASTAnalyzer and lexical token analysis."""

from sqlilab.detector.tokenizer import SQLASTAnalyzer
from sqlilab.models.finding import ConfidenceLevel, SQLiCategory


def test_ast_tautology_detection() -> None:
    """Test AST analyzer flags string and numeric tautologies."""
    payloads = [
        "' OR '1'='1",
        "' or 'a'='a'",
        "1 OR 1=1",
        "admin' AND 1=1",
        "' OR 2!=1",
        "test' OR 'admin' LIKE 'admin'",
    ]
    for p in payloads:
        findings = SQLASTAnalyzer.analyze_input(p)
        tautologies = [f for f in findings if f.category == SQLiCategory.TAUTOLOGY]
        assert len(tautologies) >= 1, f"Failed to detect tautology in: {p}"
        assert tautologies[0].confidence == ConfidenceLevel.CERTAIN


def test_ast_comment_injection() -> None:
    """Test AST analyzer flags line and inline comments."""
    payloads = [
        "admin'--",
        "admin' -- end of line",
        "admin'/* inline comment */",
        "root'# hash comment",
    ]
    for p in payloads:
        findings = SQLASTAnalyzer.analyze_input(p)
        comments = [f for f in findings if f.category == SQLiCategory.COMMENT_INJECTION]
        assert len(comments) >= 1, f"Failed to detect comment in: {p}"


def test_ast_stacked_queries() -> None:
    """Test AST analyzer flags multiple distinct commands separated by semicolons."""
    payload = "1; DROP TABLE accounts; SELECT 1;"
    findings = SQLASTAnalyzer.analyze_input(payload)
    stacked = [f for f in findings if f.category == SQLiCategory.STACKED_QUERIES]
    assert len(stacked) >= 1
    assert "DROP TABLE" in stacked[0].matched_payload or "stacked" in stacked[0].rule_name.lower()


def test_ast_union_select() -> None:
    """Test AST analyzer flags UNION SELECT expressions."""
    payload = "10 UNION ALL SELECT id, username, password FROM users"
    findings = SQLASTAnalyzer.analyze_input(payload)
    unions = [f for f in findings if f.category == SQLiCategory.UNION_BASED]
    assert len(unions) >= 1
    assert unions[0].finding_id == "FIND-AST-UNION-01"


def test_ast_imbalances() -> None:
    """Test unbalanced quotes and parentheses flags."""
    res_quote = SQLASTAnalyzer.analyze_input("admin' OR password = 1")
    assert any(f.finding_id == "FIND-AST-IMBALANCE-01" for f in res_quote)

    res_paren = SQLASTAnalyzer.analyze_input("((test)")
    assert any(f.finding_id == "FIND-AST-IMBALANCE-02" for f in res_paren)


def test_ast_benign_inputs_no_tautology() -> None:
    """Test benign inputs do not trigger false positive tautology or stacked findings."""
    benign = [
        "O'Connor",
        "shoes or boots",
        "simple query",
        "12345",
        "john.doe@example.com",
    ]
    for b in benign:
        findings = SQLASTAnalyzer.analyze_input(b)
        # Should not flag tautology, union, or stacked queries
        critical_categories = {
            SQLiCategory.TAUTOLOGY,
            SQLiCategory.UNION_BASED,
            SQLiCategory.STACKED_QUERIES,
        }
        for f in findings:
            assert f.category not in critical_categories, f"False positive on: {b} -> {f}"


def test_extract_token_summary() -> None:
    """Test statistical token summary extraction."""
    summary = SQLASTAnalyzer.extract_token_summary("SELECT * FROM users WHERE id = 1;")
    assert summary.total_tokens > 0
    assert summary.semicolon_count == 1
    assert summary.has_tautology is False
    assert summary.unbalanced_quotes is False
