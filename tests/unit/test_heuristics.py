"""Unit tests for SQLHeuristicAnalyzer entropy and density metrics."""

from sqlilab.detector.heuristics import SQLHeuristicAnalyzer
from sqlilab.models.finding import SQLiCategory


def test_shannon_entropy_calculation() -> None:
    """Test Shannon entropy computation on varied character distributions."""
    assert SQLHeuristicAnalyzer.calculate_shannon_entropy("") == 0.0
    assert SQLHeuristicAnalyzer.calculate_shannon_entropy("aaaaaaa") == 0.0

    # Normal text entropy is typically between 2.5 and 4.2
    normal_entropy = SQLHeuristicAnalyzer.calculate_shannon_entropy("standard user query")
    assert 2.5 <= normal_entropy <= 4.5

    # Moderately dispersed hex string
    hex_str = "0x4142434445464748494a4b4c4d4e4f50"
    high_entropy = SQLHeuristicAnalyzer.calculate_shannon_entropy(hex_str)
    assert high_entropy >= 3.0

    # Truly diverse high-entropy string
    max_entropy = SQLHeuristicAnalyzer.calculate_shannon_entropy("aB3$kL9#mZ1@wQ7!")
    assert max_entropy == 4.0


def test_special_char_density() -> None:
    """Test special operator and quote density ratios."""
    assert SQLHeuristicAnalyzer.calculate_special_char_density("") == 0.0
    # Clean string with zero special chars
    assert SQLHeuristicAnalyzer.calculate_special_char_density("alphanumeric") == 0.0

    # High density attack string: ' or 1=1;--
    attack = "' or 1=1;--"
    density = SQLHeuristicAnalyzer.calculate_special_char_density(attack)
    # 6 special characters (' = ; - -) out of 11 chars
    assert density > 0.4


def test_keyword_density() -> None:
    """Test SQL keyword density ratio calculation."""
    assert SQLHeuristicAnalyzer.calculate_keyword_density("") == 0.0
    assert SQLHeuristicAnalyzer.calculate_keyword_density("nothing matching here") == 0.0

    kw_string = "SELECT id FROM users WHERE name = 1"
    kw_density = SQLHeuristicAnalyzer.calculate_keyword_density(kw_string)
    # words: select, id, from, users, where, name (6 words, 3 keywords: select, from, where)
    assert kw_density == 0.5


def test_analyze_heuristics_attack_vs_benign() -> None:
    """Test heuristic analysis produces findings for attacks and remains clean for benign input."""
    # Attack payload with high special character density and SQL keywords
    attack_payload = "' UNION SELECT null, 0x61646d696e--"
    score, findings = SQLHeuristicAnalyzer.analyze_heuristics(attack_payload)
    assert score > 0.3
    assert len(findings) > 0
    assert any(f.category == SQLiCategory.HEURISTIC_ANOMALY for f in findings)

    # Benign input
    benign_text = "regular search text"
    b_score, b_findings = SQLHeuristicAnalyzer.analyze_heuristics(benign_text)
    assert b_score < 0.2
    assert b_findings == []

    # Empty text
    empty_score, empty_findings = SQLHeuristicAnalyzer.analyze_heuristics("")
    assert empty_score == 0.0
    assert empty_findings == []
