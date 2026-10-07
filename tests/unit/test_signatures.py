"""Unit tests for SQLSignatureEngine pattern matches and rules."""

from sqlilab.detector.signatures import SQLSignatureEngine
from sqlilab.models.finding import ConfidenceLevel, SQLiCategory


def test_signature_error_based() -> None:
    """Test error-based extraction signatures."""
    p1 = "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))"
    findings1 = SQLSignatureEngine.match_signatures(p1)
    assert any(f.finding_id == "SIG-SQLI-ERR-01" for f in findings1)

    p2 = "1 AND UPDATEXML(1, CONCAT(0x7e, user()), 1)"
    findings2 = SQLSignatureEngine.match_signatures(p2)
    assert any(f.finding_id == "SIG-SQLI-ERR-01" for f in findings2)

    p3 = "1 AND CAST((SELECT user) AS INT)"
    findings3 = SQLSignatureEngine.match_signatures(p3)
    assert any(f.finding_id == "SIG-SQLI-ERR-02" for f in findings3)


def test_signature_time_blind() -> None:
    """Test inferential time-based sleep, delay, and benchmark signatures."""
    # MySQL / PG Sleep
    f_sleep = SQLSignatureEngine.match_signatures("1' AND SLEEP(5)--")
    assert any(f.finding_id == "SIG-SQLI-TIME-01" for f in f_sleep)
    assert f_sleep[0].category == SQLiCategory.TIME_BLIND
    assert f_sleep[0].confidence == ConfidenceLevel.CERTAIN

    # PG Sleep
    f_pg = SQLSignatureEngine.match_signatures("1; SELECT pg_sleep(10)")
    assert any(f.finding_id == "SIG-SQLI-TIME-01" for f in f_pg)

    # Benchmark
    f_bench = SQLSignatureEngine.match_signatures("1 AND BENCHMARK(5000000, MD5(1))")
    assert any(f.finding_id == "SIG-SQLI-TIME-02" for f in f_bench)

    # MSSQL Waitfor Delay
    f_wait = SQLSignatureEngine.match_signatures("1; WAITFOR DELAY '0:0:5'--")
    assert any(f.finding_id == "SIG-SQLI-TIME-03" for f in f_wait)


def test_signature_boolean_blind() -> None:
    """Test character extraction and conditional delays."""
    p1 = "1 AND ASCII(SUBSTR((SELECT password FROM users), 1, 1)) > 64"
    f1 = SQLSignatureEngine.match_signatures(p1)
    assert any(f.finding_id == "SIG-SQLI-BOOL-01" for f in f1)

    p2 = "1 AND IF(1=1, SLEEP(3), 0)"
    f2 = SQLSignatureEngine.match_signatures(p2)
    assert any(f.finding_id == "SIG-SQLI-BOOL-02" for f in f2)


def test_signature_oob_and_system_commands() -> None:
    """Test xp_cmdshell, into outfile, and load_file directives."""
    f_xp = SQLSignatureEngine.match_signatures("1; EXEC xp_cmdshell 'dir'")
    assert any(f.finding_id == "SIG-SQLI-OOB-01" for f in f_xp)
    assert f_xp[0].category == SQLiCategory.STACKED_QUERIES

    f_out = SQLSignatureEngine.match_signatures("SELECT * FROM users INTO OUTFILE '/tmp/users.txt'")
    assert any(f.finding_id == "SIG-SQLI-OOB-02" for f in f_out)

    f_load = SQLSignatureEngine.match_signatures("SELECT LOAD_FILE('/etc/passwd')")
    assert any(f.finding_id == "SIG-SQLI-OOB-03" for f in f_load)


def test_signature_metadata_and_obfuscation() -> None:
    """Test system table enumeration and char sequence reconstruction."""
    f_meta = SQLSignatureEngine.match_signatures(
        "1 UNION SELECT 1, 2 FROM information_schema.tables"
    )
    assert any(f.finding_id == "SIG-SQLI-META-01" for f in f_meta)

    f_sqlite = SQLSignatureEngine.match_signatures(
        "SELECT sql FROM sqlite_master WHERE type='table'"
    )
    assert any(f.finding_id == "SIG-SQLI-META-01" for f in f_sqlite)

    f_char = SQLSignatureEngine.match_signatures("CHAR(114, 111, 111, 116)")
    assert any(f.finding_id == "SIG-SQLI-ENC-01" for f in f_char)


def test_signature_benign_inputs() -> None:
    """Test benign clean inputs return zero signature hits."""
    clean = [
        "john.doe@company.com",
        "standard search keywords",
        "product catalog item 123",
        "O'Connor",
    ]
    for text in clean:
        assert SQLSignatureEngine.match_signatures(text) == []
