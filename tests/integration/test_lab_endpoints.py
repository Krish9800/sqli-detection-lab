"""Integration tests for the dual-mode vulnerable and hardened database lab."""

import pytest

from sqlilab.lab.database import LabDatabase
from sqlilab.lab.endpoints import LabExecutor
from sqlilab.models.query import LabQueryRequest


@pytest.fixture
def lab_executor() -> LabExecutor:
    """Fixture providing initialized LabExecutor with fresh in-memory database."""
    db = LabDatabase()
    return LabExecutor(database=db)


def test_database_initialization_and_fixtures() -> None:
    """Verify database initializes tables and fixtures properly."""
    db = LabDatabase()
    users = db.execute_raw("SELECT * FROM users ORDER BY id ASC")
    assert len(users) == 4
    assert users[0]["username"] == "admin"

    products = db.execute_raw("SELECT * FROM products")
    assert len(products) == 4

    accounts = db.execute_raw("SELECT * FROM accounts")
    assert len(accounts) == 4

    db.close()


def test_user_lookup_insecure_vs_hardened(lab_executor: LabExecutor) -> None:
    """Verify insecure mode dumps data whereas hardened mode safely parameterizes."""
    # 1. Insecure mode with benign lookup
    benign_req = LabQueryRequest(
        param_value="alice",
        mode="insecure",
        endpoint="user_lookup",
    )
    benign_res = lab_executor.execute_simulation(benign_req)
    assert benign_res.executed_safely is False
    assert benign_res.row_count == 1
    assert benign_res.rows_returned[0]["username"] == "alice"
    assert benign_res.detection_verdict is not None
    assert benign_res.detection_verdict.is_malicious is False

    # 2. Insecure mode with tautology exploit: dumps entire table
    exploit_req = LabQueryRequest(
        param_value="' OR '1'='1",
        mode="insecure",
        endpoint="user_lookup",
    )
    exploit_res = lab_executor.execute_simulation(exploit_req)
    assert exploit_res.row_count == 4  # All rows leaked!
    assert exploit_res.detection_verdict is not None
    assert exploit_res.detection_verdict.is_malicious is True
    assert exploit_res.detection_verdict.risk_score >= 70.0

    # 3. Hardened mode with identical exploit: parameterized query prevents dump
    hardened_req = LabQueryRequest(
        param_value="' OR '1'='1",
        mode="hardened",
        endpoint="user_lookup",
    )
    hardened_res = lab_executor.execute_simulation(hardened_req)
    assert hardened_res.executed_safely is True
    assert hardened_res.row_count == 0  # No literal user named "' OR '1'='1"
    assert hardened_res.detection_verdict is not None
    assert hardened_res.detection_verdict.is_malicious is True


def test_auth_login_bypass_demonstration(lab_executor: LabExecutor) -> None:
    """Verify authentication bypass in insecure mode and containment in hardened mode."""
    # Insecure login bypass using comment payload
    bypass_req = LabQueryRequest(
        param_value="admin'--",
        mode="insecure",
        endpoint="auth_login",
    )
    bypass_res = lab_executor.execute_simulation(bypass_req)
    assert bypass_res.row_count == 1
    assert bypass_res.rows_returned[0]["username"] == "admin"
    assert bypass_res.detection_verdict is not None
    assert bypass_res.detection_verdict.is_malicious is True

    # Hardened login containment
    hardened_req = LabQueryRequest(
        param_value="admin'--",
        mode="hardened",
        endpoint="auth_login",
    )
    hardened_res = lab_executor.execute_simulation(hardened_req)
    assert hardened_res.executed_safely is True
    assert hardened_res.row_count == 0


def test_product_search_endpoints(lab_executor: LabExecutor) -> None:
    """Verify product search queries under insecure and hardened execution."""
    # Benign product search
    search_req = LabQueryRequest(
        param_value="Key",
        mode="hardened",
        endpoint="product_search",
    )
    search_res = lab_executor.execute_simulation(search_req)
    assert search_res.row_count >= 1
    assert any("Key" in p["name"] for p in search_res.rows_returned)

    # Insecure product search with syntax error
    bad_req = LabQueryRequest(
        param_value="'''",
        mode="insecure",
        endpoint="product_search",
    )
    bad_res = lab_executor.execute_simulation(bad_req)
    assert bad_res.error_message is not None
    assert any(
        err in bad_res.error_message.lower() for err in ("syntax error", "unrecognized token")
    )


def test_stacked_query_simulation(lab_executor: LabExecutor) -> None:
    """Verify stacked statement execution path in insecure mode."""
    stacked_req = LabQueryRequest(
        param_value="admin'; DELETE FROM users WHERE id = 999;--",
        mode="insecure",
        endpoint="user_lookup",
    )
    stacked_res = lab_executor.execute_simulation(stacked_req)
    assert stacked_res.error_message is None
    assert stacked_res.detection_verdict is not None
    assert stacked_res.detection_verdict.is_malicious is True
