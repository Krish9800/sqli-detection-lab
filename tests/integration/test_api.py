"""Integration tests for the FastAPI microservice endpoints."""

from fastapi.testclient import TestClient

from sqlilab.api.app import app

client = TestClient(app)


def test_health_endpoint() -> None:
    """Verify /health returns healthy status and active version."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "timestamp" in data


def test_detect_endpoint_benign_and_malicious() -> None:
    """Verify /api/v1/detect classifies safe queries as clean and attacks as malicious."""
    # 1. Benign request
    res_clean = client.post(
        "/api/v1/detect",
        json={"input_text": "SELECT id, username FROM users WHERE id = 10;"},
    )
    assert res_clean.status_code == 200
    clean_data = res_clean.json()
    assert clean_data["is_malicious"] is False
    assert clean_data["risk_level"] == "CLEAN"

    # 2. Malicious request
    res_mal = client.post(
        "/api/v1/detect",
        json={"input_text": "' OR '1'='1"},
    )
    assert res_mal.status_code == 200
    mal_data = res_mal.json()
    assert mal_data["is_malicious"] is True
    assert mal_data["risk_level"] == "MALICIOUS"
    assert len(mal_data["findings"]) > 0


def test_simulate_endpoint_insecure_and_hardened() -> None:
    """Verify /api/v1/simulate executes query in vulnerable and hardened modes."""
    # 1. Insecure simulation
    res_insecure = client.post(
        "/api/v1/simulate",
        json={
            "param_value": "' OR '1'='1",
            "mode": "insecure",
            "endpoint": "user_lookup",
        },
    )
    assert res_insecure.status_code == 200
    insecure_data = res_insecure.json()
    assert insecure_data["executed_safely"] is False
    assert insecure_data["row_count"] == 4
    assert insecure_data["detection_verdict"]["is_malicious"] is True

    # 2. Hardened simulation
    res_hardened = client.post(
        "/api/v1/simulate",
        json={
            "param_value": "' OR '1'='1",
            "mode": "hardened",
            "endpoint": "user_lookup",
        },
    )
    assert res_hardened.status_code == 200
    hardened_data = res_hardened.json()
    assert hardened_data["executed_safely"] is True
    assert hardened_data["row_count"] == 0
    assert hardened_data["detection_verdict"]["is_malicious"] is True


def test_rules_endpoint() -> None:
    """Verify /api/v1/rules returns registered signature rules."""
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["total_rules"] >= 6
    assert len(data["rules"]) == data["total_rules"]
    assert any(r["rule_id"].startswith("SIG-SQLI") for r in data["rules"])
