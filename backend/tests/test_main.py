from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def graph():
    return {
        "nodes": [
            {"id": "emp_a", "type": "employee", "label": "Avery"},
            {"id": "grp_a", "type": "identity_group", "label": "Finance"},
            {"id": "drive", "type": "resource", "label": "Payroll", "sensitivity": 9, "pii": True},
            {"id": "db", "type": "cloud_resource", "label": "Production DB", "sensitivity": 10, "environment": "prod"},
        ],
        "edges": [
            {"from": "emp_a", "to": "grp_a", "relation": "member_of"},
            {"from": "grp_a", "to": "drive", "relation": "can_read"},
            {"from": "drive", "to": "db", "relation": "exposes"},
        ],
    }


def test_simulates_and_reduces_after_cut():
    before = client.post("/api/v1/simulate", json={"graph": graph(), "employee_id": "emp_a"})
    assert before.status_code == 200
    result = before.json()
    assert result["verdict"] == "CRITICAL"
    assert result["recommendations"]
    revoked = [item["edge_index"] for item in result["recommendations"]]
    after = client.post("/api/v1/simulate", json={"graph": graph(), "employee_id": "emp_a", "revoked_edges": revoked})
    assert after.status_code == 200
    assert after.json()["impact_score"] < result["impact_score"]


def test_rejects_unknown_edge_endpoint():
    invalid = graph()
    invalid["edges"][0]["to"] = "missing"
    response = client.post("/api/v1/simulate", json={"graph": invalid, "employee_id": "emp_a"})
    assert response.status_code == 422
