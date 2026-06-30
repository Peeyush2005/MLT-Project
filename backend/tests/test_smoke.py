"""Hackathon-speed smoke tests for backend contract and demo stability."""

import base64
import io
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
from app.db import init_db
from app.main import app

init_db()
client = TestClient(app, raise_server_exceptions=True)

BENIGN_RECORD = {
    "ioc_type": "ip",
    "threat_type": "benign",
    "malware_family": "none",
    "confidence_level": 20,
    "dst_port": 80,
    "days_active": 2,
    "src_country": "US",
    "tags": "known_good",
    "reporter": "analyst_team_a",
}

MALWARE_RECORD = {
    "ioc_type": "domain",
    "threat_type": "botnet_cc",
    "malware_family": "emotet",
    "confidence_level": 75,
    "dst_port": 4444,
    "days_active": 15,
    "src_country": "RU",
    "tags": "c2",
    "reporter": "honeypot_net",
}


def create_key(label: str = "smoke", rate_limit_per_min: int = 60) -> tuple[str, str]:
    resp = client.post(
        "/api/keys",
        json={"label": label, "rate_limit_per_min": rate_limit_per_min},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["api_key"], data["key_id"]


def auth_headers(api_key: str) -> dict:
    return {"X-API-Key": api_key}


def test_predict_contract_and_unseen_category_fallback():
    key, _ = create_key("predict-contract")

    resp = client.post("/api/predict", json=BENIGN_RECORD, headers=auth_headers(key))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["prediction"] in {"benign", "malware"}
    assert 0.0 <= data["confidence"] <= 1.0
    assert "all_probabilities" in data
    probs = data["all_probabilities"]
    assert abs(sum(probs.values()) - 1.0) < 1e-4

    unseen = dict(BENIGN_RECORD)
    unseen["src_country"] = "ATLANTIS"
    unseen["ioc_type"] = "SATELLITE"
    unseen_resp = client.post("/api/predict", json=unseen, headers=auth_headers(key))
    assert unseen_resp.status_code == 200, unseen_resp.text


def test_malformed_numeric_returns_422_not_500():
    key, _ = create_key("bad-numeric")
    payload = dict(BENIGN_RECORD)
    payload["dst_port"] = "not-a-number"

    resp = client.post("/api/predict", json=payload, headers=auth_headers(key))
    assert resp.status_code == 422, resp.text


def test_api_key_lifecycle_create_use_revoke():
    key, key_id = create_key("lifecycle")

    ok = client.post("/api/predict", json=MALWARE_RECORD, headers=auth_headers(key))
    assert ok.status_code == 200, ok.text

    revoke_resp = client.delete(f"/api/keys/{key_id}")
    assert revoke_resp.status_code == 200, revoke_resp.text

    rejected = client.post("/api/predict", json=MALWARE_RECORD, headers=auth_headers(key))
    assert rejected.status_code == 401, rejected.text


def test_rate_limit_returns_429_and_retry_after():
    key, _ = create_key("rl", rate_limit_per_min=5)

    hit_429 = None
    for _ in range(20):
        resp = client.post("/api/predict", json=BENIGN_RECORD, headers=auth_headers(key))
        if resp.status_code == 429:
            hit_429 = resp
            break

    assert hit_429 is not None, "Expected at least one 429 when exceeding low limit"
    assert "Retry-After" in hit_429.headers


def test_route_status_matrix_and_schema_basics():
    key, key_id = create_key("route-matrix")
    headers = auth_headers(key)

    r_predict = client.post("/api/predict", json=BENIGN_RECORD, headers=headers)
    assert r_predict.status_code == 200

    r_batch = client.post(
        "/api/predict/batch",
        json={"records": [BENIGN_RECORD, MALWARE_RECORD]},
        headers=headers,
    )
    assert r_batch.status_code == 200
    batch_data = r_batch.json()
    assert "results" in batch_data and "summary" in batch_data

    csv_content = (
        "ioc_type,threat_type,malware_family,confidence_level,dst_port,days_active,"
        "src_country,tags,reporter\n"
        "domain,botnet_cc,emotet,75,4444,15,RU,c2,honeypot_net\n"
    )
    r_csv = client.post(
        "/api/predict/csv",
        headers=headers,
        files={"file": ("quick.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
    )
    assert r_csv.status_code == 200

    r_info = client.get("/api/model/info")
    assert r_info.status_code == 200

    r_imp = client.get("/api/model/feature-importance")
    assert r_imp.status_code == 200

    r_health = client.get("/api/health")
    assert r_health.status_code == 200

    r_keys = client.get("/api/keys")
    assert r_keys.status_code == 200

    r_usage = client.get(f"/api/keys/{key_id}/usage")
    assert r_usage.status_code == 200

    r_scenarios = client.get("/api/simulate/scenarios", headers=headers)
    assert r_scenarios.status_code == 200
    scenarios = r_scenarios.json()["scenarios"]
    assert len(scenarios) > 0

    scenario_id = scenarios[0]["scenario"]
    r_sim = client.post(
        "/api/simulate/scenario",
        headers=headers,
        json={"scenario": scenario_id},
    )
    assert r_sim.status_code == 200

    r_stats = client.get("/api/stream/stats", headers=headers)
    assert r_stats.status_code == 200


def test_golden_label_regression_records():
    key, _ = create_key("golden")
    headers = auth_headers(key)

    golden_cases = [
        (MALWARE_RECORD, "malware"),
        (BENIGN_RECORD, "benign"),
        (
            {
                "ioc_type": "hash",
                "threat_type": "ransomware",
                "malware_family": "lockbit",
                "confidence_level": 95,
                "dst_port": 445,
                "days_active": 30,
                "src_country": "DE",
                "tags": "lateral_movement",
                "reporter": "partner_org",
            },
            "malware",
        ),
    ]

    for record, expected in golden_cases:
        resp = client.post("/api/predict", json=record, headers=headers)
        assert resp.status_code == 200, resp.text
        assert resp.json()["prediction"] == expected


def test_csv_five_rows_one_bad_row():
    key, _ = create_key("csv-five")
    headers = auth_headers(key)

    csv_payload = (
        "ioc_type,threat_type,malware_family,confidence_level,dst_port,days_active,"
        "src_country,tags,reporter\n"
        "domain,botnet_cc,emotet,75,4444,15,RU,c2,honeypot_net\n"
        "ip,benign,none,20,80,2,US,known_good,analyst_team_a\n"
        "url,phishing,trickbot,60,443,7,CN,exfil,automated_feed_1\n"
        "hash,ransomware,lockbit,90,445,30,DE,lateral_movement,partner_org\n"
        "ip,benign,none,BADVALUE,80,2,US,known_good,analyst_team_b\n"
    )

    resp = client.post(
        "/api/predict/csv",
        headers=headers,
        files={"file": ("test.csv", io.BytesIO(csv_payload.encode("utf-8")), "text/csv")},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert len(data["results"]) == 4
    assert len(data["errors"]) == 1
    assert data["errors"][0]["row_index"] == 4
    decoded = base64.b64decode(data["csv_content"]).decode("utf-8")
    assert "prediction" in decoded
