

import os

os.environ["DATABASE_URL"] = "sqlite:///./test_security_records.db"
import base64

from fastapi.testclient import TestClient
from sqlalchemy import select

import main

client = TestClient(main.app)


def set_test_secrets(monkeypatch):
    key = base64.urlsafe_b64encode(b"K" * 32).decode()
    monkeypatch.setenv("APP_ENCRYPTION_KEY", key)
    monkeypatch.setenv("APP_CAPABILITY_TOKEN", "test-capability-token")


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_record_requires_capability_token(monkeypatch):
    set_test_secrets(monkeypatch)

    response = client.post(
        "/records",
        json={"owner": "Test User", "note": "Private note"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Valid capability token required"


def test_create_and_retrieve_encrypted_record(monkeypatch):
    set_test_secrets(monkeypatch)

    with main.SessionLocal() as session:
        session.query(main.SecureRecord).delete()
        session.commit()

    create_response = client.post(
        "/records",
        headers={"X-Capability-Token": "test-capability-token"},
        json={"owner": "Test User", "note": "Private note"},
    )
    assert create_response.status_code == 201
    record_id = create_response.json()["id"]

    with main.SessionLocal() as session:
        stored = session.get(main.SecureRecord, record_id)
        assert stored is not None
        assert stored.encrypted_note != "Private note"
        assert "Private note" not in stored.encrypted_note

    read_response = client.get(
        f"/records/{record_id}",
        headers={"X-Capability-Token": "test-capability-token"},
    )
    assert read_response.status_code == 200
    assert read_response.json()["note"] == "Private note"


def test_sql_injection_input_does_not_bypass_record_lookup(monkeypatch):
    set_test_secrets(monkeypatch)

    response = client.get(
        "/records/1 OR 1=1",
        headers={"X-Capability-Token": "test-capability-token"},
    )
    assert response.status_code in (404, 422)


def test_sql_injection_string_is_stored_as_data(monkeypatch):
    set_test_secrets(monkeypatch)

    injection_text = "' OR '1'='1"

    response = client.post(
        "/records",
        headers={"X-Capability-Token": "test-capability-token"},
        json={
            "owner": "Injection Test",
            "note": injection_text,
        },
    )

    assert response.status_code == 201
    record_id = response.json()["id"]

    read_response = client.get(
        f"/records/{record_id}",
        headers={"X-Capability-Token": "test-capability-token"},
    )

    assert read_response.status_code == 200
    assert read_response.json()["note"] == injection_text

