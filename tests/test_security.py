import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import main as tv

@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    tv.Base.metadata.create_all(test_engine)
    monkeypatch.setattr(tv, "STORE", tmp_path / "encrypted")
    tv.STORE.mkdir(parents=True, exist_ok=True)

    def override_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    tv.app.dependency_overrides[tv.db_dep] = override_db
    with TestClient(tv.app) as client:
        yield client, TestSession
    tv.app.dependency_overrides.clear()
    test_engine.dispose()


def create_user(Session, email, role="owner"):
    db = Session()
    user = tv.User(name=email.split("@")[0], email=email, password_hash=tv.pwd.hash("test-password-123"),
                   public_key="-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----",
                   private_key_bundle="encrypted-test-key-bundle", role=role)
    db.add(user); db.commit(); db.refresh(user)
    result = (user.id, tv.token_for(user))
    db.close()
    return result


def upload_as(client, token, filename="sample.pdf"):
    return client.post("/api/documents", headers={"Authorization": f"Bearer {token}"},
                       data={"wrapped_key": "wrapped-key-placeholder-123456", "category": "Contracts"},
                       files={"file": (filename, b"\x00" * 40, "application/octet-stream")})


def test_ungranted_user_cannot_list_open_or_download_document(app_client):
    client, Session = app_client
    owner_id, owner_token = create_user(Session, "owner@example.com")
    _, outsider_token = create_user(Session, "outsider@example.com")
    uploaded = upload_as(client, owner_token)
    assert uploaded.status_code == 200
    doc_id = uploaded.json()["id"]

    assert client.get("/api/documents", headers={"Authorization": f"Bearer {outsider_token}"}).json() == []
    key = client.get(f"/api/documents/{doc_id}/key", headers={"Authorization": f"Bearer {outsider_token}"})
    download = client.get(f"/api/documents/{doc_id}/ciphertext", headers={"Authorization": f"Bearer {outsider_token}"})
    assert key.status_code == 403
    assert download.status_code == 403

    db = Session()
    actions = [x.action for x in db.scalars(select(tv.Audit).where(tv.Audit.actor_id.is_not(None))).all()]
    assert "ACCESS_DENIED" in actions
    db.close()


def test_grant_then_revoke_removes_access_immediately(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "owner2@example.com")
    recipient_id, recipient_token = create_user(Session, "recipient@example.com", role="viewer")
    uploaded = upload_as(client, owner_token)
    doc_id = uploaded.json()["id"]

    grant = client.post(f"/api/documents/{doc_id}/share", headers={"Authorization": f"Bearer {owner_token}"},
                        json={"email": "recipient@example.com", "wrapped_key": "recipient-wrapped-key-123456", "permission": "read"})
    assert grant.status_code == 200
    assert client.get(f"/api/documents/{doc_id}/key", headers={"Authorization": f"Bearer {recipient_token}"}).status_code == 200

    revoke = client.delete(f"/api/documents/{doc_id}/permissions/{recipient_id}", headers={"Authorization": f"Bearer {owner_token}"})
    assert revoke.status_code == 200
    assert client.get(f"/api/documents/{doc_id}/key", headers={"Authorization": f"Bearer {recipient_token}"}).status_code == 403
    assert client.get(f"/api/documents/{doc_id}/ciphertext", headers={"Authorization": f"Bearer {recipient_token}"}).status_code == 403


def test_viewer_cannot_upload_or_share(app_client):
    client, Session = app_client
    _, viewer_token = create_user(Session, "viewer@example.com", role="viewer")
    assert upload_as(client, viewer_token).status_code == 403
    assert client.post("/api/documents/not-a-real-id/share", headers={"Authorization": f"Bearer {viewer_token}"},
                       json={"email": "other@example.com", "wrapped_key": "wrapped-key-placeholder-123456"}).status_code == 403

def test_non_admin_cannot_read_global_audit_or_verify_chain(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "ordinary@example.com")
    assert client.get("/api/admin/activity", headers={"Authorization": f"Bearer {owner_token}"}).status_code == 403
    assert client.get("/api/audit/verify", headers={"Authorization": f"Bearer {owner_token}"}).status_code == 403
    db = Session()
    assert db.scalar(select(tv.Audit).where(tv.Audit.action == "ADMIN_ACTION_DENIED")) is not None
    db.close()


def test_admin_can_review_activity_and_verify_audit(app_client):
    client, Session = app_client
    _, admin_token = create_user(Session, "admin@example.com", role="admin")
    _, owner_token = create_user(Session, "owner3@example.com")
    upload_as(client, owner_token)
    activity = client.get("/api/admin/activity", headers={"Authorization": f"Bearer {admin_token}"})
    verified = client.get("/api/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert activity.status_code == 200
    assert any(e["action"] == "DOCUMENT_UPLOADED" for e in activity.json()["events"])
    assert verified.status_code == 200
    assert verified.json()["valid"] is True


def test_viewer_cannot_edit_or_delete_another_users_document(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "owner4@example.com")
    viewer_id, viewer_token = create_user(Session, "viewer4@example.com", role="viewer")
    doc_id = upload_as(client, owner_token).json()["id"]
    db = Session(); db.add(tv.Permission(document_id=doc_id, user_id=viewer_id, wrapped_key="viewer-wrapped-key", permission="read")); db.commit(); db.close()
    assert client.patch(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {viewer_token}"},
                        json={"filename": "changed.pdf"}).status_code == 403
    assert client.delete(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {viewer_token}"}).status_code == 403


def test_read_grant_cannot_edit_metadata(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "owner5@example.com")
    reader_id, reader_token = create_user(Session, "reader5@example.com", role="viewer")
    doc_id = upload_as(client, owner_token).json()["id"]
    db = Session(); db.add(tv.Permission(document_id=doc_id, user_id=reader_id, wrapped_key="reader-wrapped-key", permission="read")); db.commit(); db.close()
    response = client.patch(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {reader_token}"},
                            json={"category": "Changed"})
    assert response.status_code == 403


def test_edit_grant_can_update_metadata(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "owner6@example.com")
    editor_id, editor_token = create_user(Session, "editor6@example.com", role="owner")
    doc_id = upload_as(client, owner_token).json()["id"]
    db = Session(); db.add(tv.Permission(document_id=doc_id, user_id=editor_id, wrapped_key="editor-wrapped-key", permission="edit")); db.commit(); db.close()
    response = client.patch(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {editor_token}"},
                            json={"category": "Reviewed"})
    assert response.status_code == 200
    assert response.json()["category"] == "Reviewed"


def test_audit_tampering_is_detected(app_client):
    client, Session = app_client
    _, admin_token = create_user(Session, "auditadmin@example.com", role="admin")
    _, owner_token = create_user(Session, "auditowner@example.com")
    upload_as(client, owner_token)
    db = Session()
    first = db.scalar(select(tv.Audit).order_by(tv.Audit.id.asc()))
    first.details = '{"tampered":true}'
    db.commit(); db.close()
    result = client.get("/api/audit/verify", headers={"Authorization": f"Bearer {admin_token}"})
    assert result.status_code == 200
    assert result.json()["valid"] is False


def test_denied_share_attempt_is_audited(app_client):
    client, Session = app_client
    _, owner_token = create_user(Session, "owner7@example.com")
    _, viewer_token = create_user(Session, "viewer7@example.com", role="viewer")
    doc_id = upload_as(client, owner_token).json()["id"]
    response = client.post(f"/api/documents/{doc_id}/share", headers={"Authorization": f"Bearer {viewer_token}"},
                           json={"email": "nobody@example.com", "wrapped_key": "wrapped-key-placeholder-123456"})
    assert response.status_code == 403
    db = Session()
    assert db.scalar(select(tv.Audit).where(tv.Audit.action == "OWNER_ACTION_DENIED")) is not None
    db.close()


def test_downgraded_viewer_cannot_use_old_owner_grant(app_client):
    client, Session = app_client
    owner_id, owner_token = create_user(Session, "downgrade@example.com")
    doc_id = upload_as(client, owner_token).json()["id"]
    db = Session(); user = db.get(tv.User, owner_id); user.role = "viewer"; db.commit(); db.close()
    # The existing owner permission row must not bypass the viewer account role.
    assert client.get(f"/api/documents/{doc_id}/key", headers={"Authorization": f"Bearer {owner_token}"}).status_code == 403
    assert client.delete(f"/api/documents/{doc_id}", headers={"Authorization": f"Bearer {owner_token}"}).status_code == 403
