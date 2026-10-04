import hashlib
from email.message import EmailMessage
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.artifact_storage import LocalArtifactStorage
from app.services.email_parser import parse_email


def synthetic_email(multipart: bool = False) -> bytes:
    message = EmailMessage()
    message["From"] = "=?utf-8?q?Jos=C3=A9_Analyst?= <sender@example.com>"
    message["To"] = "analyst@example.net"
    message["Subject"] = "=?utf-8?b?U3VzcGljaW91cyBBbGVydA==?="
    message["Authentication-Results"] = "mx.example; spf=fail dkim=pass dmarc=fail"
    message["Received"] = "from mail.example.com ([192.168.1.10]) by mx.example.com; Tue, 01 Jan 2024 00:00:00 +0000"
    if multipart:
        message.set_content("Visit https://Example.com/reset and 203.0.113.7")
        message.add_alternative(
            '<html><body><script>alert(1)</script><a href="javascript:bad()">Reset</a></body></html>',
            subtype="html",
        )
        message.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="../../evil.exe")
    else:
        message.set_content("Plain body")
    return message.as_bytes()


def test_parser_handles_multipart_encoded_headers_and_security_metadata():
    result = parse_email(synthetic_email(multipart=True)).model_dump()
    assert result["subject"] == "Suspicious Alert"
    assert result["from_addr"] == "sender@example.com"
    assert result["plain_body"] is not None
    assert "<script" not in result["html_body"]
    assert "javascript:" not in result["html_body"]
    assert any(item["normalized_value"] == "https://example.com/reset" for item in result["indicators"])
    private = next(item for item in result["indicators"] if item["normalized_value"] == "192.168.1.10")
    assert private["is_private"] is True
    assert any(item["is_suspicious"] and item["filename"] == "evil.exe" for item in result["attachments"])
    assert result["auth_results"][0]["protocol"] == "SPF"
    assert result["hops"][0]["ip_address"] == "192.168.1.10"


def test_parser_tolerates_malformed_and_missing_headers():
    result = parse_email(b"Subject: broken\nContent-Type: multipart/mixed; boundary=missing\n\nnot multipart").model_dump()
    assert result["subject"] == "broken"
    assert result["from_addr"] is None
    assert result["headers"]


def test_storage_sanitizes_traversal_and_hashes_content(tmp_path: Path):
    storage = LocalArtifactStorage(str(tmp_path))
    content = b"email"
    path, digest, size = storage.store("../../../../etc/passwd.eml", content)
    assert Path(path).parent == tmp_path
    assert Path(path).name.endswith("_passwd.eml")
    assert digest == hashlib.sha256(content).hexdigest()
    assert size == len(content)


def test_api_rejects_non_eml_and_oversized_upload(tmp_path: Path, monkeypatch):
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(test_engine)
    Session = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    app.dependency_overrides[get_db] = lambda: Session()
    monkeypatch.setattr("app.main.engine", test_engine)
    monkeypatch.setattr("app.main.storage", LocalArtifactStorage(str(tmp_path)))
    monkeypatch.setenv("MAX_UPLOAD_SIZE", "4")
    try:
        with TestClient(app) as client:
            invalid = client.post("/api/v1/investigations", files={"file": ("note.txt", b"test", "text/plain")})
            assert invalid.status_code == 400
            oversized = client.post("/api/v1/investigations", files={"file": ("mail.eml", b"12345", "message/rfc822")})
            assert oversized.status_code == 413
    finally:
        app.dependency_overrides.clear()


def test_api_cors_rejects_unconfigured_origins():
    with TestClient(app) as client:
        blocked = client.get("/health", headers={"Origin": "https://attacker.example"})
        allowed = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert "access-control-allow-origin" not in blocked.headers
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert allowed.headers["x-content-type-options"] == "nosniff"
    assert allowed.headers["x-frame-options"] == "DENY"


def test_api_persists_complete_investigation(tmp_path: Path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    app.dependency_overrides[get_db] = lambda: Session()
    monkeypatch.setattr("app.main.engine", engine)
    monkeypatch.setattr("app.main.storage", LocalArtifactStorage(str(tmp_path)))
    monkeypatch.setenv("MAX_UPLOAD_SIZE", "100000")
    content = synthetic_email(multipart=True)
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/v1/investigations",
                files={"file": ("../suspicious.eml", content, "message/rfc822")},
            )
            assert response.status_code == 200, response.text
            item = response.json()
            assert item["status"] == "completed"
            assert item["artifacts"][0]["sha256"] == hashlib.sha256(content).hexdigest()
            assert item["artifacts"][0]["attachments"][0]["filename"] == "evil.exe"
            assert item["indicators"]
            detail = client.get(f"/api/v1/investigations/{item['id']}")
            assert detail.status_code == 200
            listing = client.get("/api/v1/investigations")
            assert listing.json()["total"] == 1
    finally:
        app.dependency_overrides.clear()
