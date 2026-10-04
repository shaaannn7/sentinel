import hashlib
import json
import secrets
import pytest
from pathlib import Path
from email.message import EmailMessage
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.auth import AuthUser, UserRole, require_viewer, require_analyst, require_admin
from app.core.logging import SanitizingFilter
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.artifact_storage import LocalArtifactStorage
from app.services.threat_intel import is_safe_ip, is_safe_domain, is_safe_url, ThreatIntelProvider
from app.brain.ml.classifier import BrainClassifier, META_PATH, MODEL_PATH


def create_test_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autocommit=False, autoflush=False)


def sample_eml_content() -> bytes:
    msg = EmailMessage()
    msg["From"] = "test@external.com"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "Urgent Notice"
    msg.set_content("Please click the link.")
    return msg.as_bytes()


# ==========================================
# 1. SSRF MITIGATION TESTS
# ==========================================

def test_ssrf_safe_ip_detection():
    # Dangerous/Private/Cloud IPs must be rejected
    assert is_safe_ip("127.0.0.1") is False
    assert is_safe_ip("10.0.0.5") is False
    assert is_safe_ip("172.16.1.1") is False
    assert is_safe_ip("192.168.1.1") is False
    assert is_safe_ip("169.254.169.254") is False  # AWS/GCP metadata
    assert is_safe_ip("0.0.0.0") is False
    assert is_safe_ip("::1") is False  # IPv6 loopback

    # Legitimate public IPs must be accepted
    assert is_safe_ip("8.8.8.8") is True
    assert is_safe_ip("1.1.1.1") is True
    assert is_safe_ip("208.67.222.222") is True


def test_ssrf_safe_domain_detection():
    # Internal/Metadata domains must be rejected
    assert is_safe_domain("localhost") is False
    assert is_safe_domain("localhost.localdomain") is False
    assert is_safe_domain("metadata.google.internal") is False
    assert is_safe_domain("instance-data") is False
    assert is_safe_domain("company.internal") is False
    assert is_safe_domain("server.corp") is False
    assert is_safe_domain("router.lan") is False

    # Valid public domains must be accepted
    assert is_safe_domain("google.com") is True
    assert is_safe_domain("github.com") is True
    assert is_safe_domain("subdomain.example.org") is True


def test_ssrf_safe_url_detection():
    assert is_safe_url("http://127.0.0.1/admin") is False
    assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False
    assert is_safe_url("http://localhost:8000") is False
    assert is_safe_url("file:///etc/passwd") is False
    assert is_safe_url("gopher://127.0.0.1:6379") is False

    assert is_safe_url("https://www.google.com/search?q=test") is True
    assert is_safe_url("https://api.github.com/repos") is True


def test_threat_intel_blocks_internal_ip_lookup():
    provider = ThreatIntelProvider()
    # Looking up private IP should return a safe response without making external network calls
    result = provider.lookup_ip("192.168.1.100")
    assert result is not None
    assert result.verdict == "unknown"
    assert result.confidence == 0


# ==========================================
# 2. RBAC & AUTHENTICATION TESTS
# ==========================================

def test_auth_enforce_blocks_unauthorized_requests(monkeypatch, tmp_path):
    engine, Session = create_test_db()
    app.dependency_overrides[get_db] = lambda: Session()
    monkeypatch.setattr("app.main.engine", engine)
    monkeypatch.setattr("app.main.storage", LocalArtifactStorage(str(tmp_path)))

    # Enforce authentication
    monkeypatch.setattr(settings, "AUTH_ENFORCE", True)
    monkeypatch.setattr(settings, "ADMIN_API_KEY", "admin-secret-key-2026")
    monkeypatch.setattr(settings, "ANALYST_API_KEY", "analyst-secret-key-2026")
    monkeypatch.setattr(settings, "VIEWER_API_KEY", "viewer-secret-key-2026")
    monkeypatch.setattr("app.brain.orchestrator.Brain.retrain", lambda: {})

    try:
        with TestClient(app) as client:
            # 1. No key -> 401 Unauthorized
            res = client.get("/api/v1/investigations")
            assert res.status_code == 401

            # 2. Invalid key -> 401 Unauthorized
            res = client.get(
                "/api/v1/investigations",
                headers={"X-API-Key": "wrong-key"}
            )
            assert res.status_code == 401

            # 3. Viewer key can list investigations
            res = client.get(
                "/api/v1/investigations",
                headers={"X-API-Key": "viewer-secret-key-2026"}
            )
            assert res.status_code == 200

            # 4. Viewer key CANNOT upload / create investigation (requires analyst)
            res = client.post(
                "/api/v1/investigations",
                files={"file": ("test.eml", sample_eml_content(), "message/rfc822")},
                headers={"X-API-Key": "viewer-secret-key-2026"}
            )
            assert res.status_code == 403

            # 5. Analyst key CAN upload / create investigation
            res = client.post(
                "/api/v1/investigations",
                files={"file": ("test.eml", sample_eml_content(), "message/rfc822")},
                headers={"X-API-Key": "analyst-secret-key-2026"}
            )
            assert res.status_code == 200
            inv_id = res.json()["id"]

            # 6. Analyst key CANNOT trigger retrain (requires admin)
            res = client.post(
                "/api/v1/brain/retrain",
                headers={"X-API-Key": "analyst-secret-key-2026"}
            )
            assert res.status_code == 403

            # 7. Admin key CAN access retrain
            res = client.post(
                "/api/v1/brain/retrain",
                headers={"Authorization": "Bearer admin-secret-key-2026"}
            )
            assert res.status_code == 200
    finally:
        app.dependency_overrides.clear()


# ==========================================
# 3. REPORT ENDPOINT & CONTENT SECURITY POLICY
# ==========================================

def test_investigation_report_endpoint_and_csp(monkeypatch, tmp_path):
    engine, Session = create_test_db()
    app.dependency_overrides[get_db] = lambda: Session()
    monkeypatch.setattr("app.main.engine", engine)
    monkeypatch.setattr("app.main.storage", LocalArtifactStorage(str(tmp_path)))
    monkeypatch.setattr(settings, "AUTH_ENFORCE", False)

    try:
        with TestClient(app) as client:
            upload_res = client.post(
                "/api/v1/investigations",
                files={"file": ("test.eml", sample_eml_content(), "message/rfc822")},
            )
            assert upload_res.status_code == 200
            inv_id = upload_res.json()["id"]

            # 1. JSON Report
            json_report = client.get(f"/api/v1/investigations/{inv_id}/report?format=json")
            assert json_report.status_code == 200
            data = json_report.json()
            assert data["id"] == inv_id
            assert "verdict" in data
            assert "risk_score" in data
            assert "score_version" in data
            assert data["score_version"] == "2026.10"

            # 2. HTML Report with strict CSP and sandboxing
            html_report = client.get(f"/api/v1/investigations/{inv_id}/report?format=html")
            assert html_report.status_code == 200
            assert "text/html" in html_report.headers["content-type"]
            # Verify Content-Security-Policy headers isolate untrusted email payload
            csp = html_report.headers.get("content-security-policy", "")
            assert "default-src 'none'" in csp
            assert "sandbox" in csp
            assert "SENTINEL Forensic Investigation Report" in html_report.text
    finally:
        app.dependency_overrides.clear()


# ==========================================
# 4. PAGINATION BOUNDS & INPUT CAPPING
# ==========================================

def test_pagination_bounds(monkeypatch, tmp_path):
    engine, Session = create_test_db()
    app.dependency_overrides[get_db] = lambda: Session()
    monkeypatch.setattr("app.main.engine", engine)
    monkeypatch.setattr("app.main.storage", LocalArtifactStorage(str(tmp_path)))
    monkeypatch.setattr(settings, "AUTH_ENFORCE", False)

    try:
        with TestClient(app) as client:
            # Querying with limit > 100 violates Query(le=100) and returns 422 Unprocessable Content
            res = client.get("/api/v1/investigations?limit=500&skip=0")
            assert res.status_code == 422

            # Valid bounded query returns 200
            valid_res = client.get("/api/v1/investigations?limit=100&skip=0")
            assert valid_res.status_code == 200

            # Negative skip should return 422 Unprocessable Entity
            bad_skip = client.get("/api/v1/investigations?skip=-5")
            assert bad_skip.status_code == 422
    finally:
        app.dependency_overrides.clear()


# ==========================================
# 5. ML CLASSIFIER INTEGRITY VERIFICATION
# ==========================================

def test_ml_classifier_hash_verification():
    # Verify current model matches its metadata hash
    if MODEL_PATH.exists() and META_PATH.exists():
        with open(META_PATH) as f:
            meta = json.load(f)
        expected = meta.get("model_sha256")
        assert expected is not None
        actual = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
        assert secrets.compare_digest(actual, expected) is True

    # Verify that a tampered file is detected
    tampered_bytes = b"tampered_malicious_payload"
    tampered_hash = hashlib.sha256(tampered_bytes).hexdigest()
    assert secrets.compare_digest(tampered_hash, expected) is False


# ==========================================
# 6. SENSITIVE LOG SANITIZATION
# ==========================================

def test_log_sanitizer_masks_secrets():
    import logging
    filter_ = SanitizingFilter()

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="User authenticated with api_key=secret_token_123456789 and Bearer abcdef1234567890",
        args=(),
        exc_info=None
    )

    filter_.filter(record)
    assert "secret_token_123456789" not in record.msg
    assert "abcdef1234567890" not in record.msg
    assert "[REDACTED]" in record.msg
