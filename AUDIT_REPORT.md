# SENTINEL Security Audit Report

**Date:** 2026-10-04
**Auditor:** Buffy (Codebuff Security Audit)
**Repository:** https://github.com/shaaannn7/sentinel
**Scope:** Full codebase security, reliability, and quality audit

---

## Executive Summary

SENTINEL is an evidence-first email threat detection platform with a FastAPI backend, Next.js frontend, ML components, and Docker/Kubernetes deployment. The audit identified **15 security findings** across critical, high, medium, and low severities.

**Overall Assessment:** The project has solid foundational security controls (SSRF protection, HTML sanitization, path traversal protection) but requires immediate fixes for several critical issues before production use.

---

## BASELINE STATUS

| Check | Status | Notes |
|-------|--------|-------|
| Backend tests | Not executed | Missing dependencies (scikit-learn, joblib, numpy) |
| Frontend tests | Not executed | Requires Node.js environment |
| Lint | Not executed | - |
| Typecheck | Not executed | - |
| Build | Not executed | - |
| Docker | Configured | docker-compose.yml present, Dockerfiles present |
| Database migrations | Present | Alembic with initial schema |
| Security checks | Performed | Manual audit completed |

---

## CRITICAL FINDINGS

### C-001: PostgreSQL Trust Authentication

**File:** `docker-compose.yml`
**Line:** 47
**Severity:** CRITICAL
**CWE:** CWE-287 (Improper Authentication)

**Problem:**
```yaml
postgres:
  environment:
    POSTGRES_HOST_AUTH_METHOD: trust
```

The `trust` authentication method allows any user to connect to PostgreSQL without a password. Any entity with network access to the database port can execute arbitrary SQL queries.

**Impact:**
- Complete database compromise
- Access to all investigation data including email content
- Ability to modify or delete investigation records
- Potential lateral movement if database contains credentials

**Recommended Fix:**
```yaml
postgres:
  environment:
    POSTGRES_USER: sentinel
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    POSTGRES_DB: sentinel
    # REMOVE: POSTGRES_HOST_AUTH_METHOD: trust
```

**Status:** ❌ NOT FIXED

---

### C-002: Missing Python Dependencies

**File:** `apps/api/requirements.txt`
**Severity:** CRITICAL
**CWE:** CWE-1312 (Missing Cryptographic Protections) - indirect

**Problem:**
The requirements.txt file is incomplete. The following critical dependencies are used in the codebase but not declared:

- `scikit-learn` - Used in `apps/api/app/brain/ml/classifier.py`
- `joblib` - Used in `apps/api/app/brain/ml/classifier.py`
- `numpy` - Used in `apps/api/app/brain/ml/classifier.py` and `apps/api/app/brain/features.py`

**Impact:**
- Application will fail to start in fresh environments
- Inconsistent dependency resolution
- Potential security vulnerabilities from unpinned transitive dependencies

**Recommended Fix:**
```txt
# Add to requirements.txt
scikit-learn>=1.3.0
joblib>=1.3.0
numpy>=1.24.0
```

**Status:** ❌ NOT FIXED

---

## HIGH FINDINGS

### H-001: Redis Without Authentication

**File:** `docker-compose.yml`
**Lines:** 56-63
**Severity:** HIGH
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Problem:**
```yaml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  # No password configuration
```

Redis is exposed on port 6379 without password authentication. While it's on an internal network, any compromised service in the stack can access Redis without credentials.

**Impact:**
- Unauthorized access to cached data
- Potential data manipulation
- Redis could be used for inter-service communication attacks

**Recommended Fix:**
```yaml
redis:
  image: redis:7-alpine
  command: redis-server --requirepass ${REDIS_PASSWORD}
  ports:
    - "6379:6379"
```

**Status:** ❌ NOT FIXED

---

### H-002: Optional API Key Authentication

**File:** `apps/api/app/core/config.py`
**Line:** 28
**Severity:** HIGH
**CWE:** CWE-306 (Missing Authentication for Critical Function)

**Problem:**
```python
API_AUTH_KEY: str = ""
```

The API authentication key defaults to an empty string, effectively disabling authentication. The `require_api_key` dependency in `apps/api/app/core/auth.py` only enforces authentication when `API_AUTH_KEY` is set.

**Impact:**
- All API endpoints accessible without authentication in default configuration
- Investigation data, email content, and threat intelligence exposed
- No authorization model implemented (IDOR/BOLA vulnerabilities possible)

**Code Location:**
- `apps/api/app/core/auth.py:8-11` - Authentication check only when key is set
- `apps/api/app/api/routes/investigations.py:18` - `dependencies=[Depends(require_api_key)]`

**Recommended Fix:**
1. Make API key mandatory in production:
```python
API_AUTH_KEY: str = ""
# Add validation in settings or startup
```

2. Consider implementing proper user-based authentication for multi-user scenarios

**Status:** ❌ NOT FIXED

---

### H-003: No Rate Limiting

**File:** Entire API
**Severity:** HIGH
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**Problem:**
No rate limiting is implemented on any API endpoint. The following expensive operations have no protection:

- Email upload and analysis (`POST /api/v1/investigations`)
- Analysis reruns (`POST /api/v1/investigations/{id}/analyze`)
- AI enrichment (`POST /api/v1/investigations/{id}/ai-analysis`)
- Threat intelligence enrichment (`POST /api/v1/investigations/{id}/enrich`)
- Model retraining (`POST /api/v1/brain/retrain`)

**Impact:**
- Denial of service through resource exhaustion
- Brute force attacks on investigation endpoints
- Excessive costs from AI/LLM API calls
- Redis/database connection exhaustion

**Recommended Fix:**
Implement Redis-based rate limiting:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/investigations")
@limiter.limit("10/minute")
async def create_investigation(...):
    ...
```

**Status:** ❌ NOT FIXED

---

### H-004: ML Model Loaded Without Integrity Verification

**File:** `apps/api/app/brain/ml/classifier.py`
**Line:** 152
**Severity:** HIGH
**CWE:** CWE-502 (Deserialization of Untrusted Data)

**Problem:**
```python
self._pipe = joblib.load(self._path)
```

The ML model is loaded using `joblib.load()` without any integrity verification. Joblib/pickle can execute arbitrary code during deserialization.

**Impact:**
- If model file is tampered with, arbitrary code execution
- Model poisoning attacks
- Supply chain attack vector

**Current Mitigations:**
- Model file stored in repository (version controlled)
- No user-uploaded model capability

**Recommended Fix:**
```python
import hashlib

EXPECTED_HASH = "sha256:..."  # Store expected hash

def _verify_model_integrity(path: Path) -> bool:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest() == EXPECTED_HASH[7:]  # Remove "sha256:" prefix

def _load_or_train(self) -> None:
    if self._path.exists():
        if not _verify_model_integrity(self._path):
            logger.error("Model integrity check failed")
            # Fall back to training or raise error
        else:
            self._pipe = joblib.load(self._path)
```

**Status:** ❌ NOT FIXED

---

### H-005: No Request ID/Tracing

**File:** Entire API
**Severity:** HIGH (Operational)
**CWE:** CWE-778 (Insufficient Logging)

**Problem:**
No request correlation IDs are generated or logged. Each request is independent with no tracing capability.

**Impact:**
- Difficult to debug issues in production
- No correlation between logs and specific requests
- Hard to trace security incidents
- Audit trail gaps

**Recommended Fix:**
```python
import uuid
from starlette.middleware.base import BaseHTTPMiddleware

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
```

**Status:** ❌ NOT FIXED

---

## MEDIUM FINDINGS

### M-001: Email Parsing Resource Limits Incomplete

**File:** `apps/api/app/api/routes/investigations.py`
**Lines:** 35-46
**Severity:** MEDIUM
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**Problem:**
While upload size is limited, other resource limits are missing:
- No limit on MIME nesting depth
- No limit on number of headers (though capped at 100 in storage)
- No limit on number of attachments
- No limit on body size per MIME part (5MB limit exists in body.py)

**Impact:**
- Resource exhaustion through deeply nested MIME structures
- Memory exhaustion through many small attachments

**Current Mitigations:**
- `MAX_UPLOAD_SIZE` limits total upload
- Body extraction limited to 5MB in `apps/api/app/services/email_parser/body.py:13`

**Recommended Fix:**
Add explicit limits for MIME depth and attachment count:
```python
MAX_MIME_DEPTH = 20
MAX_ATTACHMENTS = 50
MAX_HEADERS = 100
```

**Status:** ⚠️ PARTIALLY MITIGATED

---

### M-002: Error Messages May Leak Information

**File:** Multiple files
**Severity:** MEDIUM
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Problem:**
Some error handlers include exception details in responses:

```python
# investigations.py:67
raise HTTPException(status_code=500, detail=f"Failed to store artifact: {e}")

# investigations.py:73
raise HTTPException(status_code=400, detail=f"Failed to parse email artifact: {e}")
```

**Impact:**
- Internal path disclosure
- Implementation details exposed
- Potential for information gathering attacks

**Recommended Fix:**
```python
# Log detailed error internally
logger.exception("Artifact storage failed")

# Return generic message to client
raise HTTPException(
    status_code=500,
    detail="Unable to process email artifact",
    headers={"X-Request-ID": request.state.request_id}
)
```

**Status:** ❌ NOT FIXED

---

### M-003: Database Connection Pool Not Configured

**File:** `apps/api/app/db/session.py`
**Lines:** 12-17
**Severity:** MEDIUM
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**Problem:**
```python
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
    connect_args=connect_args,
)
```

No explicit pool size, max overflow, or timeout configuration.

**Impact:**
- Connection exhaustion under load
- Potential denial of service
- Unpredictable behavior under high concurrency

**Recommended Fix:**
```python
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
    connect_args=connect_args,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
)
```

**Status:** ❌ NOT FIXED

---

### M-004: Frontend API Client Inconsistency

**Files:**
- `apps/web/src/lib/api.ts`
- `apps/web/src/lib/api/client.ts`
- `apps/web/src/lib/api/types.ts`

**Severity:** MEDIUM
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)

**Problem:**
Multiple API client implementations exist with different interfaces:

1. `apps/web/src/lib/api.ts` - Simple fetch wrappers
2. `apps/web/src/lib/api/client.ts` - Class-based API with normalization
3. `apps/web/src/lib/api/types.ts` - TypeScript types (different from backend schemas)

**Impact:**
- Code duplication
- Inconsistent error handling
- Type mismatches between frontend and backend
- Maintenance burden

**Recommended Fix:**
Consolidate to single API client (recommend `apps/web/src/lib/api/client.ts` as base) and align types with backend schemas.

**Status:** ❌ NOT FIXED

---

### M-005: No Pagination Maximum Limit

**File:** `apps/api/app/api/routes/investigations.py`
**Lines:** 157-169
**Severity:** MEDIUM
**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)

**Problem:**
```python
@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    ...
):
```

No maximum limit enforced on the `limit` parameter. A client could request a very large number of investigations.

**Impact:**
- Memory exhaustion from large result sets
- Database performance degradation
- Slow response times

**Recommended Fix:**
```python
MAX_LIMIT = 100

@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    skip: int = 0,
    limit: int = 50,
    ...
):
    limit = min(limit, MAX_LIMIT)
    ...
```

**Status:** ❌ NOT FIXED

---

## LOW FINDINGS

### L-001: No LICENSE File

**File:** Repository root
**Severity:** LOW
**CWE:** N/A (Legal/Compliance)

**Problem:**
Repository has no LICENSE file. README states: "This repository does not currently include a LICENSE file."

**Impact:**
- Unclear usage rights
- Potential legal issues for adopters
- May hinder open-source adoption

**Recommended Fix:**
Add appropriate license file (e.g., MIT, Apache 2.0, GPL-3.0).

**Status:** ❌ NOT FIXED

---

### L-002: No Security Policy

**File:** Repository root
**Severity:** LOW
**CWE:** N/A (Process)

**Problem:**
No `SECURITY.md` file with vulnerability disclosure policy.

**Impact:**
- No clear process for reporting security issues
- May discourage responsible disclosure
- Security researchers may not know how to report

**Recommended Fix:**
Create `SECURITY.md` with:
- Contact email for security issues
- Response time expectations
- Disclosure policy

**Status:** ❌ NOT FIXED

---

### L-003: CORS May Be Overly Permissive in Production

**File:** `apps/api/app/main.py`
**Lines:** 22-29
**Severity:** LOW
**CWE:** CWE-942 (Permissive Cross-domain Policy)

**Problem:**
CORS origins are configured via environment variable with no validation. If misconfigured, could allow unauthorized origins.

**Current Configuration:**
```python
cors_origins = [
    origin.strip()
    for origin in settings.CORS_ORIGINS.split(",")
    if origin.strip()
]
```

**Impact:**
- If `CORS_ORIGINS=*` is set, allows any origin
- Combined with credentials, could enable CSRF attacks

**Mitigation:**
- `allow_credentials=False` is correctly set
- Development defaults are appropriate

**Status:** ⚠️ ACCEPTABLE WITH CAUTION

---

## POSITIVE SECURITY CONTROLS

The following security controls are correctly implemented:

### ✅ SSRF Protection
**File:** `apps/api/app/services/threat_intel.py:134-147`

The `is_safe_for_external_lookup()` function correctly blocks:
- Private IPv4 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback addresses (127.0.0.0/8, ::1)
- Link-local addresses (169.254.0.0/16)
- Reserved and multicast addresses

### ✅ HTML Sanitization
**File:** `apps/api/app/services/email_parser/body.py:58-107`

The `_SafeHTMLParser` correctly:
- Blocks script, iframe, object, embed, SVG, form tags
- Strips event handlers (on* attributes)
- Validates href protocols (only http, https, mailto allowed)
- Escapes all text content

### ✅ Path Traversal Protection
**File:** `apps/api/app/services/artifact_storage.py:47-53`

The `store()` method correctly:
- Uses `os.path.basename()` to strip directory components
- Sanitizes filenames with regex
- Validates final path with `os.path.commonpath()`
- Uses SHA256-based filenames

### ✅ Upload Size Limits
**File:** `apps/api/app/api/routes/investigations.py:35-46`

Upload size is:
- Checked during streaming (not after full upload)
- Enforced server-side (not just frontend)
- Configurable via MAX_UPLOAD_SIZE

### ✅ Attachment Security
**File:** `apps/api/app/services/analyzers/attachments/analyzer.py`

Attachments are:
- Never executed
- Analyzed only for metadata (size, hash, magic bytes)
- Flagged for suspicious extensions and MIME types

### ✅ AI Prompt Injection Defense
**File:** `apps/api/app/services/ai_investigation.py:37-50`

The `build_prompt()` function:
- Explicitly states email content is untrusted data
- Instructs model not to follow instructions in evidence
- Uses evidence delimiters (EVIDENCE_JSON_BEGIN/END)
- Validates evidence references against supplied IDs

### ✅ Security Headers
**File:** `apps/api/app/main.py:32-37`

The security headers middleware sets:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`

### ✅ CORS Configuration
**File:** `apps/api/app/main.py:22-29`

CORS is:
- Configured with explicit origins (not wildcard)
- Credentials disabled (`allow_credentials=False`)
- Methods and headers restricted

---

## TESTING ASSESSMENT

### Existing Tests
- `apps/api/app/tests/test_phase1.py` - Parser and API tests
- `apps/api/app/tests/test_phase2.py` - Analysis engine tests
- `apps/api/app/tests/test_ai_investigation.py` - AI investigation tests

### Testing Gaps

| Gap | Severity | Description |
|-----|----------|-------------|
| No security regression tests | HIGH | No tests for SSRF, XSS, path traversal, auth bypass |
| No integration tests | MEDIUM | Tests use SQLite in-memory, not production PostgreSQL |
| No E2E tests | MEDIUM | No end-to-end user flow tests |
| No fuzz testing | MEDIUM | Email parser not fuzzed for malformed input |
| Frontend test coverage | LOW | Only one test file (`InvestigationTable.test.tsx`) |
| No performance tests | LOW | No benchmarks for parsing or analysis |

### Missing Security Tests Needed

```
tests/security/
├── test_ssrf_protection.py
├── test_xss_sanitization.py
├── test_path_traversal.py
├── test_auth_required.py
├── test_upload_limits.py
├── test_mime_safety.py
└── test_ai_prompt_injection.py
```

---

## DEPENDENCY AUDIT

### Python Dependencies

**Complete (`requirements.txt`):**
- fastapi==0.135.3 ✅
- uvicorn==0.38.0 ✅
- sqlalchemy==2.0.48 ✅
- psycopg2-binary==2.9.11 ✅
- redis==6.4.0 ✅
- pydantic==2.13.4 ✅
- pydantic-settings==2.14.2 ✅
- python-multipart==0.0.26 ✅
- alembic==1.18.4 ✅
- httpx==0.28.1 ✅
- pytest==8.3.5 ✅
- pytest-asyncio==1.2.0 ✅

**Missing (used in code but not in requirements.txt):**
- scikit-learn ❌ - Used in ML classifier
- joblib ❌ - Used for model persistence
- numpy ❌ - Used for feature vectors

### Node Dependencies

All dependencies appear properly declared in `apps/web/package.json`.

---

## DOCUMENTATION GAPS

| Document | Status | Location |
|----------|--------|----------|
| README.md | ✅ Present | Repository root |
| Architecture docs | ⚠️ Referenced but not reviewed | `docs/architecture/` |
| API docs | ⚠️ Referenced but not reviewed | `docs/api/` |
| Threat model | ⚠️ Referenced but not reviewed | `docs/security/threat-model.md` |
| Deployment docs | ⚠️ Referenced but not reviewed | `docs/deployment/` |
| LICENSE | ❌ Missing | - |
| SECURITY.md | ❌ Missing | - |

---

## INFRASTRUCTURE ASSESSMENT

### Docker Compose

**Issues:**
1. PostgreSQL trust authentication (C-001)
2. Redis without password (H-001)
3. All services expose ports to host (development convenience, but not production-ready)
4. No resource limits configured

**Positive:**
- Health checks configured for all services
- Internal network isolated from host
- Volume persistence configured

### Kubernetes/Helm

**Status:** Not deeply reviewed in this audit. Helm chart present at `infrastructure/k8s/helm-chart/`.

---

## REMAINING RISKS

### Cannot Be Fixed Without Architecture Changes

1. **No user-based authorization model** - Current API key authentication is all-or-nothing. Multi-user scenarios require role-based access control.

2. **No asynchronous processing** - Analysis runs synchronously in HTTP request. Long-running analyses will timeout.

3. **No circuit breakers for external services** - TI/L MM provider failures could impact analysis.

### Acceptable Risks

1. **Model file integrity** - Current deployment model (version-controlled file) mitigates tampering risk
2. **Redis exposure** - Internal Docker network limits exposure in default configuration
3. **CORS configuration** - `allow_credentials=False` mitigates most XSS/CSRF risks

---

## SUMMARY OF REQUIRED ACTIONS

### Immediate (Before Production)

1. ❌ Remove `POSTGRES_HOST_AUTH_METHOD: trust` from docker-compose.yml
2. ❌ Add `POSTGRES_PASSWORD` to docker-compose.yml and .env.example
3. ❌ Add Redis password authentication
4. ❌ Add missing Python dependencies to requirements.txt
5. ❌ Make API authentication mandatory (or clearly document it's optional)

### Short-term (Before Scale)

6. ❌ Implement rate limiting
7. ❌ Add model file integrity verification
8. ❌ Add request ID tracing
9. ❌ Sanitize error messages
10. ❌ Configure database connection pool
11. ❌ Add pagination maximum limits
12. ❌ Add security regression tests

### Medium-term (Improvement)

13. ❌ Consolidate frontend API client
14. ❌ Add LICENSE file
15. ❌ Create SECURITY.md
16. ❌ Add audit logging
17. ❌ Implement email MIME depth limits
18. ❌ Add database indexes for common queries

---

## CONCLUSION

SENTINEL demonstrates good security awareness in several areas:
- SSRF protection is well-implemented
- HTML sanitization blocks dangerous content
- Path traversal is prevented
- Attachments are never executed
- AI prompt injection has defenses

However, several critical gaps must be addressed before production deployment:

1. **Authentication is effectively disabled by default**
2. **PostgreSQL uses trust authentication**
3. **Redis has no password**
4. **No rate limiting exists**
5. **ML model loading has no integrity verification**

With the recommended fixes applied, SENTINEL would be suitable for cautious production use with appropriate monitoring and permission controls.

---

*End of Audit Report*
