# Mobile App Security Analyzer - Technical Architecture Documentation

This document provides a comprehensive architectural and engineering reference for the **Mobile App Security Analyzer** platform, covering the full scope of **Phases 1 through 12**.

---

## 1. System Architecture & Component Interactions

```text
+-----------------------------------------------------------------------------------------+
|                                     USER INTERFACE                                      |
|                       React 18 + Vite + Tailwind CSS + Recharts                         |
|   - Real-Time Operations & Telemetry Dashboard   - Scan Comparison / Differential Matrix|
|   - Ingestion & Archive Upload Pipeline          - Interactive Finding Triage & Notes   |
|   - Application Portfolio View (by package_name) - Administrative Governance (/admin)   |
|   - Multi-Format Export Center (PDF/JSON/CSV)    - Deep Static Telemetry Visualizations |
+--------------------------------------------+--------------------------------------------+
                                             |
                                             | REST API (JSON / Bearer JWT)
                                             v
+-----------------------------------------------------------------------------------------+
|                                   NODE.JS API GATEWAY                                   |
|                                    Express.js Server                                    |
|   ├── Security Middleware: Helmet, CORS, Global & Export Rate Limiters                  |
|   ├── Auth Layer: JWT verification, RBAC, tenant isolation                              |
|   ├── Upload Sandbox: Multer, size restrictions, magic byte validation, SHA-256         |
|   ├── Process Supervisor: child_process.spawn, 120s timeout, 512KB bounded stdout/stderr|
|   ├── Services: ScanExecutionService, ReportService (PDFKit, JSON, CSV)                 |
|   └── Controllers: Auth, APK, Scan, Vulnerability, Report, Dashboard, Admin             |
+----------------------+------------------------------------------+-----------------------+
                       |                                          |
                       | Spawns (child_process.spawn)              | Parameterized Queries
                       v                                          v
+--------------------------------------------+   +----------------------------------------+
|        PYTHON STATIC ANALYSIS ENGINE       |   |             MYSQL 8.0 DATABASE         |
|   ├── AXML Binary Manifest Parser          |   |   ├── users & audit_logs               |
|   ├── Dalvik DEX & Multi-DEX Harvester     |   |   ├── apk_files & scans                |
|   ├── X.509 Certificate Parser (DER/PKCS7) |   |   ├── vulnerabilities & finding_history|
|   ├── ContentProvider Security Auditor     |   |   ├── permissions & components         |
|   ├── Native Library (.so ELF) Inspector   |   |   ├── network_findings & secrets       |
|   ├── Shannon Information Entropy Analyzer |   |   └── reports                          |
|   ├── Source-to-Sink API Correlator        |   |                                        |
|   ├── Secret Pattern & Masking Engine      |   |                                        |
|   ├── Network Intelligence Analyzer        |   |                                        |
|   ├── Code & Bytecode Heuristics Engine    |   |                                        |
|   └── Deterministic Risk Scoring Engine    |   |                                        |
+--------------------------------------------+   +----------------------------------------+
```

---

## 2. Ingestion & Pre-Execution Pipeline (Phases 2 & 4)

1. **Upload Validation**:
   - Multer middleware intercepts `multipart/form-data`.
   - File size enforced strictly at 200 MB maximum.
   - Archive magic bytes verified: `PK\x03\x04` (ZIP format).
   - Filename sanitized using UUID and timestamp prefix (`apk_<timestamp>_<uuid>.apk`).
2. **Cryptographic Fingerprinting**:
   - Node.js streams file through `crypto.createHash('sha256')` to compute SHA-256 fingerprint.
   - Database record created in `apk_files` and associated `scans` table with status `QUEUED`.
3. **Zip-Slip Safe Extraction**:
   - Python `apk_utils.py` uses `zipfile.ZipFile` with strict canonical path checking (`os.path.commonpath`) to prevent directory traversal attacks via malicious archive members.

---

## 3. Static Analysis Architecture (Phases 5, 6, 8 & 9)

### A. Binary AndroidManifest.xml Parsing
- **Module:** `analyzer/utils/axml_parser.py`
- Parses Android Binary XML format (`0x00080003`):
  - String pool extraction with UTF-8/UTF-16 decoding.
  - Resource map resolution.
  - Tag traversal for `<manifest>`, `<application>`, `<activity>`, `<service>`, `<receiver>`, `<provider>`, `<uses-permission>`.
- Evaluates security flags:
  - `android:debuggable`
  - `android:allowBackup`
  - `android:usesCleartextTraffic`
  - `android:networkSecurityConfig`
  - `android:requestLegacyExternalStorage`
  - `android:testOnly`

### B. Dalvik Multi-DEX String Harvester
- **Module:** `analyzer/utils/dex_parser.py`
- Conforms to Dalvik Executable specifications (`dex\n035\0`).
- Iterates over all `classes*.dex` files in the archive.
- Parses string ID tables and decodes LEB128 string offsets.
- Secondary regex-based printable string harvester captures raw ASCII/UTF-8 constants embedded in bytecode arrays.

### C. X.509 Certificate & Signing Auditor (Phase 8)
- **Module:** `analyzer/analyzers/certificate_analyzer.py`
- Extracts PKCS#7 / DER signature files from `META-INF/` (`.RSA`, `.DSA`, `.EC`).
- Parses ASN.1 structure to extract:
  - Subject and Issuer Distinguished Names.
  - Serial number and validity dates (NotBefore, NotAfter).
  - SHA-256 and SHA-1 certificate fingerprints.
- Identifies debug keystores (`CN=Android Debug`, `androiddebugkey`).
- Audits JAR v1 and APK Signature Schemes v2/v3 presence.

### D. ContentProvider Security Auditor (Phase 8)
- **Module:** `analyzer/analyzers/provider_analyzer.py`
- Inspects all declared `<provider>` components in the manifest:
  - Exported status (`android:exported="true"` or implicit via `<intent-filter>`).
  - Read/Write permission enforcement (`android:readPermission`, `android:writePermission`, `android:permission`).
  - URI grant permissions (`android:grantUriPermissions="true"`).
- Flags unprotected ContentProviders vulnerable to unauthorized data exfiltration or injection (CWE-276 / CWE-280, OWASP M1).

### E. Native Shared Library (`.so`) Inspection (Phase 9)
- **Module:** `analyzer/analyzers/native_analyzer.py`
- Scans `lib/` directory for ELF shared objects across architectures (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`).
- Computes ABI distribution metrics:
  - Flags apps shipping only 32-bit binaries lacking full 64-bit ASLR address space protections.
  - Reports native attack surface footprint.

### F. Shannon Information Entropy Engine (Phase 9)
- **Module:** `analyzer/utils/entropy_analyzer.py`
- Calculates Shannon entropy:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Analyzes candidate string tokens (length 20 to 128 characters, character sets: Base64, Hexadecimal, Alphanumeric).
- Tokens with entropy $> 4.5$ bits/character are flagged as suspected embedded cryptographic keys or tokens.
- All detected high-entropy values are masked before output.

### G. Source-to-Sink Data-Flow Correlator (Phase 9)
- **Module:** `analyzer/analyzers/correlation_analyzer.py`
- Driven by `analyzer/utils/security_api_mapping.json`.
- Identifies combinations of:
  - **Sensitive Data Sources**: `getDeviceId`, `getSubscriberId`, `getLastKnownLocation`, `ContactsContract`, `readFromClipboard`, `Camera.open`, `AudioRecord`.
  - **Transmission Sinks**: `HttpURLConnection.connect`, `OkHttpClient.newCall`, `Retrofit.create`, `Socket.connect`, `SmsManager.sendTextMessage`.
- Correlates co-occurring source-sink pairs across the application's bytecode to detect potential data leakage paths.

### H. Secrets Detection & Masking Engine (Phase 6)
- **Module:** `analyzer/analyzers/secret_analyzer.py`
- Pattern-based detection for Google/Firebase keys, AWS Access/Secret keys, JWTs, Stripe keys, GitHub tokens, Slack tokens, private keys, and hardcoded credentials.
- **Strict Masking Guarantee**: Every detected secret is masked using `mask_secret` (retaining at most 4 prefix characters and 4 suffix characters, replacing all middle characters with `*`). Raw secrets never reach the database, logs, reports, or frontend.

### I. Deterministic Risk Scoring Model
- Calculated in `analyzer/main.py`:
  $$\text{Score} = 100 - \sum \text{Finding Deductions}$$
- Bounded between 0 and 100:
  - `CRITICAL`: -25 points
  - `HIGH`: -15 points
  - `MEDIUM`: -8 points
  - `LOW`: -3 points
- Standardized Risk Tiers:
  - 0–39: `CRITICAL`
  - 40–69: `HIGH`
  - 70–84: `MEDIUM`
  - 85–100: `LOW`

---

## 4. Security Operations & Analyst Platform (Phase 10)

### Finding Lifecycle State Machine
Findings progress through an auditable state machine:
- `OPEN`: Newly discovered finding from static analysis.
- `ACKNOWLEDGED`: Triaged and verified by an analyst.
- `IN_PROGRESS`: Engineering team actively remediating.
- `RESOLVED`: Validated fix applied in source code.
- `FALSE_POSITIVE`: Reviewed and deemed non-actionable or intentional.

### Immutable Audit Trail (`finding_history`)
Every state change records:
- `vulnerability_id`: Foreign key to `vulnerabilities.id`.
- `user_id`: Acting analyst.
- `old_status` and `new_status`.
- `note`: Free-text justification.
- `created_at`: Immutable timestamp.

### Application Portfolio Management
- Scans are dynamically grouped by `package_name`.
- Displays total versions scanned, latest score, risk tier, and score trajectory over time.

### Administrative Governance (`/admin`)
- Accessible only by users with `role = 'admin'`.
- Endpoints: `GET /api/admin/users`, `PUT /api/admin/users/:id/status`, `PUT /api/admin/users/:id/role`, `GET /api/admin/metrics`, `GET /api/admin/audit-logs`.
- Prevents administrative self-demotion or self-suspension.

---

## 5. Production Hardening & DevOps Architecture (Phase 11)

### Execution Sandboxing & Resource Limits
- In `backend/services/scanExecutionService.js`:
  - Python processes spawn with isolated arguments (no shell interpretation).
  - Strict execution timeout: 120,000 ms (2 minutes). Processes exceeding the limit are terminated via `SIGTERM`/`SIGKILL`.
  - Bounded stdout/stderr buffer: Maximum 512 KB stored to prevent memory exhaustion from verbose output.
  - Safe failure handling: Marks scan as `FAILED` in database upon timeout or non-zero exit code.

### Database Least-Privilege Hardening (`database/user-privileges.sql`)
- Application database user `analyzer_app`:
  - Granted `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `mobile_security_analyzer.*`.
  - Prohibited from `DROP`, `ALTER`, `GRANT`, `SUPER`, `FILE`, `SHUTDOWN`.

### Container Architecture (`docker-compose.yml`)
- Multi-container topology:
  - `db`: Official `mysql:8.0` container with volume persistence and healthcheck.
  - `backend`: Node.js 20 with Python 3 runtime, non-root user execution, and healthcheck.
  - `frontend`: Multi-stage build producing static assets served by `nginx:alpine` on port 80.

### Continuous Integration (`.github/workflows/ci.yml`)
- Automated GitHub Actions pipeline:
  - Installs backend dependencies and runs backend checks.
  - Installs frontend dependencies and runs Vite production build.
  - Runs Python unit test suite (`test_analyzer.py`).

---

## 6. End-to-End Verification Matrix (Phase 12)

| Layer | Test Suite | Scope | Result |
| :--- | :--- | :--- | :--- |
| **Analyzer Core** | `analyzer/test_analyzer.py` | 16 unit tests covering all static analyzers, parsers, and heuristics | **16/16 Passed** |
| **Backend & Integration** | `backend/test_e2e_regression.js` | 22 assertions: Auth, RBAC, Upload, Scan execution, Findings, Masking, Reports, Finding lifecycle, Admin telemetry | **22/22 Passed** |
| **Frontend Production** | `npm run build` in `frontend/` | 2305 modules transformed, production bundling | **Build Succeeded** |
