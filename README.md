# Mobile App Security Analyzer

[![CI Pipeline](https://github.com/example/mobile-app-security-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/example/mobile-app-security-analyzer/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/example/mobile-app-security-analyzer/releases/tag/v1.0.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Pure Static](https://img.shields.io/badge/Execution-Zero%20Runtime%20Risk-brightgreen.svg)](#security-guarantees)

An enterprise-grade, web-based static application security testing (SAST) platform engineered to audit Android APK archives for security vulnerabilities, dangerous permissions, exposed secrets, insecure network configurations, exported components, and OWASP Mobile Top 10 risks.

---

## 1. Project Overview & Capabilities

Android applications frequently suffer from security anti-patterns:
- Accidental `android:debuggable="true"` in release builds
- Enabled application backups (`android:allowBackup="true"`)
- Unprotected exported Activities, Services, Broadcast Receivers, and ContentProviders
- Cleartext HTTP traffic configurations allowing MITM attacks
- Hardcoded API keys, OAuth secrets, Firebase credentials, and private tokens
- Over-privileged permission requests exposing sensitive user telemetry
- Insecure dynamic code loading, broken cryptography, and source-to-sink data leaks

**Mobile App Security Analyzer** provides automated static decompilation, heuristic security checks, transparent 0-100 risk scoring, interactive SecOps finding management, differential build comparisons, and publication-ready PDF security audits.

---

## 2. High-Level Architecture & Tech Stack

```text
+-----------------------------------------------------------------------------------------+
|                                     WEB FRONTEND                                        |
|                          React 18 + Vite + Tailwind CSS + Recharts                      |
|   - Real-Time SecOps Dashboard              - Scan Comparison / Differential Matrix     |
|   - Ingestion & Archive Upload Pipeline     - Interactive Finding Triage & Audit Trail  |
|   - Application Portfolio View (by package) - User Governance & Access Control (/admin) |
|   - Multi-Format Export (PDF, JSON, CSV)    - Deep Static Telemetry Visualizations      |
+--------------------------------------------+--------------------------------------------+
                                             |
                                             | REST API (JSON / Bearer JWT)
                                             v
+-----------------------------------------------------------------------------------------+
|                                    NODE.JS API GATEWAY                                  |
|                                     Express.js Server                                   |
|   ├── Security Middleware: Helmet, CORS, Global & Export Rate Limiters                  |
|   ├── Auth Layer: JWT verification, RBAC (Admin/User), Tenant Isolation                 |
|   ├── Upload Sandbox: Multer, size restrictions, magic byte validation, SHA-256        |
|   ├── Process Supervisor: 120s timeout, 512KB bounded buffer, non-execution execution   |
|   ├── Services: ScanExecutionService, ReportService (PDFKit, JSON, CSV)                 |
|   └── Controllers: Auth, APK, Scan, Vulnerability Triage, Report, Dashboard, Admin      |
+----------------------+------------------------------------------+-----------------------+
                       |                                          |
                       | Spawns (child_process.spawn)              | Parameterized Queries
                       v                                          v
+--------------------------------------------+   +----------------------------------------+
|        PYTHON STATIC ANALYSIS ENGINE       |   |             MYSQL 8.0 DATABASE         |
|   ├── AXML Binary Manifest Parser          |   |   ├── users (RBAC & status)            |
|   ├── Multi-DEX String Pool Harvester      |   |   ├── apk_files & scans                |
|   ├── X.509 Certificate Parser (DER/PKCS7) |   |   ├── vulnerabilities & finding_history|
|   ├── ContentProvider Security Auditor     |   |   ├── permissions & components         |
|   ├── Native Library (.so ELF) Inspector   |   |   ├── network_findings & secrets       |
|   ├── Shannon Entropy Analyzer             |   |   ├── reports                          |
|   ├── Source-to-Sink API Correlator        |   |   └── audit_logs                       |
|   ├── Masking Engine (Strict Asterisks)    |   |                                        |
|   └── Deterministic Risk Scoring (0-100)   |   |                                        |
+--------------------------------------------+   +----------------------------------------+
```

### Technology Highlights
- **Frontend**: React 18, Vite, Tailwind CSS, Recharts, Framer Motion, Lucide React, Axios, React Router v6.
- **Backend**: Node.js v18+, Express.js, MySQL2 (connection pool), JWT (`jsonwebtoken`), `bcryptjs`, Multer, Helmet, CORS, `express-rate-limit`, `pdfkit`.
- **Analyzer Engine**: Python 3.9+ standard library (`zipfile`, `hashlib`, `struct`, `argparse`, `json`, `math`, `re`, `unicodedata`) + pure static inspection. Zero external reverse-engineering binaries required.
- **Database**: MySQL 8.0 (InnoDB engine, parameterized prepared queries, relational foreign keys, cascade deletes, composite indexes).
- **Containerization**: Multi-stage Dockerfiles (`backend/Dockerfile`, `frontend/Dockerfile`), Nginx reverse proxy, and `docker-compose.yml`.

---

## 3. Core Security Modules & Heuristics

1. **AXML Binary Manifest Parser (`analyzer/utils/axml_parser.py`)**:
   - Parses compiled Android binary XML (`0x00080003`) string pools, resource IDs, and XML tag hierarchies.
   - Extracts package metadata, SDK versions, permissions, and application flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, `requestLegacyExternalStorage`, `testOnly`).

2. **X.509 Certificate & Signing Auditor (`analyzer/analyzers/certificate_analyzer.py`)**:
   - Inspects `META-INF/` signing blocks (`.RSA`, `.DSA`, `.EC`, `CERT.SF`, `MANIFEST.MF`).
   - Extracts X.509 certificates from DER and PKCS#7 structures.
   - Computes SHA-256 and SHA-1 certificate fingerprints, validates validity windows, and flags debug keystores (`CN=Android Debug`, `androiddebugkey`).

3. **ContentProvider Security Auditor (`analyzer/analyzers/provider_analyzer.py`)**:
   - Audits exported ContentProviders for missing `android:permission`, `android:readPermission`, and `android:writePermission`.
   - Inspects `android:grantUriPermissions` configurations to prevent unauthorized data exposure across IPC boundaries.

4. **Multi-DEX Bytecode Harvester (`analyzer/utils/dex_parser.py`)**:
   - Unpacks Dalvik Executable headers (`dex\n035\0`), LEB128 string offsets, and bytecode string pools across all `classes*.dex` files (`classes.dex`, `classes2.dex`, etc.).

5. **Secrets & Entropy Detection Engine (`analyzer/analyzers/secret_analyzer.py`, `entropy_analyzer.py`)**:
   - Matches Google/Firebase API keys, AWS Access Keys, AWS Secret Keys, JWTs, Stripe keys, GitHub tokens, Slack tokens, private keys, and hardcoded credentials.
   - Computes Shannon Information Entropy ($H(X) = -\sum P(x) \log_2 P(x)$) over candidate string tokens to detect high-entropy embedded secrets.
   - **Zero Leakage Guarantee**: All secrets are masked with asterisks (e.g. `AKIA************MPLE`, `sk_l****************2345`) before persistence, reporting, or display.

6. **Native Library (`.so`) ELF Inspector (`analyzer/analyzers/native_analyzer.py`)**:
   - Identifies compiled native shared libraries under `lib/` across ABIs (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`).
   - Inspects 32-bit vs 64-bit architecture distribution and checks for native library security considerations.

7. **Source-to-Sink Data-Flow Heuristics (`analyzer/analyzers/correlation_analyzer.py`)**:
   - Maps sensitive data sources (IMEI, IMSI, GPS location, contacts, SMS, camera, microphone) to network transmission sinks (`HttpURLConnection`, `OkHttpClient`, `Retrofit`, `Socket`, `sendTextMessage`).
   - Detects potential unauthorized data exfiltration paths without runtime execution.

8. **Deterministic 0-100 Risk Scoring Engine (`analyzer/main.py`)**:
   - Calculates transparent, severity-weighted score deductions:
     - `CRITICAL`: -25 points
     - `HIGH`: -15 points
     - `MEDIUM`: -8 points
     - `LOW`: -3 points
     - `INFO`: 0 points
   - Assigns standardized risk tiers: `CRITICAL` (0-39), `HIGH` (40-69), `MEDIUM` (70-84), `LOW` (85-100).

---

## 4. Security Operations & Analyst Platform

- **Finding Lifecycle State Machine**: Triage findings through states: `OPEN` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `IN_PROGRESS` $\rightarrow$ `RESOLVED` / `FALSE_POSITIVE`.
- **Immutable Audit Trail (`finding_history`)**: Tracks state transitions, timestamps, user IDs, and analyst remediation notes.
- **Application Portfolio View**: Organizes scans into application groups by `package_name` with version history, risk progression, and latest score.
- **Administrative Governance (`/admin`)**: Admin dashboard for user status activation/suspension, role promotion, system telemetry, and audit trail inspection.

---

## 5. Quickstart & Local Installation

### Prerequisites
- **Node.js**: v18.0.0+ (v20+ recommended)
- **Python**: Python 3.9+ (Python 3.14 compatible)
- **MySQL**: MySQL Server 8.0+

### Step 1: Database Setup
In MySQL CLI or Workbench:
```sql
CREATE DATABASE mobile_security_analyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```
Import schema and seed data:
```bash
mysql -u root -p mobile_security_analyzer < database/schema.sql
mysql -u root -p mobile_security_analyzer < database/seed.sql
```
*(Optional for production)* Configure least-privilege application user:
```bash
mysql -u root -p < database/user-privileges.sql
```

### Step 2: Backend Configuration & Start
```bash
cd backend
cp .env.example .env
# Edit .env with your MySQL credentials and JWT secret
npm install
npm run dev
```

Development account bootstrapping (Development Only):
- **Admin**: `<ADMIN_EMAIL>` / `<ADMIN_PASSWORD>` (Bootstrap via environment or register first user)
- **Analyst**: Register a new account via the `/register` web portal

### Step 3: Frontend Start
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 6. Docker Deployment

Deploy the complete multi-container stack via Docker Compose:
```bash
docker-compose up --build -d
```
Services spun up:
- `db`: MySQL 8.0 container on port 3306 with health checks
- `backend`: Node.js API with Python 3 runtime on port 5000
- `frontend`: React SPA served via Nginx reverse proxy on port 80

---

## 7. Automated Testing & Verification Suite

### Python Analyzer Unit Tests (16 Tests)
```bash
cd analyzer
python test_analyzer.py
```
*Output: 16/16 tests passing (AXML parser, DEX parser, Secrets detection, Masking guarantee, Network analyzer, Code heuristics, Entropy, Correlation, Native audit, Certificate extraction).*

### Backend & End-to-End Regression Suite (22 Assertions)
With backend running on `localhost:5000`:
```bash
cd backend
npm run test:e2e
```
*Output: 22/22 assertions passing (Health endpoints, DB connection, Admin/Analyst authentication, RBAC access control, APK upload, asynchronous scan execution, finding persistence, masked secrets verification, PDF/JSON/CSV report generation, finding lifecycle status transitions, audit history retrieval, global telemetry).*

### Frontend Production Build
```bash
cd frontend
npm run build
```
*Output: Vite production build successful with 0 errors.*

---

## 8. Implementation Roadmap Summary

| Phase | Scope | Status |
| :--- | :--- | :--- |
| **Phase 1** | Requirements analysis, threat modeling, architecture design | **Completed** |
| **Phase 2** | Project initialization, Express API, React frontend skeleton, Python CLI, MySQL schema | **Completed** |
| **Phase 3** | Database implementation, seed data, JWT authentication & RBAC | **Completed** |
| **Phase 4** | Secure APK upload pipeline, Zip-Slip defense, SHA-256 integrity validation | **Completed** |
| **Phase 5** | Real Android APK static analysis engine, binary AXML parsing, risk scoring | **Completed** |
| **Phase 6** | Deep static analysis, multi-DEX string parsing, secrets detection with masking, network intelligence & code heuristics | **Completed** |
| **Phase 7** | Professional security reporting (PDF/JSON/CSV), scan comparison, finding triage lifecycle & advanced dashboard | **Completed** |
| **Phase 8** | Advanced Android security analysis, X.509 cert extraction, ContentProvider audits, advanced manifest attributes | **Completed** |
| **Phase 9** | Advanced APK intelligence, multi-DEX metrics, native library `.so` inspection, Shannon entropy, source-to-sink correlation | **Completed** |
| **Phase 10** | Security operations platform, finding history, analyst notes, user governance & application portfolio grouping | **Completed** |
| **Phase 11** | Production hardening, 120s process timeouts, 512KB bounded buffers, Docker orchestration, least-privilege DB & CI/CD | **Completed** |
| **Phase 12** | Comprehensive QA, end-to-end regression validation, release documentation & v1.0.0 git release tag | **Completed** |

---

## 9. Security Guarantees & Constraints

- **Pure Static Inspection**: The engine never executes, emulates, or installs untrusted APK binaries.
- **Zero Plaintext Secret Exposure**: All detected credentials (API keys, tokens, passwords) are masked with asterisks across all storage, APIs, exports, and frontend views.
- **Zip-Slip & Path Traversal Immune**: Extractors enforce canonical path normalization inside designated sandbox directories.
- **Subprocess Isolation**: Analysis subprocesses execute with sanitized string argument arrays, strict execution timeouts (120s), and bounded output buffers (512KB).
