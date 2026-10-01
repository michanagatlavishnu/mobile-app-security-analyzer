# Mobile App Security Analyzer - Architecture Specification

## 1. High-Level Architecture Overview

The platform uses a layered micro-service architecture separating client presentation, API gateway management, relational data persistence, and sandboxed static analysis:

```
[ React 18 + Vite (Tailwind CSS, Recharts) ]
                     |
                     | REST API (JSON / Bearer JWT)
                     v
[ Node.js + Express API Gateway ]
    ├── Authentication & Authorization (bcrypt + JWT)
    ├── Multer File Upload Sandbox (UUID naming, 200MB limit)
    ├── MySQL 8.0 Connection Pool (InnoDB, Parameterized Queries)
    └── ScanExecutionService (child_process.spawn)
                     |
                     | JSON CLI arguments & structured output
                     v
[ Python 3 Static Analysis Engine ]
    ├── Zip-Slip Protected Archive Inspector
    ├── Binary AndroidManifest.xml (AXML) Parser
    ├── Dalvik Executable (.dex) Header Inspector
    ├── Manifest Security Analyzer (debuggable, backup, cleartext, SDK)
    ├── Permission Danger Classifier (Android standard mappings)
    ├── Component Exposure Analyzer (Activities, Services, Providers)
    └── Transparent 0-100 Risk Engine (Deduction model)
```

---

## 2. Scan Execution Pipeline & Lifecycle

When a security scan is requested, the lifecycle transitions through the following stages:

1. **`uploaded` (0%)**: Package file is validated, SHA-256 computed, and metadata persisted.
2. **`queued` (10%)**: Backend verifies authorization and enqueues job.
3. **`extracting` (25%)**: Safe extraction checks integrity and enumerates internal archive streams.
4. **`analyzing` (50%)**: Binary AXML parser extracts manifest tree, permissions, components, and intent-filters.
5. **`persisting` (85%)**: Node backend executes an atomic MySQL transaction committing all findings.
6. **`completed` (100%)**: Final deterministic score (0-100) and risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) are set.

---

## 3. Data Flow & Transaction Guarantees

All findings (`vulnerabilities`, `permissions`, `components`, `network_findings`, `secrets`) are written inside an explicit `START TRANSACTION ... COMMIT` block. If any query fails, `ROLLBACK` is issued to prevent partial or corrupted scan results.
