# Security Architecture & Hardening Guide

This document details the security principles and controls implemented in **Mobile App Security Analyzer**.

---

## 1. Authentication & Session Security

- **Bcrypt Password Hashing**: All user passwords are salted and hashed using `bcryptjs` with 10 salt rounds before persistence. Plaintext passwords are never stored or logged.
- **JWT Claims**: Tokens carry minimal non-sensitive data (`userId` and `role`). Passwords, hashes, and internal server secrets are excluded from token payloads.
- **Constant-Time Verification**: Password checking uses bcrypt constant-time comparisons to mitigate timing attacks.
- **Account Enumeration Defense**: The login endpoint returns identical error responses (`"Invalid email or password"`) regardless of whether the email exists.

---

## 2. API & Network Protection

- **Helmet**: Secures HTTP response headers against clickjacking, MIME-sniffing, and XSS.
- **Strict CORS**: Cross-origin resource sharing is restricted to allowed origins (`http://localhost:5173`).
- **Rate Limiting**: Enforces a global IP sliding window limiter (300 requests per 15 minutes) to protect against brute-force and credential stuffing attacks.
- **No Stack Traces in Production**: Error handling middleware suppresses internal stack traces in production environments.

---

## 3. Database Security

- **Parameterized Queries**: Every SQL query across all models utilizes `mysql2/promise` parameterized statements (`?` placeholders). String interpolation and user-controlled query construction are strictly forbidden.
- **Relational Integrity**: Foreign keys enforce cascading updates and deletes to prevent orphan records.
- **Audit Logging**: Authentication events and credential updates are immutably logged to the `audit_logs` table.

---

## 4. File Upload & Sandbox Protection

- **Extension & MIME Validation**: Only `.apk` files are accepted.
- **Randomized Storage Names**: Uploaded files receive cryptographically random hexadecimal names to eliminate path traversal and collisions.
- **Non-Executable Sandbox**: Uploads are stored in an isolated directory (`backend/uploads/`) located completely outside the public web root. Uploaded APKs are never executed.
- **Zip-Slip Protection**: Analyzer archive routines explicitly reject entries containing `..` or absolute paths.
