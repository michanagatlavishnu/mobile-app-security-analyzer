# Mobile App Security Analyzer - REST API Specification

Base URL: `http://localhost:5000/api`

All protected endpoints require an HTTP header:
```http
Authorization: Bearer <JWT_TOKEN>
```

---

## 1. System Health

### `GET /health`
Returns the status and version of the API gateway.
- **Authentication**: None
- **Response** (`200 OK`):
```json
{
  "success": true,
  "message": "Mobile App Security Analyzer API is running",
  "timestamp": "2026-09-30T15:10:35.464Z",
  "version": "1.0.0"
}
```

### `GET /health/db`
Pings MySQL database pool without exposing sensitive credentials.
- **Authentication**: None
- **Response (Connected)** (`200 OK`):
```json
{
  "success": true,
  "database": "connected"
}
```
- **Response (Disconnected)** (`503 Service Unavailable`):
```json
{
  "success": false,
  "database": "disconnected"
}
```

---

## 2. Authentication

### `POST /auth/register`
Creates a new analyst account and returns an initial session JWT.
- **Authentication**: None
- **Request Body**:
```json
{
  "name": "Jane Analyst",
  "email": "jane@security.org",
  "password": "StrongPassword123!"
}
```
- **Response** (`201 Created`):
```json
{
  "success": true,
  "message": "Registration successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 2,
    "name": "Jane Analyst",
    "email": "jane@security.org",
    "role": "user"
  }
}
```

### `POST /auth/login`
Authenticates user credentials and issues a signed JWT.
- **Authentication**: None
- **Request Body**:
```json
{
  "email": "jane@security.org",
  "password": "StrongPassword123!"
}
```
- **Response** (`200 OK`):
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 2,
    "name": "Jane Analyst",
    "email": "jane@security.org",
    "role": "user"
  }
}
```
- **Error Response** (`401 Unauthorized`):
```json
{
  "success": false,
  "message": "Invalid email or password"
}
```

### `GET /auth/me`
Retrieves currently authenticated user profile from token claims.
- **Authentication**: Required (`Bearer <token>`)
- **Response** (`200 OK`):
```json
{
  "success": true,
  "user": {
    "id": 2,
    "name": "Jane Analyst",
    "email": "jane@security.org",
    "role": "user",
    "createdAt": "2026-09-30T15:20:00.000Z",
    "updatedAt": "2026-09-30T15:20:00.000Z"
  }
}
```

---

## 3. User Governance

### `GET /users/profile`
- **Authentication**: Required
- **Response** (`200 OK`): User object.

### `PUT /users/profile`
- **Authentication**: Required
- **Request Body**:
```json
{
  "name": "Jane Senior Analyst",
  "email": "jane.senior@security.org"
}
```
- **Response** (`200 OK`):
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "user": { ... }
}
```

### `PUT /users/change-password`
- **Authentication**: Required
- **Request Body**:
```json
{
  "currentPassword": "<CURRENT_PASSWORD>",
  "newPassword": "<NEW_STRONG_PASSWORD>"
}
```
- **Response** (`200 OK`):
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

## 4. Administration

### `GET /admin/statistics`
- **Authentication**: Required (`role: "admin"`)
- **Response** (`200 OK`):
```json
{
  "success": true,
  "statistics": {
    "totalUsers": 5,
    "totalScans": 12,
    "totalVulnerabilities": 48,
    "criticalFindings": 6
  },
  "recentActivity": [
    {
      "id": 1,
      "user_name": "Dev Administrator",
      "action": "USER_LOGIN",
      "ip_address": "127.0.0.1",
      "created_at": "2026-09-30T15:25:00.000Z"
    }
  ]
}
```
