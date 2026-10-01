# Setup & Installation Guide

This document outlines the local setup instructions for **Mobile App Security Analyzer** on Windows and Linux/macOS environments.

---

## Prerequisites

1. **Node.js**: `v18.0.0` or higher (Tested with `v24.18.1`).
2. **npm**: `10.0.0` or higher (Tested with `11.4.2`).
3. **Python**: Python 3.9+ (Tested with `3.14.2`).
4. **MySQL**: MySQL Server 8.0+ (InnoDB engine).

---

## 1. Database Setup (MySQL)

### Starting the MySQL Service on Windows
The MySQL 8.0 Windows service is named `MYSQL80`. Starting Windows services requires Administrator privileges.

1. Open PowerShell **as Administrator** (Right-click Windows Start $\rightarrow$ *Terminal (Admin)* or *PowerShell (Admin)*).
2. Execute:
   ```powershell
   Start-Service -Name MYSQL80
   ```
   Or using standard command prompt:
   ```cmd
   net start MYSQL80
   ```
3. Verify that port 3306 is listening:
   ```powershell
   Test-NetConnection 127.0.0.1 -Port 3306
   ```

### Initializing Database Schema & Seed Data
Using the MySQL CLI client:
```bash
# Execute schema migration (creates database and 10 tables)
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < database/schema.sql

# Execute seed script (creates initial development admin account)
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < database/seed.sql
```

#### Default Development Credentials
> [!WARNING]
> **DEVELOPMENT ONLY — DO NOT USE IN PRODUCTION**
> - **Email**: `<ADMIN_EMAIL>`
> - **Password**: `<ADMIN_PASSWORD>`
> - **Role**: `admin`

---

## 2. Backend API Setup

1. Navigate to `backend/`:
   ```bash
   cd backend
   ```
2. Copy environment file:
   ```bash
   cp .env.example .env
   ```
3. Verify your database password in `.env`:
   ```ini
   DB_HOST=localhost
   DB_PORT=3306
   DB_NAME=mobile_security_analyzer
   DB_USER=root
   DB_PASSWORD=your_mysql_password
   JWT_SECRET=super_secure_random_key_min_32_characters
   ```
4. Install dependencies and start development server:
   ```bash
   npm install
   npm run dev
   ```
5. Confirm API health:
   - System Health: `http://localhost:5000/api/health`
   - Database Status: `http://localhost:5000/api/health/db`

---

## 3. Frontend Setup

1. Navigate to `frontend/`:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser at:
   ```
   http://localhost:5173
   ```

---

## 4. Python Static Analyzer

The static analyzer requires Python 3 standard library and can be run independently:
```bash
cd analyzer
python main.py --help
```
Sample test run:
```bash
python main.py --apk path\to\application.apk --output results.json --scan-id 1
```
