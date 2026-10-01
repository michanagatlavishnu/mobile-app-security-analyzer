-- ==============================================================
-- Mobile App Security Analyzer - Production Least-Privilege Grants
-- ==============================================================
-- Instructions:
-- Execute this script as MySQL root or administrative user.
-- Replace 'CHANGE_TO_STRONG_PASSWORD' with your secure production password.
-- ==============================================================

-- Create dedicated application user with restricted database privileges
CREATE USER IF NOT EXISTS 'analyzer_app'@'%' IDENTIFIED BY 'CHANGE_TO_STRONG_PASSWORD';

-- Grant exclusively Data Manipulation Privileges on application tables
GRANT SELECT, INSERT, UPDATE, DELETE ON `mobile_security_analyzer`.* TO 'analyzer_app'@'%';

-- Explicitly withhold DDL, administrative, and filesystem root privileges
REVOKE DROP, ALTER, GRANT OPTION, SUPER, FILE ON *.* FROM 'analyzer_app'@'%';

FLUSH PRIVILEGES;
