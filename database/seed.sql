-- ==============================================================
-- Mobile App Security Analyzer - Local Development & Test Seed Data
-- ==============================================================
-- CAUTION:
-- THIS SCRIPT IS INTENDED EXCLUSIVELY FOR LOCAL DEVELOPMENT AND QA TESTING.
-- DO NOT RUN OR IMPORT THIS FILE IN A PRODUCTION DEPLOYMENT.
-- In production, create administrative users through a secure bootstrap process.
-- ==============================================================

USE `mobile_security_analyzer`;

-- 1. Development Administrator Account (For local testing)
-- Email: admin@example.com
-- Role: admin
INSERT INTO `users` (`id`, `name`, `email`, `password_hash`, `role`, `status`)
VALUES (
  1,
  'Dev Administrator',
  'admin@example.com',
  '$2b$10$dKqU0DuLUILLk.QD2QJ9tOY0ZQP8sSokgFrQcn/RZ9YTKN4msLbDm',
  'admin',
  'active'
)
ON DUPLICATE KEY UPDATE `role` = 'admin', `status` = 'active';

-- 2. Initial System Audit Log Entry
INSERT INTO `audit_logs` (`user_id`, `action`, `ip_address`)
VALUES (
  1,
  'SYSTEM_INITIALIZATION_DEV_SEED',
  '127.0.0.1'
);
