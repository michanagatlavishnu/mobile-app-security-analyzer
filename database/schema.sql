-- ==============================================================
-- Mobile App Security Analyzer - Database Schema
-- Database: mobile_security_analyzer
-- Engine: InnoDB
-- Character Set: utf8mb4 / utf8mb4_unicode_ci
-- ==============================================================

CREATE DATABASE IF NOT EXISTS `mobile_security_analyzer`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE `mobile_security_analyzer`;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(120) NOT NULL,
  `email` VARCHAR(191) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  `status` ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` TIMESTAMP NULL DEFAULT NULL,
  INDEX `idx_users_email` (`email`),
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_status` (`status`),
  INDEX `idx_users_created_at` (`created_at`),
  INDEX `idx_users_last_login` (`last_login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. APK Files Table
CREATE TABLE IF NOT EXISTS `apk_files` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NOT NULL,
  `filename` VARCHAR(255) NOT NULL,
  `original_filename` VARCHAR(255) NOT NULL,
  `package_name` VARCHAR(255) NULL,
  `version_name` VARCHAR(100) NULL,
  `version_code` INT UNSIGNED NULL,
  `file_size` BIGINT UNSIGNED NOT NULL,
  `sha256` CHAR(64) NOT NULL,
  `storage_path` VARCHAR(500) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_apk_user_id` (`user_id`),
  INDEX `idx_apk_sha256` (`sha256`),
  INDEX `idx_apk_package_name` (`package_name`),
  INDEX `idx_apk_created_at` (`created_at`),
  CONSTRAINT `fk_apk_files_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Scans Table
CREATE TABLE IF NOT EXISTS `scans` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NOT NULL,
  `apk_id` INT UNSIGNED NOT NULL,
  `status` ENUM('uploaded', 'queued', 'extracting', 'analyzing', 'completed', 'failed') NOT NULL DEFAULT 'uploaded',
  `progress` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `security_score` INT NULL DEFAULT NULL,
  `risk_level` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NULL DEFAULT NULL,
  `started_at` TIMESTAMP NULL DEFAULT NULL,
  `completed_at` TIMESTAMP NULL DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_scans_user_id` (`user_id`),
  INDEX `idx_scans_apk_id` (`apk_id`),
  INDEX `idx_scans_status` (`status`),
  INDEX `idx_scans_created_at` (`created_at`),
  CONSTRAINT `fk_scans_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_scans_apk`
    FOREIGN KEY (`apk_id`) REFERENCES `apk_files` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Vulnerabilities Table
CREATE TABLE IF NOT EXISTS `vulnerabilities` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL,
  `title` VARCHAR(255) NOT NULL,
  `severity` ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL') NOT NULL,
  `category` VARCHAR(100) NOT NULL,
  `description` TEXT NOT NULL,
  `evidence` TEXT NULL,
  `location` VARCHAR(255) NULL,
  `impact` TEXT NULL,
  `recommendation` TEXT NULL,
  `cwe` VARCHAR(50) NULL,
  `owasp_category` VARCHAR(100) NULL,
  `confidence` ENUM('HIGH', 'MEDIUM', 'LOW') NOT NULL DEFAULT 'HIGH',
  `analyzer` VARCHAR(50) NOT NULL DEFAULT 'static',
  `source` VARCHAR(100) NULL DEFAULT 'dex',
  `status` ENUM('OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'OPEN',
  `analyst_note` TEXT NULL,
  `resolved_at` TIMESTAMP NULL,
  `resolved_by` INT UNSIGNED NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_vuln_scan_id` (`scan_id`),
  INDEX `idx_vuln_severity` (`severity`),
  INDEX `idx_vuln_category` (`category`),
  INDEX `idx_vuln_status` (`status`),
  INDEX `idx_vuln_created_at` (`created_at`),
  CONSTRAINT `fk_vuln_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Permissions Table
CREATE TABLE IF NOT EXISTS `permissions` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL,
  `permission_name` VARCHAR(255) NOT NULL,
  `danger_level` ENUM('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'SAFE',
  `description` TEXT NULL,
  INDEX `idx_perm_scan_id` (`scan_id`),
  INDEX `idx_perm_danger_level` (`danger_level`),
  CONSTRAINT `fk_perm_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Components Table
CREATE TABLE IF NOT EXISTS `components` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL,
  `component_type` ENUM('activity', 'service', 'receiver', 'provider') NOT NULL,
  `component_name` VARCHAR(255) NOT NULL,
  `exported` BOOLEAN NOT NULL DEFAULT FALSE,
  `permission` VARCHAR(255) NULL,
  INDEX `idx_comp_scan_id` (`scan_id`),
  INDEX `idx_comp_type` (`component_type`),
  INDEX `idx_comp_exported` (`exported`),
  CONSTRAINT `fk_comp_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Network Findings Table
CREATE TABLE IF NOT EXISTS `network_findings` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL,
  `type` VARCHAR(100) NOT NULL,
  `severity` ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL') NOT NULL,
  `description` TEXT NOT NULL,
  `evidence` TEXT NULL,
  INDEX `idx_net_scan_id` (`scan_id`),
  INDEX `idx_net_severity` (`severity`),
  CONSTRAINT `fk_net_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Secrets Table
CREATE TABLE IF NOT EXISTS `secrets` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL,
  `secret_type` VARCHAR(100) NOT NULL,
  `location` VARCHAR(255) NULL,
  `masked_value` VARCHAR(255) NOT NULL,
  `severity` ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
  INDEX `idx_sec_scan_id` (`scan_id`),
  INDEX `idx_sec_type` (`secret_type`),
  CONSTRAINT `fk_sec_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Reports Table
CREATE TABLE IF NOT EXISTS `reports` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `scan_id` INT UNSIGNED NOT NULL UNIQUE,
  `file_path` VARCHAR(500) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_rep_scan_id` (`scan_id`),
  CONSTRAINT `fk_rep_scan`
    FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. Audit Logs Table
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT UNSIGNED NULL,
  `action` VARCHAR(100) NOT NULL,
  `entity_type` VARCHAR(50) NULL,
  `entity_id` INT UNSIGNED NULL,
  `details` TEXT NULL,
  `ip_address` VARCHAR(45) NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_user_id` (`user_id`),
  INDEX `idx_audit_action` (`action`),
  INDEX `idx_audit_entity` (`entity_type`, `entity_id`),
  INDEX `idx_audit_created_at` (`created_at`),
  CONSTRAINT `fk_audit_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
    ON DELETE SET NULL
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. Finding History Table (Security Operations & Analyst Auditing)
CREATE TABLE IF NOT EXISTS `finding_history` (
  `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `vulnerability_id` INT UNSIGNED NOT NULL,
  `previous_status` VARCHAR(32) NULL,
  `new_status` VARCHAR(32) NOT NULL,
  `changed_by` INT UNSIGNED NULL,
  `note` TEXT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_history_vuln_id` (`vulnerability_id`),
  INDEX `idx_history_changed_by` (`changed_by`),
  INDEX `idx_history_created_at` (`created_at`),
  CONSTRAINT `fk_history_vuln`
    FOREIGN KEY (`vulnerability_id`) REFERENCES `vulnerabilities` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_history_user`
    FOREIGN KEY (`changed_by`) REFERENCES `users` (`id`)
    ON DELETE SET NULL
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

