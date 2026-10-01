const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const User = require('../models/User');
const Scan = require('../models/Scan');
const ApkFile = require('../models/ApkFile');
const Vulnerability = require('../models/Vulnerability');
const AuditLog = require('../models/AuditLog');
const { query } = require('../config/db');
const logger = require('../utils/logger');

class AdminController {
  /**
   * Phase 3: Comprehensive Admin Overview Dashboard Metrics
   * GET /api/admin/dashboard
   */
  static async getDashboardOverview(req, res, next) {
    try {
      // 1. 14 Required Metric Cards
      const [userStats] = await query(`
        SELECT
          COUNT(*) AS total_users,
          COUNT(CASE WHEN status = 'active' THEN 1 END) AS active_users,
          COUNT(CASE WHEN status = 'disabled' THEN 1 END) AS disabled_users,
          COUNT(CASE WHEN role = 'admin' THEN 1 END) AS admin_users,
          COUNT(CASE WHEN role = 'user' THEN 1 END) AS analyst_users
        FROM users
      `);

      const [apkStats] = await query(`
        SELECT
          COUNT(*) AS total_apks,
          COALESCE(SUM(file_size), 0) AS total_bytes
        FROM apk_files
      `);

      const [scanStats] = await query(`
        SELECT
          COUNT(*) AS total_scans,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) AS completed_scans,
          COUNT(CASE WHEN status = 'failed' THEN 1 END) AS failed_scans,
          COUNT(CASE WHEN status IN ('extracting', 'analyzing', 'queued', 'uploaded') THEN 1 END) AS active_scans
        FROM scans
      `);

      const [vulnStats] = await query(`
        SELECT
          COUNT(*) AS total_vulns,
          COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) AS critical,
          COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) AS high,
          COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) AS medium,
          COUNT(CASE WHEN severity = 'LOW' THEN 1 END) AS low,
          COUNT(CASE WHEN severity = 'INFORMATIONAL' THEN 1 END) AS informational,
          COUNT(CASE WHEN status = 'RESOLVED' THEN 1 END) AS resolved,
          COUNT(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 END) AS false_positive
        FROM vulnerabilities
      `);

      // 2. Registration Statistics
      const [regStats] = await query(`
        SELECT
          COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) AS today,
          COUNT(CASE WHEN YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1) THEN 1 END) AS this_week,
          COUNT(CASE WHEN created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN 1 END) AS this_month,
          COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 END) AS last_30_days
        FROM users
      `);

      // 3. Platform Usage Statistics
      const [usersWithApks] = await query(`SELECT COUNT(DISTINCT user_id) AS count FROM apk_files`);
      const [usersWithScans] = await query(`SELECT COUNT(DISTINCT user_id) AS count FROM scans WHERE status = 'completed'`);
      const [scanTimeStats] = await query(`
        SELECT
          COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) AS scans_today,
          COUNT(CASE WHEN YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1) THEN 1 END) AS scans_this_week,
          COUNT(CASE WHEN created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN 1 END) AS scans_this_month
        FROM scans
      `);

      // 4. Latest Platform Activity
      const [latestUsers] = await query(`
        SELECT id, name, email, role, status, created_at, last_login
        FROM users
        ORDER BY created_at DESC
        LIMIT 5
      `);

      const [latestScans] = await query(`
        SELECT
          s.id, s.security_score, s.risk_level, s.status, s.created_at,
          a.original_filename, a.package_name,
          u.name AS user_name, u.email AS user_email
        FROM scans s
        JOIN apk_files a ON s.apk_id = a.id
        JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 5
      `);

      const [latestAudits] = await query(`
        SELECT
          a.id, a.action, a.entity_type, a.entity_id, a.details, a.ip_address, a.created_at,
          u.name AS user_name, u.email AS user_email
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 5
      `);

      const u = userStats[0] || {};
      const a = apkStats[0] || {};
      const s = scanStats[0] || {};
      const v = vulnStats[0] || {};
      const r = regStats[0] || {};
      const st = scanTimeStats[0] || {};

      return res.json({
        success: true,
        cards: {
          totalUsers: Number(u.total_users || 0),
          activeUsers: Number(u.active_users || 0),
          disabledUsers: Number(u.disabled_users || 0),
          adminUsers: Number(u.admin_users || 0),
          analystUsers: Number(u.analyst_users || 0),
          totalApks: Number(a.total_apks || 0),
          totalScans: Number(s.total_scans || 0),
          completedScans: Number(s.completed_scans || 0),
          failedScans: Number(s.failed_scans || 0),
          activeScans: Number(s.active_scans || 0),
          totalVulnerabilities: Number(v.total_vulns || 0),
          criticalFindings: Number(v.critical || 0),
          highFindings: Number(v.high || 0),
          mediumFindings: Number(v.medium || 0),
          lowFindings: Number(v.low || 0),
          informationalFindings: Number(v.informational || 0),
          resolvedFindings: Number(v.resolved || 0),
          falsePositiveFindings: Number(v.false_positive || 0),
          storageBytes: Number(a.total_bytes || 0),
          storageMb: Math.round(Number(a.total_bytes || 0) / (1024 * 1024) * 10) / 10,
        },
        registrationStats: {
          today: Number(r.today || 0),
          thisWeek: Number(r.this_week || 0),
          thisMonth: Number(r.this_month || 0),
          last30Days: Number(r.last_30_days || 0),
        },
        usageStats: {
          usersWithApkUploads: Number(usersWithApks[0]?.count || 0),
          usersWithCompletedScans: Number(usersWithScans[0]?.count || 0),
          scansToday: Number(st.scans_today || 0),
          scansThisWeek: Number(st.scans_this_week || 0),
          scansThisMonth: Number(st.scans_this_month || 0),
        },
        platformActivity: {
          latestRegistrations: latestUsers,
          latestScans: latestScans,
          latestAuditEvents: latestAudits,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Legacy System Metrics (Maintains backward compatibility with test suites)
   * GET /api/admin/metrics
   */
  static async getSystemMetrics(req, res, next) {
    try {
      const [userCount] = await query('SELECT COUNT(*) AS total FROM users');
      const [apkStats] = await query('SELECT COUNT(*) AS total, COALESCE(SUM(file_size), 0) AS total_bytes FROM apk_files');
      const [scanStats] = await query(`
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
          SUM(CASE WHEN status = 'analyzing' OR status = 'extracting' THEN 1 ELSE 0 END) AS active,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM scans
      `);
      const [vulnStats] = await query(`
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low,
          SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved,
          SUM(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS false_positive
        FROM vulnerabilities
      `);

      return res.json({
        success: true,
        data: {
          users: {
            total: userCount[0].total,
          },
          apks: {
            total: apkStats[0].total,
            totalBytes: Number(apkStats[0].total_bytes),
            totalMb: Math.round(Number(apkStats[0].total_bytes) / (1024 * 1024) * 10) / 10,
          },
          scans: {
            total: scanStats[0].total,
            completed: Number(scanStats[0].completed || 0),
            active: Number(scanStats[0].active || 0),
            failed: Number(scanStats[0].failed || 0),
          },
          vulnerabilities: {
            total: vulnStats[0].total,
            critical: Number(vulnStats[0].critical || 0),
            high: Number(vulnStats[0].high || 0),
            medium: Number(vulnStats[0].medium || 0),
            low: Number(vulnStats[0].low || 0),
            resolved: Number(vulnStats[0].resolved || 0),
            falsePositive: Number(vulnStats[0].false_positive || 0),
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 4: Paginated, searchable, filterable User Management
   * GET /api/admin/users
   */
  static async getUsers(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        search = '',
        filter = 'all',
        sortBy = 'created_at',
        sortOrder = 'DESC',
      } = req.query;

      const result = await User.findUsersPaginated({
        page,
        limit,
        search,
        filter,
        sortBy,
        sortOrder,
      });

      return res.json({
        success: true,
        data: result.users,
        pagination: result.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 5: User Details with Usage, Scans, and Activity
   * GET /api/admin/users/:id
   */
  static async getUserDetails(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      if (isNaN(targetUserId)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID' });
      }

      const details = await User.getUserDetails(targetUserId);
      if (!details) {
        return res.status(404).json({ success: false, message: 'User account not found' });
      }

      return res.json({
        success: true,
        data: details,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 6: Update User Role (with self-demotion and last-admin protections)
   * PATCH or PUT /api/admin/users/:id/role
   */
  static async updateUserRole(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      let { role } = req.body;
      const currentAdminId = req.user.id;

      if (!role) {
        return res.status(400).json({ success: false, error: 'Role is required' });
      }

      // Map 'analyst' to 'user' for database consistency
      if (role === 'analyst') {
        role = 'user';
      }

      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({
          success: false,
          error: 'Role must be either "user", "analyst", or "admin"',
        });
      }

      // 1. Prevent Self-Demotion
      if (targetUserId === currentAdminId && role !== 'admin') {
        return res.status(400).json({
          success: false,
          error: 'Administrators cannot demote their own account. Self-demotion is strictly prohibited.',
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          error: 'Target user not found',
        });
      }

      // 2. Prevent Demoting the Final Active Administrator
      if (targetUser.role === 'admin' && role !== 'admin' && targetUser.status === 'active') {
        const activeAdmins = await User.countActiveAdmins();
        if (activeAdmins <= 1) {
          return res.status(400).json({
            success: false,
            error: 'Cannot demote the final active administrator account on the platform.',
          });
        }
      }

      await User.updateRole(targetUserId, role);

      await AuditLog.log({
        userId: currentAdminId,
        action: 'ROLE_CHANGED',
        entityType: 'user',
        entityId: targetUserId,
        details: `Updated role for ${targetUser.email} from ${targetUser.role} to ${role}`,
        ipAddress: req.ip,
      });

      logger.info(`Admin #${currentAdminId} updated User #${targetUserId} role to ${role}`);

      return res.json({
        success: true,
        message: `User role successfully updated to ${role === 'user' ? 'analyst' : 'admin'}`,
        data: { id: targetUserId, role },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 6: Update User Status (with self-disable and last-admin protections)
   * PATCH or PUT /api/admin/users/:id/status
   */
  static async updateUserStatus(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      const { status } = req.body;
      const currentAdminId = req.user.id;

      if (!status || !['active', 'disabled'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Status must be either "active" or "disabled"',
        });
      }

      // 1. Prevent Self-Disabling
      if (targetUserId === currentAdminId && status === 'disabled') {
        return res.status(400).json({
          success: false,
          error: 'Administrators cannot disable their own account.',
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          error: 'Target user not found',
        });
      }

      // 2. Prevent Disabling the Final Active Administrator
      if (targetUser.role === 'admin' && status === 'disabled') {
        const activeAdmins = await User.countActiveAdmins();
        if (activeAdmins <= 1) {
          return res.status(400).json({
            success: false,
            error: 'Cannot disable the final active administrator account on the platform.',
          });
        }
      }

      await User.updateStatus(targetUserId, status);

      const auditAction = status === 'disabled' ? 'USER_DISABLED' : 'USER_ENABLED';

      await AuditLog.log({
        userId: currentAdminId,
        action: auditAction,
        entityType: 'user',
        entityId: targetUserId,
        details: `Updated account status for ${targetUser.email} to ${status}`,
        ipAddress: req.ip,
      });

      logger.info(`Admin #${currentAdminId} updated User #${targetUserId} status to ${status}`);

      return res.json({
        success: true,
        message: `User status successfully updated to ${status}`,
        data: { id: targetUserId, status },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 5: Specific User Activity Audit Trail
   * GET /api/admin/users/:id/activity
   */
  static async getUserActivity(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      const page = parseInt(req.query.page, 10) || 1;
      const limit = parseInt(req.query.limit, 10) || 25;

      const result = await AuditLog.getFilteredLogs({
        page,
        limit,
        user: String(targetUserId),
      });

      return res.json({
        success: true,
        data: result.logs,
        pagination: result.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 7: System-Wide Audit Logs with Search & Date Filters
   * GET /api/admin/audit-logs
   */
  static async getAuditLogs(req, res, next) {
    try {
      const {
        page = 1,
        limit = 50,
        user = '',
        action = '',
        entityType = '',
        startDate = '',
        endDate = '',
      } = req.query;

      const result = await AuditLog.getFilteredLogs({
        page,
        limit,
        user,
        action,
        entityType,
        startDate,
        endDate,
      });

      return res.json({
        success: true,
        data: {
          logs: result.logs,
          pagination: result.pagination,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 8: Registration Analytics (Daily 30d, Weekly 12w, Monthly 12m)
   * GET /api/admin/analytics/registrations
   */
  static async getRegistrationAnalytics(req, res, next) {
    try {
      // 1. Daily registrations for the last 30 days
      const [dailyRows] = await query(`
        SELECT
          DATE_FORMAT(d.date_val, '%Y-%m-%d') AS date,
          COUNT(u.id) AS count
        FROM (
          SELECT CURDATE() - INTERVAL (a.a + (10 * b.a)) DAY AS date_val
          FROM (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) AS a
          CROSS JOIN (SELECT 0 AS a UNION ALL SELECT 1 UNION ALL SELECT 2) AS b
          WHERE (a.a + (10 * b.a)) < 30
        ) d
        LEFT JOIN users u ON DATE(u.created_at) = d.date_val
        GROUP BY d.date_val
        ORDER BY d.date_val ASC
      `);

      // 2. Weekly registrations for the last 12 weeks
      const [weeklyRows] = await query(`
        SELECT
          CONCAT('W', LPAD(w.yw % 100, 2, '0')) AS week,
          DATE_FORMAT(w.min_date, '%b %d') AS week_start,
          w.user_count AS count
        FROM (
          SELECT
            YEARWEEK(created_at, 1) AS yw,
            MIN(DATE(created_at)) AS min_date,
            COUNT(*) AS user_count
          FROM users
          WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 WEEK)
          GROUP BY YEARWEEK(created_at, 1)
        ) w
        ORDER BY w.yw ASC
      `);

      // 3. Monthly registrations for the last 12 months
      const [monthlyRows] = await query(`
        SELECT
          m.month_key,
          DATE_FORMAT(m.min_date, '%b %Y') AS month,
          m.user_count AS count
        FROM (
          SELECT
            DATE_FORMAT(created_at, '%Y-%m') AS month_key,
            MIN(created_at) AS min_date,
            COUNT(*) AS user_count
          FROM users
          WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
          GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ) m
        ORDER BY m.month_key ASC
      `);

      // 4. Registration summary metrics
      const [summaryRows] = await query(`
        SELECT
          COUNT(*) AS total_registrations,
          COUNT(CASE WHEN status = 'active' THEN 1 END) AS active_users,
          COUNT(CASE WHEN status = 'disabled' THEN 1 END) AS disabled_users,
          COUNT(CASE WHEN created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN 1 END) AS new_this_month
        FROM users
      `);

      const s = summaryRows[0] || {};

      return res.json({
        success: true,
        summary: {
          totalRegistrations: Number(s.total_registrations || 0),
          activeUsers: Number(s.active_users || 0),
          disabledUsers: Number(s.disabled_users || 0),
          newUsersThisMonth: Number(s.new_this_month || 0),
        },
        daily: dailyRows.map((r) => ({ date: r.date, count: Number(r.count || 0) })),
        weekly: weeklyRows.map((r) => ({ week: r.week, label: r.week_start, count: Number(r.count || 0) })),
        monthly: monthlyRows.map((r) => ({ month: r.month, count: Number(r.count || 0) })),
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 9: User Activity Analytics (Active periods & Top platform users)
   * GET /api/admin/analytics/activity
   */
  static async getActivityAnalytics(req, res, next) {
    try {
      // 1. Active user counts based on verified database activity (logins, audit events, scans)
      const [activeToday] = await query(`
        SELECT COUNT(DISTINCT u.id) AS count
        FROM users u
        WHERE DATE(u.last_login) = CURDATE()
           OR u.id IN (SELECT user_id FROM audit_logs WHERE DATE(created_at) = CURDATE() AND user_id IS NOT NULL)
           OR u.id IN (SELECT user_id FROM scans WHERE DATE(created_at) = CURDATE())
      `);

      const [activeWeek] = await query(`
        SELECT COUNT(DISTINCT u.id) AS count
        FROM users u
        WHERE YEARWEEK(u.last_login, 1) = YEARWEEK(CURDATE(), 1)
           OR u.id IN (SELECT user_id FROM audit_logs WHERE YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1) AND user_id IS NOT NULL)
           OR u.id IN (SELECT user_id FROM scans WHERE YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1))
      `);

      const [activeMonth] = await query(`
        SELECT COUNT(DISTINCT u.id) AS count
        FROM users u
        WHERE u.last_login >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
           OR u.id IN (SELECT user_id FROM audit_logs WHERE created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01') AND user_id IS NOT NULL)
           OR u.id IN (SELECT user_id FROM scans WHERE created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01'))
      `);

      const [neverUsed] = await query(`
        SELECT COUNT(*) AS count
        FROM users u
        WHERE NOT EXISTS (SELECT 1 FROM apk_files a WHERE a.user_id = u.id)
          AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.user_id = u.id)
      `);

      // 2. Top users by completed scans
      const [topScanners] = await query(`
        SELECT
          u.id, u.name, u.email, u.role,
          COUNT(s.id) AS total_scans,
          ROUND(AVG(CASE WHEN s.status = 'completed' THEN s.security_score END), 1) AS avg_score
        FROM users u
        JOIN scans s ON u.id = s.user_id
        GROUP BY u.id, u.name, u.email, u.role
        ORDER BY total_scans DESC
        LIMIT 5
      `);

      // 3. Top users by APK uploads
      const [topUploaders] = await query(`
        SELECT
          u.id, u.name, u.email, u.role,
          COUNT(a.id) AS total_uploads,
          SUM(a.file_size) AS total_bytes
        FROM users u
        JOIN apk_files a ON u.id = a.user_id
        GROUP BY u.id, u.name, u.email, u.role
        ORDER BY total_uploads DESC
        LIMIT 5
      `);

      return res.json({
        success: true,
        activity: {
          activeToday: Number(activeToday[0]?.count || 0),
          activeThisWeek: Number(activeWeek[0]?.count || 0),
          activeThisMonth: Number(activeMonth[0]?.count || 0),
          neverUsedAnalyzer: Number(neverUsed[0]?.count || 0),
        },
        topUsers: {
          byScans: topScanners.map((u) => ({
            id: u.id,
            name: u.name,
            email: u.email,
            role: u.role,
            totalScans: Number(u.total_scans || 0),
            avgScore: u.avg_score !== null ? Number(u.avg_score) : null,
          })),
          byUploads: topUploaders.map((u) => ({
            id: u.id,
            name: u.name,
            email: u.email,
            role: u.role,
            totalUploads: Number(u.total_uploads || 0),
            totalMb: Math.round(Number(u.total_bytes || 0) / (1024 * 1024) * 10) / 10,
          })),
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 10: Grouped Applications across the platform
   * GET /api/admin/applications
   */
  static async getApplications(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        search = '',
        sortBy = 'latest_uploaded',
        sortOrder = 'DESC',
      } = req.query;

      const result = await ApkFile.getGroupedApplications({
        page,
        limit,
        search,
        sortBy,
        sortOrder,
      });

      return res.json({
        success: true,
        data: result.applications,
        pagination: result.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 10: Specific Application Drill-down (Versions & Scans)
   * GET /api/admin/applications/:packageName
   */
  static async getApplicationDetails(req, res, next) {
    try {
      const packageName = decodeURIComponent(req.params.packageName);
      const details = await ApkFile.getApplicationDetails(packageName);

      if (!details) {
        return res.status(404).json({
          success: false,
          message: 'Application not found',
        });
      }

      return res.json({
        success: true,
        data: details,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 11: Platform-Wide Scan Management
   * GET /api/admin/scans
   */
  static async getScans(req, res, next) {
    try {
      const {
        page = 1,
        limit = 20,
        status = '',
        riskLevel = '',
        user = '',
        application = '',
        search = '',
        startDate = '',
        endDate = '',
        sortBy = 'created_at',
        sortOrder = 'DESC',
      } = req.query;

      const result = await Scan.getAdminScansPaginated({
        page,
        limit,
        status,
        riskLevel,
        user,
        application,
        search,
        startDate,
        endDate,
        sortBy,
        sortOrder,
      });

      return res.json({
        success: true,
        data: result.scans,
        pagination: result.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 12: Aggregate Security Findings Overview & Paginated List
   * GET /api/admin/findings
   */
  static async getFindings(req, res, next) {
    try {
      const {
        page = 1,
        limit = 25,
        severity = '',
        status = '',
        category = '',
        search = '',
        sortBy = 'created_at',
        sortOrder = 'DESC',
      } = req.query;

      const [overview, paginatedFindings] = await Promise.all([
        Vulnerability.getAdminFindingsOverview(),
        Vulnerability.getAdminFindingsPaginated({
          page,
          limit,
          severity,
          status,
          category,
          search,
          sortBy,
          sortOrder,
        }),
      ]);

      return res.json({
        success: true,
        overview,
        findings: paginatedFindings.findings,
        pagination: paginatedFindings.pagination,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Phase 13: Real System Health & Telemetry
   * GET /api/admin/system-health
   */
  static async getSystemHealth(req, res, next) {
    try {
      const startTime = Date.now();
      // 1. Test database connection & latency
      await query('SELECT 1');
      const dbLatencyMs = Date.now() - startTime;

      // 2. Python Analyzer Operability Verification
      let pythonVersion = 'Unknown';
      let analyzerOperable = false;
      try {
        const pythonOut = execSync('python --version', { encoding: 'utf8' }).trim();
        pythonVersion = pythonOut;
        const analyzerScript = path.resolve(__dirname, '../../analyzer/main.py');
        analyzerOperable = fs.existsSync(analyzerScript);
      } catch {
        pythonVersion = 'Not detected in PATH';
      }

      // 3. Scan & Performance Telemetry
      const [scanPerf] = await query(`
        SELECT
          COUNT(*) AS total_scans,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) AS completed_scans,
          COUNT(CASE WHEN status = 'failed' THEN 1 END) AS failed_scans,
          ROUND(AVG(CASE WHEN status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
                         THEN TIMESTAMPDIFF(SECOND, started_at, completed_at) END), 1) AS avg_duration_sec
        FROM scans
      `);

      // 4. Storage Usage
      const [storageStats] = await query(`
        SELECT
          COUNT(*) AS total_apks,
          COALESCE(SUM(file_size), 0) AS total_bytes
        FROM apk_files
      `);

      const p = scanPerf[0] || {};
      const st = storageStats[0] || {};
      const mem = process.memoryUsage();

      return res.json({
        success: true,
        health: {
          apiStatus: 'online',
          databaseStatus: 'connected',
          databaseLatencyMs: dbLatencyMs,
          analyzerStatus: analyzerOperable ? 'ready' : 'degraded',
          analyzerPathValid: analyzerOperable,
          nodeVersion: process.version,
          pythonVersion,
          environment: process.env.NODE_ENV || 'development',
          appVersion: '1.0.0',
          dockerRuntimeStatus: 'Not verified on this host',
          uptimeSeconds: Math.floor(process.uptime()),
          memory: {
            rssMb: Math.round(mem.rss / (1024 * 1024) * 10) / 10,
            heapUsedMb: Math.round(mem.heapUsed / (1024 * 1024) * 10) / 10,
            heapTotalMb: Math.round(mem.heapTotal / (1024 * 1024) * 10) / 10,
          },
          telemetry: {
            totalScans: Number(p.total_scans || 0),
            completedScans: Number(p.completed_scans || 0),
            failedScans: Number(p.failed_scans || 0),
            avgScanDurationSeconds: p.avg_duration_sec !== null ? Number(p.avg_duration_sec) : null,
            totalApkFiles: Number(st.total_apks || 0),
            storageMb: Math.round(Number(st.total_bytes || 0) / (1024 * 1024) * 10) / 10,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = AdminController;
