const User = require('../models/User');
const Scan = require('../models/Scan');
const ApkFile = require('../models/ApkFile');
const Vulnerability = require('../models/Vulnerability');
const AuditLog = require('../models/AuditLog');
const { query } = require('../config/db');
const logger = require('../utils/logger');

class AdminController {
  /**
   * Retrieves all users with their scan and APK statistics
   */
  static async getUsers(req, res, next) {
    try {
      const users = await User.findAllWithStats();
      return res.json({
        success: true,
        data: users,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Updates user role (admin/user)
   */
  static async updateUserRole(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      const { role } = req.body;
      const currentAdminId = req.user.id;

      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({
          success: false,
          error: 'Role must be either "user" or "admin"',
        });
      }

      if (targetUserId === currentAdminId && role !== 'admin') {
        return res.status(400).json({
          success: false,
          error: 'Administrators cannot demote their own account',
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          error: 'Target user not found',
        });
      }

      await User.updateRole(targetUserId, role);

      await AuditLog.log({
        userId: currentAdminId,
        action: 'USER_ROLE_UPDATED',
        entityType: 'user',
        entityId: targetUserId,
        details: `Updated role for ${targetUser.email} from ${targetUser.role} to ${role}`,
        ipAddress: req.ip,
      });

      logger.info(`Admin #${currentAdminId} updated User #${targetUserId} role to ${role}`);

      return res.json({
        success: true,
        message: `User role successfully updated to ${role}`,
        data: { id: targetUserId, role },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Updates user account status (active/disabled)
   */
  static async updateUserStatus(req, res, next) {
    try {
      const targetUserId = parseInt(req.params.id, 10);
      const { status } = req.body;
      const currentAdminId = req.user.id;

      if (!['active', 'disabled'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Status must be either "active" or "disabled"',
        });
      }

      if (targetUserId === currentAdminId && status === 'disabled') {
        return res.status(400).json({
          success: false,
          error: 'Administrators cannot disable their own account',
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          error: 'Target user not found',
        });
      }

      await User.updateStatus(targetUserId, status);

      await AuditLog.log({
        userId: currentAdminId,
        action: 'USER_STATUS_UPDATED',
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
   * Returns system-wide telemetry, storage usage, and vulnerability aggregates
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
   * Retrieves paginated audit logs for system governance
   */
  static async getAuditLogs(req, res, next) {
    try {
      const page = parseInt(req.query.page, 10) || 1;
      const limit = parseInt(req.query.limit, 10) || 50;
      const offset = (page - 1) * limit;

      const logs = await AuditLog.getRecent(limit, offset);
      const total = await AuditLog.countAll();

      return res.json({
        success: true,
        data: {
          logs,
          pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = AdminController;
