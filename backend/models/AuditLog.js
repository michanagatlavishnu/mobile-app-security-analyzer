const { query } = require('../config/db');

class AuditLog {
  static async log({ userId = null, action, entityType = null, entityId = null, details = null, ipAddress = null }) {
    try {
      const sql = `
        INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      await query(sql, [userId, action, entityType, entityId, details, ipAddress]);
    } catch {
      // Audit failures should not crash user-facing actions
    }
  }

  static async getRecent(limit = 50, offset = 0) {
    const sql = `
      SELECT a.*, u.name as user_name, u.email as user_email, u.role as user_role
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await query(sql, [Number(limit), Number(offset)]);
    return rows;
  }

  static async countAll() {
    const sql = `SELECT COUNT(*) AS total FROM audit_logs`;
    const [rows] = await query(sql);
    return rows[0].total;
  }
}

module.exports = AuditLog;
