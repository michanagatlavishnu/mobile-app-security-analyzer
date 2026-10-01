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

  /**
   * Filtered and paginated audit trail for Admin Audit Logs
   */
  static async getFilteredLogs({
    page = 1,
    limit = 50,
    user = '',
    action = '',
    entityType = '',
    startDate = '',
    endDate = '',
  }) {
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(100, parseInt(limit, 10) || 50));
    const offset = (pageNum - 1) * limitNum;

    const whereClauses = [];
    const params = [];

    if (user && user.trim().length > 0) {
      const trimmed = user.trim();
      const asInt = parseInt(trimmed, 10);
      if (!isNaN(asInt) && String(asInt) === trimmed) {
        whereClauses.push('(a.user_id = ? OR u.name LIKE ? OR u.email LIKE ?)');
        params.push(asInt, `%${trimmed}%`, `%${trimmed}%`);
      } else {
        whereClauses.push('(u.name LIKE ? OR u.email LIKE ?)');
        params.push(`%${trimmed}%`, `%${trimmed}%`);
      }
    }

    if (action && action.trim().length > 0 && action.trim() !== 'all') {
      whereClauses.push('a.action = ?');
      params.push(action.trim());
    }

    if (entityType && entityType.trim().length > 0 && entityType.trim() !== 'all') {
      whereClauses.push('a.entity_type = ?');
      params.push(entityType.trim());
    }

    if (startDate && startDate.trim().length > 0) {
      whereClauses.push('a.created_at >= ?');
      params.push(`${startDate.trim()} 00:00:00`);
    }

    if (endDate && endDate.trim().length > 0) {
      whereClauses.push('a.created_at <= ?');
      params.push(`${endDate.trim()} 23:59:59`);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const countSql = `
      SELECT COUNT(*) AS total
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      ${whereSql}
    `;
    const [countRows] = await query(countSql, params);
    const total = Number(countRows[0]?.total || 0);

    const dataSql = `
      SELECT a.*, u.name as user_name, u.email as user_email, u.role as user_role
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      ${whereSql}
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `;
    const [rows] = await query(dataSql, [...params, limitNum, offset]);

    return {
      logs: rows,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum) || 1,
      },
    };
  }
}

module.exports = AuditLog;
