const { query } = require('../config/db');

class User {
  /**
   * Create a new user with hashed password
   */
  static async createUser({ name, email, passwordHash, role = 'user', status = 'active' }) {
    const sql = `
      INSERT INTO users (name, email, password_hash, role, status)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [name, email.toLowerCase().trim(), passwordHash, role, status]);
    return {
      id: result.insertId,
      name,
      email: email.toLowerCase().trim(),
      role,
      status,
    };
  }

  /**
   * Find user by email address
   */
  static async findByEmail(email) {
    const sql = `
      SELECT id, name, email, password_hash, role, status, created_at, updated_at, last_login
      FROM users
      WHERE email = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [email.toLowerCase().trim()]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find user by primary key ID (omits password_hash)
   */
  static async findById(id) {
    const sql = `
      SELECT id, name, email, role, status, created_at, updated_at, last_login
      FROM users
      WHERE id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find user by ID including password hash for authentication checks
   */
  static async findByIdWithPassword(id) {
    const sql = `
      SELECT id, name, email, password_hash, role, status, created_at, updated_at, last_login
      FROM users
      WHERE id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Update user last login timestamp
   */
  static async updateLastLogin(id) {
    const sql = `UPDATE users SET last_login = NOW() WHERE id = ?`;
    await query(sql, [id]);
  }

  /**
   * Update user profile information (name, email)
   */
  static async updateUser(id, { name, email }) {
    const sql = `
      UPDATE users
      SET name = ?, email = ?
      WHERE id = ?
    `;
    await query(sql, [name, email.toLowerCase().trim(), id]);
    return this.findById(id);
  }

  /**
   * Update user password hash
   */
  static async updatePassword(id, newPasswordHash) {
    const sql = `
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `;
    const [result] = await query(sql, [newPasswordHash, id]);
    return result.affectedRows > 0;
  }

  /**
   * Count total registered users
   */
  static async countAll() {
    const sql = `SELECT COUNT(*) AS total FROM users`;
    const [rows] = await query(sql);
    return rows[0].total;
  }

  /**
   * Count active administrator accounts to prevent accidental lockouts
   */
  static async countActiveAdmins() {
    const sql = `SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'`;
    const [rows] = await query(sql);
    return Number(rows[0]?.count || 0);
  }

  /**
   * List all users with APK and Scan counts (Legacy compatibility)
   */
  static async findAllWithStats() {
    const sql = `
      SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.status,
        u.created_at,
        u.last_login,
        COUNT(DISTINCT a.id) AS total_apks,
        COUNT(DISTINCT s.id) AS total_scans
      FROM users u
      LEFT JOIN apk_files a ON u.id = a.user_id
      LEFT JOIN scans s ON u.id = s.user_id
      GROUP BY u.id, u.name, u.email, u.role, u.status, u.created_at, u.last_login
      ORDER BY u.created_at DESC
    `;
    const [rows] = await query(sql);
    return rows;
  }

  /**
   * Server-side paginated, searchable, filterable, and sortable user management query
   */
  static async findUsersPaginated({
    page = 1,
    limit = 20,
    search = '',
    filter = 'all',
    sortBy = 'created_at',
    sortOrder = 'DESC',
  }) {
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
    const offset = (pageNum - 1) * limitNum;

    const whereClauses = [];
    const params = [];

    // Search by name or email
    if (search && search.trim().length > 0) {
      whereClauses.push('(u.name LIKE ? OR u.email LIKE ?)');
      const term = `%${search.trim()}%`;
      params.push(term, term);
    }

    // Role or Status Filters
    const normalizedFilter = (filter || '').toLowerCase().trim();
    if (normalizedFilter === 'active') {
      whereClauses.push('u.status = "active"');
    } else if (normalizedFilter === 'disabled') {
      whereClauses.push('u.status = "disabled"');
    } else if (normalizedFilter === 'admin') {
      whereClauses.push('u.role = "admin"');
    } else if (normalizedFilter === 'analyst' || normalizedFilter === 'user') {
      whereClauses.push('u.role = "user"');
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    // Allowed sort columns to strictly prevent SQL injection
    const allowedSortColumns = {
      created_at: 'u.created_at',
      registration_date: 'u.created_at',
      last_login: 'u.last_login',
      last_activity: 'last_activity',
      total_scans: 'total_scans',
      total_apks: 'total_apks',
      status: 'u.status',
      role: 'u.role',
      name: 'u.name',
      email: 'u.email',
    };

    const sortColumn = allowedSortColumns[sortBy] || 'u.created_at';
    const orderDirection = (sortOrder || '').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // 1. Total matching count
    const countSql = `SELECT COUNT(*) AS total FROM users u ${whereSql}`;
    const [countRows] = await query(countSql, params);
    const total = Number(countRows[0]?.total || 0);

    // 2. Fetch paginated records with aggregates and last_activity
    const dataSql = `
      SELECT
        u.id,
        u.name,
        u.email,
        u.role,
        u.status,
        u.created_at,
        u.updated_at,
        u.last_login,
        COUNT(DISTINCT a.id) AS total_apks,
        COUNT(DISTINCT s.id) AS total_scans,
        (
          SELECT MAX(created_at)
          FROM audit_logs
          WHERE user_id = u.id
        ) AS last_audit,
        COALESCE(
          (SELECT MAX(created_at) FROM audit_logs WHERE user_id = u.id),
          u.last_login,
          u.created_at
        ) AS last_activity
      FROM users u
      LEFT JOIN apk_files a ON u.id = a.user_id
      LEFT JOIN scans s ON u.id = s.user_id
      ${whereSql}
      GROUP BY u.id, u.name, u.email, u.role, u.status, u.created_at, u.updated_at, u.last_login
      ORDER BY ${sortColumn} ${orderDirection}
      LIMIT ? OFFSET ?
    `;

    const [rows] = await query(dataSql, [...params, limitNum, offset]);

    return {
      users: rows.map((u) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        status: u.status,
        created_at: u.created_at,
        updated_at: u.updated_at,
        last_login: u.last_login,
        total_apks: Number(u.total_apks || 0),
        total_scans: Number(u.total_scans || 0),
        last_activity: u.last_activity,
      })),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum) || 1,
      },
    };
  }

  /**
   * Detailed user metrics, recent scans, and audit trail for /admin/users/:id
   */
  static async getUserDetails(id) {
    const targetUserId = parseInt(id, 10);
    const user = await this.findById(targetUserId);
    if (!user) return null;

    // 1. Scan and Vulnerability aggregates
    const [scanStats] = await query(
      `
      SELECT
        COUNT(*) AS total_scans,
        COUNT(CASE WHEN s.status = 'completed' THEN 1 END) AS completed_scans,
        COUNT(CASE WHEN s.status = 'failed' THEN 1 END) AS failed_scans,
        ROUND(AVG(CASE WHEN s.status = 'completed' THEN s.security_score END), 1) AS avg_security_score
      FROM scans s
      WHERE s.user_id = ?
    `,
      [targetUserId]
    );

    const [apkStats] = await query(
      `SELECT COUNT(*) AS total_apks FROM apk_files WHERE user_id = ?`,
      [targetUserId]
    );

    const [vulnStats] = await query(
      `
      SELECT
        COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) AS critical,
        COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) AS high,
        COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) AS medium,
        COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) AS low
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
    `,
      [targetUserId]
    );

    // 2. Recent Scans (latest 10)
    const [recentScans] = await query(
      `
      SELECT
        s.id,
        s.status,
        s.security_score,
        s.risk_level,
        s.started_at,
        s.completed_at,
        s.created_at,
        a.original_filename,
        a.package_name,
        a.version_name
      FROM scans s
      JOIN apk_files a ON s.apk_id = a.id
      WHERE s.user_id = ?
      ORDER BY s.created_at DESC
      LIMIT 10
    `,
      [targetUserId]
    );

    // 3. Recent Audit Activity (latest 15)
    const [recentActivity] = await query(
      `
      SELECT
        id,
        action,
        entity_type,
        entity_id,
        details,
        ip_address,
        created_at
      FROM audit_logs
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 15
    `,
      [targetUserId]
    );

    const [lastAuditRow] = await query(
      `SELECT MAX(created_at) AS last_audit FROM audit_logs WHERE user_id = ?`,
      [targetUserId]
    );

    const s = scanStats[0] || {};
    const v = vulnStats[0] || {};
    const lastActivity = lastAuditRow[0]?.last_audit || user.last_login || user.created_at;

    return {
      account: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
        created_at: user.created_at,
        updated_at: user.updated_at,
        last_login: user.last_login,
        last_activity: lastActivity,
      },
      usage: {
        apkUploads: Number(apkStats[0]?.total_apks || 0),
        totalScans: Number(s.total_scans || 0),
        completedScans: Number(s.completed_scans || 0),
        failedScans: Number(s.failed_scans || 0),
        avgSecurityScore: s.avg_security_score !== null ? Number(s.avg_security_score) : null,
        criticalFindings: Number(v.critical || 0),
        highFindings: Number(v.high || 0),
        mediumFindings: Number(v.medium || 0),
        lowFindings: Number(v.low || 0),
      },
      recentScans,
      recentActivity,
    };
  }

  /**
   * Admin: Update user role
   */
  static async updateRole(id, role) {
    const sql = `UPDATE users SET role = ? WHERE id = ?`;
    await query(sql, [role, id]);
    return this.findById(id);
  }

  /**
   * Admin: Update user account status (active/disabled)
   */
  static async updateStatus(id, status) {
    const sql = `UPDATE users SET status = ? WHERE id = ?`;
    await query(sql, [status, id]);
    return this.findById(id);
  }
}

module.exports = User;
