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
      SELECT id, name, email, password_hash, role, status, created_at, updated_at
      FROM users
      WHERE email = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [email.toLowerCase().trim()]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find user by primary key ID
   */
  static async findById(id) {
    const sql = `
      SELECT id, name, email, role, status, created_at, updated_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find user by ID including password hash for password verification
   */
  static async findByIdWithPassword(id) {
    const sql = `
      SELECT id, name, email, password_hash, role, status, created_at, updated_at
      FROM users
      WHERE id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
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
   * List all users with APK and Scan counts for Admin management
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
        COUNT(DISTINCT a.id) AS total_apks,
        COUNT(DISTINCT s.id) AS total_scans
      FROM users u
      LEFT JOIN apk_files a ON u.id = a.user_id
      LEFT JOIN scans s ON u.id = s.user_id
      GROUP BY u.id, u.name, u.email, u.role, u.status, u.created_at
      ORDER BY u.created_at DESC
    `;
    const [rows] = await query(sql);
    return rows;
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
