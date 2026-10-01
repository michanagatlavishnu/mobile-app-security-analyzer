const { query } = require('../config/db');

class Permission {
  static async create({ scanId, permissionName, dangerLevel = 'SAFE', description }) {
    const sql = `
      INSERT INTO permissions (scan_id, permission_name, danger_level, description)
      VALUES (?, ?, ?, ?)
    `;
    const [result] = await query(sql, [scanId, permissionName, dangerLevel, description]);
    return { id: result.insertId, scanId, permissionName, dangerLevel };
  }

  static async findByScanId(scanId) {
    const sql = `SELECT * FROM permissions WHERE scan_id = ? ORDER BY FIELD(danger_level, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE')`;
    const [rows] = await query(sql, [scanId]);
    return rows;
  }
}

module.exports = Permission;
