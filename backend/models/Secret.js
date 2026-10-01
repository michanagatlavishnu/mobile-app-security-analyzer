const { query } = require('../config/db');

class Secret {
  static async create({ scanId, secretType, location, maskedValue, severity }) {
    const sql = `
      INSERT INTO secrets (scan_id, secret_type, location, masked_value, severity)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [scanId, secretType, location, maskedValue, severity]);
    return { id: result.insertId, scanId, secretType, maskedValue };
  }

  static async findByScanId(scanId) {
    const sql = `SELECT * FROM secrets WHERE scan_id = ? ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')`;
    const [rows] = await query(sql, [scanId]);
    return rows;
  }
}

module.exports = Secret;
