const { query } = require('../config/db');

class NetworkFinding {
  static async create({ scanId, type, severity, description, evidence }) {
    const sql = `
      INSERT INTO network_findings (scan_id, type, severity, description, evidence)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [scanId, type, severity, description, evidence]);
    return { id: result.insertId, scanId, type, severity };
  }

  static async findByScanId(scanId) {
    const sql = `SELECT * FROM network_findings WHERE scan_id = ? ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')`;
    const [rows] = await query(sql, [scanId]);
    return rows;
  }
}

module.exports = NetworkFinding;
