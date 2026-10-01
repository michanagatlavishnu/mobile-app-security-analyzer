const { query } = require('../config/db');

class Report {
  static async create({ scanId, filePath }) {
    const sql = `
      INSERT INTO reports (scan_id, file_path)
      VALUES (?, ?)
      ON DUPLICATE KEY UPDATE file_path = VALUES(file_path), created_at = NOW()
    `;
    const [result] = await query(sql, [scanId, filePath]);
    return { id: result.insertId, scanId, filePath };
  }

  static async findByScanId(scanId) {
    const sql = `SELECT * FROM reports WHERE scan_id = ? LIMIT 1`;
    const [rows] = await query(sql, [scanId]);
    return rows.length > 0 ? rows[0] : null;
  }
}

module.exports = Report;
