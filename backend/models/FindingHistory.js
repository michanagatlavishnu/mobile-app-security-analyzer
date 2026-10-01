const { query } = require('../config/db');

class FindingHistory {
  /**
   * Records a status transition or analyst note in the finding audit trail
   */
  static async create({ vulnerabilityId, previousStatus, newStatus, changedBy, note = null }) {
    const sql = `
      INSERT INTO finding_history (vulnerability_id, previous_status, new_status, changed_by, note)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [
      vulnerabilityId,
      previousStatus || null,
      newStatus,
      changedBy || null,
      note || null,
    ]);
    return {
      id: result.insertId,
      vulnerabilityId,
      previousStatus,
      newStatus,
      changedBy,
      note,
    };
  }

  /**
   * Retrieves chronological audit history for a finding
   */
  static async findByVulnerabilityId(vulnerabilityId) {
    const sql = `
      SELECT h.*, u.name AS user_name, u.email AS user_email, u.role AS user_role
      FROM finding_history h
      LEFT JOIN users u ON h.changed_by = u.id
      WHERE h.vulnerability_id = ?
      ORDER BY h.created_at DESC, h.id DESC
    `;
    const [rows] = await query(sql, [vulnerabilityId]);
    return rows;
  }
}

module.exports = FindingHistory;
