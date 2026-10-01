const { query } = require('../config/db');

class Component {
  static async create({ scanId, componentType, componentName, exported = false, permission = null }) {
    const sql = `
      INSERT INTO components (scan_id, component_type, component_name, exported, permission)
      VALUES (?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [scanId, componentType, componentName, exported, permission]);
    return { id: result.insertId, scanId, componentName, exported };
  }

  static async findByScanId(scanId) {
    const sql = `SELECT * FROM components WHERE scan_id = ? ORDER BY exported DESC, component_type ASC`;
    const [rows] = await query(sql, [scanId]);
    return rows;
  }
}

module.exports = Component;
