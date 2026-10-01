const { query } = require('../config/db');

class Scan {
  /**
   * Create a new scan job record
   */
  static async create({ userId, apkId, status = 'uploaded', progress = 0 }) {
    const sql = `
      INSERT INTO scans (user_id, apk_id, status, progress, started_at)
      VALUES (?, ?, ?, ?, NOW())
    `;
    const [result] = await query(sql, [userId, apkId, status, progress]);
    return {
      id: result.insertId,
      userId,
      apkId,
      status,
      progress,
    };
  }

  /**
   * Find scan by ID with APK metadata
   */
  static async findById(id) {
    const sql = `
      SELECT s.id, s.user_id, s.apk_id, s.status, s.progress, s.security_score, s.risk_level,
             s.started_at, s.completed_at, s.created_at,
             a.original_filename, a.file_size, a.sha256,
             a.package_name, a.version_name, a.version_code
      FROM scans s
      JOIN apk_files a ON s.apk_id = a.id
      WHERE s.id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find scan by ID for a specific user (or admin)
   */
  static async findByIdForUser(id, userId, isAdmin = false) {
    if (isAdmin) {
      return this.findById(id);
    }
    const sql = `
      SELECT s.id, s.user_id, s.apk_id, s.status, s.progress, s.security_score, s.risk_level,
             s.started_at, s.completed_at, s.created_at,
             a.original_filename, a.file_size, a.sha256,
             a.package_name, a.version_name, a.version_code
      FROM scans s
      JOIN apk_files a ON s.apk_id = a.id
      WHERE s.id = ? AND s.user_id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id, userId]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find all scans belonging to a user
   */
  static async findAllByUser(userId, isAdmin = false) {
    let sql;
    let params;

    if (isAdmin) {
      sql = `
        SELECT s.id, s.user_id, s.apk_id, s.status, s.progress, s.security_score, s.risk_level,
               s.started_at, s.completed_at, s.created_at,
               a.original_filename, a.file_size, a.sha256,
               a.package_name, a.version_name, a.version_code,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'CRITICAL') AS critical_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'HIGH') AS high_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'MEDIUM') AS medium_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'LOW') AS low_count
        FROM scans s
        JOIN apk_files a ON s.apk_id = a.id
        ORDER BY s.created_at DESC
      `;
      params = [];
    } else {
      sql = `
        SELECT s.id, s.user_id, s.apk_id, s.status, s.progress, s.security_score, s.risk_level,
               s.started_at, s.completed_at, s.created_at,
               a.original_filename, a.file_size, a.sha256,
               a.package_name, a.version_name, a.version_code,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'CRITICAL') AS critical_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'HIGH') AS high_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'MEDIUM') AS medium_count,
               (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id AND v.severity = 'LOW') AS low_count
        FROM scans s
        JOIN apk_files a ON s.apk_id = a.id
        WHERE s.user_id = ?
        ORDER BY s.created_at DESC
      `;
      params = [userId];
    }

    const [rows] = await query(sql, params);
    return rows;
  }

  /**
   * Update scan status and optional results
   */
  static async updateStatus(id, { status, progress = null, securityScore = null, riskLevel = null }) {
    const fields = ['status = ?'];
    const params = [status];

    if (progress !== null) {
      fields.push('progress = ?');
      params.push(progress);
    }

    if (securityScore !== null) {
      fields.push('security_score = ?');
      params.push(securityScore);
    }

    if (riskLevel !== null) {
      fields.push('risk_level = ?');
      params.push(riskLevel);
    }

    if (status === 'completed') {
      fields.push('completed_at = NOW()');
    }

    params.push(id);

    const sql = `UPDATE scans SET ${fields.join(', ')} WHERE id = ?`;
    await query(sql, params);
  }

  /**
   * Update scan progress percentage
   */
  static async updateProgress(id, progress) {
    const sql = `UPDATE scans SET progress = ? WHERE id = ?`;
    await query(sql, [progress, id]);
  }

  /**
   * Find latest scan for an APK
   */
  static async findLatestByApkId(apkId) {
    const sql = `
      SELECT id, user_id, apk_id, status, progress, security_score, risk_level, created_at
      FROM scans
      WHERE apk_id = ?
      ORDER BY id DESC
      LIMIT 1
    `;
    const [rows] = await query(sql, [apkId]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Delete scan record
   */
  static async delete(id) {
    const sql = `DELETE FROM scans WHERE id = ?`;
    const [result] = await query(sql, [id]);
    return result.affectedRows > 0;
  }

  /**
   * Total scans in database
   */
  static async countAll() {
    const sql = `SELECT COUNT(*) AS total FROM scans`;
    const [rows] = await query(sql);
    return rows[0].total;
  }

  /**
   * Get user dashboard aggregated metrics
   */
  static async getUserDashboardStats(userId, isAdmin = false) {
    const userClause = isAdmin ? '' : 'WHERE s.user_id = ?';
    const params = isAdmin ? [] : [userId];

    // Scans stats
    const scansSql = `
      SELECT 
        COUNT(*) AS total_scans,
        COUNT(CASE WHEN s.status = 'completed' THEN 1 END) AS completed_scans,
        COUNT(CASE WHEN s.status = 'failed' THEN 1 END) AS failed_scans,
        ROUND(AVG(CASE WHEN s.status = 'completed' THEN s.security_score END), 1) AS avg_security_score
      FROM scans s
      ${userClause}
    `;
    const [scanRows] = await query(scansSql, params);

    // Finding stats
    const vulnSql = `
      SELECT 
        COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) AS critical_vulns,
        COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) AS high_vulns,
        COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) AS medium_vulns,
        COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) AS low_vulns
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      ${userClause}
    `;
    const [vulnRows] = await query(vulnSql, params);

    // Secrets stats
    const secSql = `
      SELECT COUNT(*) AS total_secrets
      FROM secrets sec
      JOIN scans s ON sec.scan_id = s.id
      ${userClause}
    `;
    const [secRows] = await query(secSql, params);

    // Network stats
    const netSql = `
      SELECT COUNT(*) AS total_network
      FROM network_findings net
      JOIN scans s ON net.scan_id = s.id
      ${userClause}
    `;
    const [netRows] = await query(netSql, params);

    const s = scanRows[0] || {};
    const v = vulnRows[0] || {};

    return {
      totalScans: Number(s.total_scans || 0),
      completedScans: Number(s.completed_scans || 0),
      failedScans: Number(s.failed_scans || 0),
      avgSecurityScore: s.avg_security_score !== null ? Number(s.avg_security_score) : null,
      criticalFindings: Number(v.critical_vulns || 0),
      highFindings: Number(v.high_vulns || 0),
      mediumFindings: Number(v.medium_vulns || 0),
      lowFindings: Number(v.low_vulns || 0),
      secretsDetected: Number(secRows[0]?.total_secrets || 0),
      networkFindings: Number(netRows[0]?.total_network || 0),
    };
  }

  /**
   * Get score history over time for completed scans
   */
  static async getUserScoreHistory(userId, isAdmin = false) {
    const sql = isAdmin
      ? `
        SELECT s.id, s.security_score, s.risk_level, s.completed_at,
               a.original_filename, a.package_name, a.version_name
        FROM scans s
        JOIN apk_files a ON s.apk_id = a.id
        WHERE s.status = 'completed' AND s.security_score IS NOT NULL
        ORDER BY s.completed_at ASC, s.id ASC
        LIMIT 50
      `
      : `
        SELECT s.id, s.security_score, s.risk_level, s.completed_at,
               a.original_filename, a.package_name, a.version_name
        FROM scans s
        JOIN apk_files a ON s.apk_id = a.id
        WHERE s.user_id = ? AND s.status = 'completed' AND s.security_score IS NOT NULL
        ORDER BY s.completed_at ASC, s.id ASC
        LIMIT 50
      `;
    const params = isAdmin ? [] : [userId];
    const [rows] = await query(sql, params);
    return rows;
  }
}

module.exports = Scan;
