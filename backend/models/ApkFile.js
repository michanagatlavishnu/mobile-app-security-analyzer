const fs = require('fs');
const path = require('path');
const { query } = require('../config/db');

class ApkFile {
  /**
   * Create an APK record
   */
  static async create({ userId, filename, originalFilename, fileSize, sha256, storagePath }) {
    const sql = `
      INSERT INTO apk_files (user_id, filename, original_filename, file_size, sha256, storage_path)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const [result] = await query(sql, [userId, filename, originalFilename, fileSize, sha256, storagePath]);
    return {
      id: result.insertId,
      userId,
      filename,
      originalFilename,
      fileSize,
      sha256,
      storagePath,
    };
  }

  /**
   * Find APK by ID
   */
  static async findById(id) {
    const sql = `
      SELECT id, user_id, filename, original_filename, file_size, sha256, storage_path, created_at
      FROM apk_files
      WHERE id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find APK by ID specifically for a user (or admin)
   */
  static async findByIdForUser(id, userId, isAdmin = false) {
    if (isAdmin) {
      return this.findById(id);
    }
    const sql = `
      SELECT id, user_id, filename, original_filename, file_size, sha256, storage_path, created_at
      FROM apk_files
      WHERE id = ? AND user_id = ?
      LIMIT 1
    `;
    const [rows] = await query(sql, [id, userId]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Find existing APK by SHA256 and user ID (for duplicate detection)
   */
  static async findBySha256ForUser(sha256, userId) {
    const sql = `
      SELECT id, user_id, filename, original_filename, file_size, sha256, storage_path, created_at
      FROM apk_files
      WHERE sha256 = ? AND user_id = ?
      ORDER BY id DESC
      LIMIT 1
    `;
    const [rows] = await query(sql, [sha256, userId]);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * List APKs owned by a user
   */
  static async findByUserId(userId) {
    const sql = `
      SELECT id, user_id, original_filename, file_size, sha256, created_at
      FROM apk_files
      WHERE user_id = ?
      ORDER BY created_at DESC
    `;
    const [rows] = await query(sql, [userId]);
    return rows;
  }

  /**
   * Delete APK record and physically unlink file if it exists
   */
  static async delete(id) {
    const apk = await this.findById(id);
    if (!apk) return false;

    // Delete database record (cascades to scans table via foreign key)
    const sql = `DELETE FROM apk_files WHERE id = ?`;
    await query(sql, [id]);

    // Securely remove physical file from disk
    if (apk.storage_path && fs.existsSync(apk.storage_path)) {
      try {
        fs.unlinkSync(apk.storage_path);
      } catch {
        // Log or handle unlink failure
      }
    }

    return true;
  }

  /**
   * Count APKs uploaded by user
   */
  static async countByUser(userId) {
    const sql = `SELECT COUNT(*) AS total FROM apk_files WHERE user_id = ?`;
    const [rows] = await query(sql, [userId]);
    return rows[0].total;
  }

  /**
   * Grouped application listing for Admin Applications view
   */
  static async getGroupedApplications({
    page = 1,
    limit = 20,
    search = '',
    sortBy = 'latest_uploaded',
    sortOrder = 'DESC',
  }) {
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
    const offset = (pageNum - 1) * limitNum;

    const whereClauses = [];
    const params = [];

    if (search && search.trim().length > 0) {
      const term = `%${search.trim()}%`;
      whereClauses.push('(a.package_name LIKE ? OR a.original_filename LIKE ?)');
      params.push(term, term);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const allowedSort = {
      package_name: 'app_identifier',
      uploads: 'uploads_count',
      scans: 'scans_count',
      latest_score: 'latest_security_score',
      latest_uploaded: 'latest_uploaded_date',
      last_analyzed: 'last_analyzed_date',
    };

    const sortCol = allowedSort[sortBy] || 'latest_uploaded_date';
    const sortDir = (sortOrder || '').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

    // Count distinct application groups
    const countSql = `
      SELECT COUNT(DISTINCT COALESCE(NULLIF(a.package_name, ''), a.original_filename)) AS total
      FROM apk_files a
      ${whereSql}
    `;
    const [countRows] = await query(countSql, params);
    const total = Number(countRows[0]?.total || 0);

    // Group by package_name or fallback to original_filename
    const dataSql = `
      SELECT
        COALESCE(NULLIF(a.package_name, ''), a.original_filename) AS app_identifier,
        MAX(a.package_name) AS package_name,
        MAX(a.original_filename) AS display_name,
        COUNT(DISTINCT a.id) AS uploads_count,
        COUNT(DISTINCT a.version_name) AS versions_count,
        COUNT(DISTINCT s.id) AS scans_count,
        MIN(a.created_at) AS first_uploaded_date,
        MAX(a.created_at) AS latest_uploaded_date,
        MAX(s.completed_at) AS last_analyzed_date,
        (
          SELECT s2.security_score
          FROM scans s2
          JOIN apk_files a2 ON s2.apk_id = a2.id
          WHERE COALESCE(NULLIF(a2.package_name, ''), a2.original_filename) = app_identifier
            AND s2.status = 'completed'
            AND s2.security_score IS NOT NULL
          ORDER BY s2.id DESC
          LIMIT 1
        ) AS latest_security_score,
        (
          SELECT s2.risk_level
          FROM scans s2
          JOIN apk_files a2 ON s2.apk_id = a2.id
          WHERE COALESCE(NULLIF(a2.package_name, ''), a2.original_filename) = app_identifier
            AND s2.status = 'completed'
          ORDER BY s2.id DESC
          LIMIT 1
        ) AS latest_risk_level,
        (
          SELECT s2.id
          FROM scans s2
          JOIN apk_files a2 ON s2.apk_id = a2.id
          WHERE COALESCE(NULLIF(a2.package_name, ''), a2.original_filename) = app_identifier
          ORDER BY s2.id DESC
          LIMIT 1
        ) AS latest_scan_id
      FROM apk_files a
      LEFT JOIN scans s ON a.id = s.apk_id
      ${whereSql}
      GROUP BY app_identifier
      ORDER BY ${sortCol} ${sortDir}
      LIMIT ? OFFSET ?
    `;

    const [rows] = await query(dataSql, [...params, limitNum, offset]);

    return {
      applications: rows.map((r) => ({
        identifier: r.app_identifier,
        packageName: r.package_name || null,
        displayName: r.display_name,
        uploadsCount: Number(r.uploads_count || 0),
        versionsCount: Math.max(1, Number(r.versions_count || 1)),
        scansCount: Number(r.scans_count || 0),
        firstUploadedDate: r.first_uploaded_date,
        latestUploadedDate: r.latest_uploaded_date,
        lastAnalyzedDate: r.last_analyzed_date,
        latestSecurityScore: r.latest_security_score !== null ? Number(r.latest_security_score) : null,
        latestRiskLevel: r.latest_risk_level || null,
        latestScanId: r.latest_scan_id || null,
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
   * Detailed application drill-down for /admin/applications/:identifier
   */
  static async getApplicationDetails(identifier) {
    if (!identifier) return null;

    // 1. Get all uploaded versions for this application
    const [versions] = await query(
      `
      SELECT
        a.id,
        a.filename,
        a.original_filename,
        a.package_name,
        a.version_name,
        a.version_code,
        a.file_size,
        a.sha256,
        a.created_at,
        u.id AS user_id,
        u.name AS user_name,
        u.email AS user_email
      FROM apk_files a
      JOIN users u ON a.user_id = u.id
      WHERE a.package_name = ? OR a.original_filename = ?
      ORDER BY a.created_at DESC
    `,
      [identifier, identifier]
    );

    if (versions.length === 0) {
      return null;
    }

    // 2. Get all scans executed for these versions
    const apkIds = versions.map((v) => v.id);
    const [scans] = await query(
      `
      SELECT
        s.id,
        s.apk_id,
        s.user_id,
        s.status,
        s.progress,
        s.security_score,
        s.risk_level,
        s.started_at,
        s.completed_at,
        s.created_at,
        u.name AS user_name,
        u.email AS user_email,
        a.original_filename,
        a.version_name,
        (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) AS vulnerability_count
      FROM scans s
      JOIN apk_files a ON s.apk_id = a.id
      JOIN users u ON s.user_id = u.id
      WHERE s.apk_id IN (?)
      ORDER BY s.created_at DESC
    `,
      [apkIds]
    );

    const first = versions[0];
    const completedScans = scans.filter((s) => s.status === 'completed' && s.security_score !== null);
    const avgScore =
      completedScans.length > 0
        ? Math.round(completedScans.reduce((acc, curr) => acc + curr.security_score, 0) / completedScans.length)
        : null;

    return {
      application: {
        identifier,
        packageName: first.package_name || null,
        displayName: first.original_filename,
        totalUploads: versions.length,
        totalScans: scans.length,
        avgSecurityScore: avgScore,
        latestRiskLevel: completedScans[0]?.risk_level || null,
        firstUploaded: versions[versions.length - 1]?.created_at,
        latestUploaded: first.created_at,
      },
      versions: versions.map((v) => ({
        id: v.id,
        filename: v.filename,
        originalFilename: v.original_filename,
        packageName: v.package_name,
        versionName: v.version_name,
        versionCode: v.version_code,
        fileSize: v.file_size,
        sha256: v.sha256,
        createdAt: v.created_at,
        uploadedBy: {
          id: v.user_id,
          name: v.user_name,
          email: v.user_email,
        },
      })),
      scans: scans.map((s) => ({
        id: s.id,
        apkId: s.apk_id,
        status: s.status,
        progress: s.progress,
        securityScore: s.security_score,
        riskLevel: s.risk_level,
        startedAt: s.started_at,
        completedAt: s.completed_at,
        createdAt: s.created_at,
        vulnerabilityCount: Number(s.vulnerability_count || 0),
        versionName: s.version_name,
        user: {
          id: s.user_id,
          name: s.user_name,
          email: s.user_email,
        },
      })),
    };
  }
}

module.exports = ApkFile;
