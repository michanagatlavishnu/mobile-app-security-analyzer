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
}

module.exports = ApkFile;
