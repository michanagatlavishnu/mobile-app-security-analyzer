const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const env = require('../config/env');
const logger = require('../utils/logger');
const { pool } = require('../config/db');
const Scan = require('../models/Scan');
const ApkFile = require('../models/ApkFile');
const Vulnerability = require('../models/Vulnerability');
const Permission = require('../models/Permission');
const Component = require('../models/Component');
const NetworkFinding = require('../models/NetworkFinding');
const Secret = require('../models/Secret');

class ScanExecutionService {
  /**
   * Spawns Python static analyzer in the background and saves parsed findings in a transaction
   */
  static async startScan(scanId, userId, isAdmin = false) {
    const scan = await Scan.findByIdForUser(scanId, userId, isAdmin);
    if (!scan) {
      throw new Error('Scan record not found or access denied');
    }

    if (scan.status === 'analyzing' || scan.status === 'extracting') {
      throw new Error('Scan is already in progress');
    }

    const apk = await ApkFile.findById(scan.apk_id);
    if (!apk || !fs.existsSync(apk.storage_path)) {
      throw new Error('Associated APK file missing on disk');
    }

    // Set status to queued (10%)
    await Scan.updateStatus(scanId, { status: 'queued', progress: 10 });

    // Spawn Python static analyzer asynchronously
    setImmediate(() => {
      this.executePythonAnalysis(scanId, apk.storage_path).catch((err) => {
        logger.error(`Unhandled error during scan ${scanId} execution: ${err.message}`);
      });
    });

    return {
      success: true,
      scanId,
      status: 'queued',
      progress: 10,
    };
  }

  /**
   * Executes the Python process using child_process.spawn with safe argument arrays
   */
  static async executePythonAnalysis(scanId, apkPath) {
    const mainPyPath = path.resolve(__dirname, '../../analyzer/main.py');
    const outputDir = path.resolve(__dirname, '../reports');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    const outputPath = path.join(outputDir, `scan_result_${scanId}.json`);

    try {
      // 1. Stage: Extracting (25%)
      await Scan.updateStatus(scanId, { status: 'extracting', progress: 25 });

      // 2. Stage: Analyzing (50%)
      await Scan.updateStatus(scanId, { status: 'analyzing', progress: 50 });

      const args = [
        mainPyPath,
        '--apk',
        apkPath,
        '--output',
        outputPath,
        '--scan-id',
        String(scanId),
      ];

      logger.info(`Spawning Python static analysis for Scan #${scanId}`);

      const pythonProcess = spawn(env.pythonPath, args, {
        cwd: path.resolve(__dirname, '../../analyzer'),
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timeoutMs = 120000; // 2 minutes max per analysis job
      let isTimedOut = false;
      const timeoutTimer = setTimeout(() => {
        isTimedOut = true;
        logger.warn(`Scan #${scanId} exceeded maximum static analysis runtime of ${timeoutMs / 1000}s. Terminating worker.`);
        try {
          pythonProcess.kill('SIGTERM');
          setTimeout(() => {
            if (!pythonProcess.killed) {
              try { pythonProcess.kill('SIGKILL'); } catch {}
            }
          }, 3000);
        } catch {}
      }, timeoutMs);

      let stderr = '';
      const MAX_STDERR_BYTES = 524288; // 512KB maximum log retention
      pythonProcess.stderr.on('data', (data) => {
        if (stderr.length < MAX_STDERR_BYTES) {
          stderr += data.toString().slice(0, MAX_STDERR_BYTES - stderr.length);
        }
      });

      pythonProcess.on('close', async (code) => {
        clearTimeout(timeoutTimer);

        if (isTimedOut) {
          logger.error(`Python analyzer for Scan #${scanId} terminated due to timeout.`);
          if (fs.existsSync(outputPath)) {
            try { fs.unlinkSync(outputPath); } catch {}
          }
          await Scan.updateStatus(scanId, { status: 'failed', progress: 0 });
          return;
        }

        if (code !== 0) {
          logger.error(`Python analyzer exited with code ${code} for Scan #${scanId}`, { stderr });
          if (fs.existsSync(outputPath)) {
            try { fs.unlinkSync(outputPath); } catch {}
          }
          await Scan.updateStatus(scanId, { status: 'failed', progress: 0 });
          return;
        }

        try {
          if (!fs.existsSync(outputPath)) {
            throw new Error('Analysis output file was not produced by analyzer');
          }

          const rawOutput = fs.readFileSync(outputPath, 'utf8');
          const result = JSON.parse(rawOutput);

          if (!result.success) {
            logger.warn(`Analysis reported failure for Scan #${scanId}`, { errors: result.errors });
            if (fs.existsSync(outputPath)) {
              try { fs.unlinkSync(outputPath); } catch {}
            }
            await Scan.updateStatus(scanId, { status: 'failed', progress: 0 });
            return;
          }

          // Stage: Persisting findings (85%)
          await Scan.updateProgress(scanId, 85);

          // Save all findings atomically in a transaction
          await this.saveAnalysisResults(scanId, result);

          // Clean up temporary output json file
          if (fs.existsSync(outputPath)) {
            try { fs.unlinkSync(outputPath); } catch {}
          }

          logger.info(`Scan #${scanId} completed successfully with score ${result.score} (${result.risk_level})`);
        } catch (saveErr) {
          logger.error(`Error saving scan results for Scan #${scanId}: ${saveErr.message}`);
          if (fs.existsSync(outputPath)) {
            try { fs.unlinkSync(outputPath); } catch {}
          }
          await Scan.updateStatus(scanId, { status: 'failed' });
        }
      });

      pythonProcess.on('error', async (procErr) => {
        clearTimeout(timeoutTimer);
        logger.error(`Failed to launch Python analyzer: ${procErr.message}`);
        if (fs.existsSync(outputPath)) {
          try { fs.unlinkSync(outputPath); } catch {}
        }
        await Scan.updateStatus(scanId, { status: 'failed', progress: 0 });
      });

    } catch (error) {
      logger.error(`Scan execution pipeline failed for Scan #${scanId}: ${error.message}`);
      if (fs.existsSync(outputPath)) {
        try { fs.unlinkSync(outputPath); } catch {}
      }
      await Scan.updateStatus(scanId, { status: 'failed', progress: 0 });
    }
  }

  /**
   * Persists analysis findings into MySQL using a transaction
   */
  static async saveAnalysisResults(scanId, result) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      // 1. Delete prior findings if scan was restarted
      await connection.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', [scanId]);
      await connection.execute('DELETE FROM permissions WHERE scan_id = ?', [scanId]);
      await connection.execute('DELETE FROM components WHERE scan_id = ?', [scanId]);
      await connection.execute('DELETE FROM network_findings WHERE scan_id = ?', [scanId]);
      await connection.execute('DELETE FROM secrets WHERE scan_id = ?', [scanId]);

      // 2. Insert Vulnerabilities with Phase 6 deep static analysis fields
      for (const f of (result.findings || [])) {
        await connection.execute(`
          INSERT INTO vulnerabilities
          (scan_id, title, severity, category, description, evidence, location, impact, recommendation, cwe, owasp_category, confidence, analyzer, source)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          scanId,
          f.title || 'Security Finding',
          f.severity || 'LOW',
          f.category || 'General',
          f.description || '',
          f.evidence || null,
          f.location || null,
          f.impact || null,
          f.recommendation || null,
          f.cwe || null,
          f.owasp_category || null,
          f.confidence || 'HIGH',
          f.analyzer || 'static',
          f.source || 'dex',
        ]);
      }

      // 3. Insert Permissions
      for (const p of (result.permissions || [])) {
        await connection.execute(`
          INSERT INTO permissions (scan_id, permission_name, danger_level, description)
          VALUES (?, ?, ?, ?)
        `, [
          scanId,
          p.permission,
          p.risk || 'SAFE',
          p.description || null,
        ]);
      }

      // 4. Insert Components
      for (const c of (result.components || [])) {
        await connection.execute(`
          INSERT INTO components (scan_id, component_type, component_name, exported, permission)
          VALUES (?, ?, ?, ?, ?)
        `, [
          scanId,
          c.type || 'activity',
          c.name || 'UnnamedComponent',
          Boolean(c.exported),
          c.permission || null,
        ]);
      }

      // 5. Insert Network Findings (Phase 6)
      for (const n of (result.network || [])) {
        await connection.execute(`
          INSERT INTO network_findings (scan_id, type, severity, description, evidence)
          VALUES (?, ?, ?, ?, ?)
        `, [
          scanId,
          n.type || 'Network Endpoint',
          n.severity || 'LOW',
          n.description || '',
          n.evidence || null,
        ]);
      }

      // 6. Insert Masked Secrets (Phase 6)
      for (const s of (result.secrets || [])) {
        await connection.execute(`
          INSERT INTO secrets (scan_id, secret_type, location, masked_value, severity)
          VALUES (?, ?, ?, ?, ?)
        `, [
          scanId,
          s.secret_type || 'Generic Secret',
          s.location || null,
          s.masked_value || '********',
          s.severity || 'LOW',
        ]);
      }

      // 7. Update APK record with package name and version if extracted
      const pkgName = result.metadata?.package || result.manifest?.package;
      const verName = result.metadata?.versionName || result.manifest?.versionName;
      const verCode = result.metadata?.versionCode || result.manifest?.versionCode;
      if (pkgName) {
        await connection.execute(`
          UPDATE apk_files af
          JOIN scans s ON s.apk_id = af.id
          SET af.package_name = ?,
              af.version_name = ?,
              af.version_code = ?
          WHERE s.id = ?
        `, [pkgName, verName || '1.0', verCode || 1, scanId]);
      }

      // 8. Update Scan Status, Score, Risk Level, and Progress to 100%
      await connection.execute(`
        UPDATE scans
        SET status = 'completed',
            progress = 100,
            security_score = ?,
            risk_level = ?,
            completed_at = NOW()
        WHERE id = ?
      `, [result.score, result.risk_level, scanId]);

      await connection.commit();
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  }
}

module.exports = ScanExecutionService;
