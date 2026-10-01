const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const Permission = require('../models/Permission');
const Component = require('../models/Component');
const NetworkFinding = require('../models/NetworkFinding');
const Secret = require('../models/Secret');
const AuditLog = require('../models/AuditLog');
const ScanExecutionService = require('../services/scanExecutionService');
const logger = require('../utils/logger');

/**
 * Start security scan on an uploaded APK
 * POST /api/scans/:id/start
 */
async function startScan(req, res, next) {
  try {
    const scanId = parseInt(req.params.id, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const result = await ScanExecutionService.startScan(scanId, userId, isAdmin);

    await AuditLog.log({
      userId,
      action: 'SCAN_STARTED',
      ipAddress: req.ip,
    });

    return res.status(200).json(result);
  } catch (error) {
    if (error.message.includes('not found')) {
      return res.status(404).json({ success: false, message: error.message });
    }
    if (error.message.includes('already in progress')) {
      return res.status(409).json({ success: false, message: error.message });
    }
    next(error);
  }
}

/**
 * Get all scans belonging to the authenticated user
 * GET /api/scans
 */
async function getScans(req, res, next) {
  try {
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const rawScans = await Scan.findAllByUser(userId, isAdmin);

    const formattedScans = rawScans.map((s) => ({
      id: s.id,
      apkId: s.apk_id,
      apkName: s.original_filename,
      packageName: s.package_name,
      versionName: s.version_name,
      versionCode: s.version_code,
      fileSize: s.file_size,
      sha256: s.sha256,
      status: s.status,
      progress: s.progress || 0,
      securityScore: s.security_score,
      riskLevel: s.risk_level,
      criticalCount: s.critical_count || 0,
      highCount: s.high_count || 0,
      mediumCount: s.medium_count || 0,
      lowCount: s.low_count || 0,
      startedAt: s.started_at,
      completedAt: s.completed_at,
      createdAt: s.created_at,
    }));

    return res.status(200).json({
      success: true,
      scans: formattedScans,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get scan details by ID, including findings if completed
 * GET /api/scans/:id
 */
async function getScan(req, res, next) {
  try {
    const scanId = parseInt(req.params.id, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const scan = await Scan.findByIdForUser(scanId, userId, isAdmin);
    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan record not found or access denied',
      });
    }

    let vulnerabilities = [];
    let permissions = [];
    let components = [];
    let networkFindings = [];
    let secrets = [];

    // If completed, fetch full results
    if (scan.status === 'completed') {
      [vulnerabilities, permissions, components, networkFindings, secrets] = await Promise.all([
        Vulnerability.findByScanId(scanId),
        Permission.findByScanId(scanId),
        Component.findByScanId(scanId),
        NetworkFinding.findByScanId(scanId),
        Secret.findByScanId(scanId),
      ]);
    }

    return res.status(200).json({
      success: true,
      scan: {
        id: scan.id,
        apkId: scan.apk_id,
        apkName: scan.original_filename,
        packageName: scan.package_name,
        versionName: scan.version_name,
        versionCode: scan.version_code,
        fileSize: scan.file_size,
        sha256: scan.sha256,
        status: scan.status,
        progress: scan.progress || 0,
        securityScore: scan.security_score,
        riskLevel: scan.risk_level,
        startedAt: scan.started_at,
        completedAt: scan.completed_at,
        createdAt: scan.created_at,
      },
      vulnerabilities,
      permissions,
      components,
      networkFindings,
      secrets,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Delete scan record
 * DELETE /api/scans/:id
 */
async function deleteScan(req, res, next) {
  try {
    const scanId = parseInt(req.params.id, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const scan = await Scan.findByIdForUser(scanId, userId, isAdmin);
    if (!scan) {
      return res.status(404).json({
        success: false,
        message: 'Scan record not found or access denied',
      });
    }

    await Scan.delete(scanId);

    await AuditLog.log({
      userId,
      action: 'SCAN_DELETED',
      ipAddress: req.ip,
    });

    return res.status(200).json({
      success: true,
      message: 'Scan record deleted successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get individual finding details
 * GET /api/scans/:scanId/findings/:findingId
 */
async function getFinding(req, res, next) {
  try {
    const findingId = parseInt(req.params.findingId, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const finding = await Vulnerability.findByIdForUser(findingId, userId, isAdmin);
    if (!finding) {
      return res.status(404).json({
        success: false,
        message: 'Finding not found or access denied',
      });
    }

    return res.status(200).json({
      success: true,
      finding,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Update finding remediation status
 * PATCH /api/scans/:scanId/findings/:findingId
 */
async function updateFinding(req, res, next) {
  try {
    const findingId = parseInt(req.params.findingId, 10);
    const { status, analystNote } = req.body;
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const validStatuses = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`,
      });
    }

    const finding = await Vulnerability.findByIdForUser(findingId, userId, isAdmin);
    if (!finding) {
      return res.status(404).json({
        success: false,
        message: 'Finding not found or access denied',
      });
    }

    const updated = await Vulnerability.updateStatus(findingId, {
      status: status || finding.status,
      analystNote: analystNote !== undefined ? analystNote : finding.analyst_note,
      resolvedBy: userId,
    });

    await AuditLog.log({
      userId,
      action: 'FINDING_STATUS_UPDATED',
      ipAddress: req.ip,
    });

    return res.status(200).json({
      success: true,
      message: 'Finding updated successfully',
      finding: updated,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Add or update analyst note on finding
 * POST /api/scans/:scanId/findings/:findingId/notes
 */
async function addFindingNote(req, res, next) {
  try {
    const findingId = parseInt(req.params.findingId, 10);
    const { note } = req.body;
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    if (note === undefined || note === null) {
      return res.status(400).json({ success: false, message: 'Note content is required' });
    }

    const finding = await Vulnerability.findByIdForUser(findingId, userId, isAdmin);
    if (!finding) {
      return res.status(404).json({
        success: false,
        message: 'Finding not found or access denied',
      });
    }

    const updated = await Vulnerability.updateStatus(findingId, {
      status: finding.status,
      analystNote: note,
      resolvedBy: userId,
    });

    return res.status(200).json({
      success: true,
      message: 'Analyst note saved successfully',
      finding: updated,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Compare two completed scans
 * GET /api/scans/compare?baseScanId=X&targetScanId=Y
 */
async function compareScans(req, res, next) {
  try {
    const baseScanId = parseInt(req.query.baseScanId, 10);
    const targetScanId = parseInt(req.query.targetScanId, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    if (isNaN(baseScanId) || isNaN(targetScanId)) {
      return res.status(400).json({
        success: false,
        message: 'Both baseScanId and targetScanId query parameters are required',
      });
    }

    if (baseScanId === targetScanId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot compare a scan with itself. Please select two distinct scans.',
      });
    }

    const [baseScan, targetScan] = await Promise.all([
      Scan.findByIdForUser(baseScanId, userId, isAdmin),
      Scan.findByIdForUser(targetScanId, userId, isAdmin),
    ]);

    if (!baseScan || !targetScan) {
      return res.status(404).json({
        success: false,
        message: 'One or both scan records not found or access denied',
      });
    }

    if (baseScan.status !== 'completed' || targetScan.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Both scans must be in completed status to perform comparison',
      });
    }

    // Fetch findings for both scans
    const [baseVulns, targetVulns, baseSec, targetSec, baseNet, targetNet, basePerms, targetPerms, baseComps, targetComps] = await Promise.all([
      Vulnerability.findByScanId(baseScanId),
      Vulnerability.findByScanId(targetScanId),
      Secret.findByScanId(baseScanId),
      Secret.findByScanId(targetScanId),
      NetworkFinding.findByScanId(baseScanId),
      NetworkFinding.findByScanId(targetScanId),
      Permission.findByScanId(baseScanId),
      Permission.findByScanId(targetScanId),
      Component.findByScanId(baseScanId),
      Component.findByScanId(targetScanId),
    ]);

    // Calculate score difference
    const scoreDiff = (targetScan.security_score ?? 0) - (baseScan.security_score ?? 0);

    // Build logical finding maps: key = title + '::' + category + '::' + location
    const makeKey = (f) => `${(f.title || '').trim().toLowerCase()}::${(f.category || '').trim().toLowerCase()}::${(f.location || '').trim().toLowerCase()}`;

    const baseMap = new Map();
    baseVulns.forEach((f) => baseMap.set(makeKey(f), f));

    const targetMap = new Map();
    targetVulns.forEach((f) => targetMap.set(makeKey(f), f));

    const newFindings = [];
    const resolvedFindings = [];
    const persistentFindings = [];

    // Findings in target scan
    targetMap.forEach((targetF, key) => {
      if (baseMap.has(key)) {
        const baseF = baseMap.get(key);
        persistentFindings.push({
          key,
          target: targetF,
          base: baseF,
          severityChanged: targetF.severity !== baseF.severity,
          statusChanged: targetF.status !== baseF.status,
        });
      } else {
        newFindings.push(targetF);
      }
    });

    // Findings in base but not in target
    baseMap.forEach((baseF, key) => {
      if (!targetMap.has(key)) {
        resolvedFindings.push(baseF);
      }
    });

    return res.status(200).json({
      success: true,
      comparison: {
        baseScan: {
          id: baseScan.id,
          apkName: baseScan.original_filename,
          packageName: baseScan.package_name,
          versionName: baseScan.version_name,
          versionCode: baseScan.version_code,
          sha256: baseScan.sha256,
          securityScore: baseScan.security_score,
          riskLevel: baseScan.risk_level,
          completedAt: baseScan.completed_at,
          totalFindings: baseVulns.length,
          criticalCount: baseVulns.filter((v) => v.severity === 'CRITICAL').length,
          highCount: baseVulns.filter((v) => v.severity === 'HIGH').length,
          mediumCount: baseVulns.filter((v) => v.severity === 'MEDIUM').length,
          lowCount: baseVulns.filter((v) => v.severity === 'LOW').length,
          secretsCount: baseSec.length,
          networkCount: baseNet.length,
          permissionsCount: basePerms.length,
          componentsCount: baseComps.length,
        },
        targetScan: {
          id: targetScan.id,
          apkName: targetScan.original_filename,
          packageName: targetScan.package_name,
          versionName: targetScan.version_name,
          versionCode: targetScan.version_code,
          sha256: targetScan.sha256,
          securityScore: targetScan.security_score,
          riskLevel: targetScan.risk_level,
          completedAt: targetScan.completed_at,
          totalFindings: targetVulns.length,
          criticalCount: targetVulns.filter((v) => v.severity === 'CRITICAL').length,
          highCount: targetVulns.filter((v) => v.severity === 'HIGH').length,
          mediumCount: targetVulns.filter((v) => v.severity === 'MEDIUM').length,
          lowCount: targetVulns.filter((v) => v.severity === 'LOW').length,
          secretsCount: targetSec.length,
          networkCount: targetNet.length,
          permissionsCount: targetPerms.length,
          componentsCount: targetComps.length,
        },
        diff: {
          scoreDiff,
          riskChanged: baseScan.risk_level !== targetScan.risk_level,
          newFindingsCount: newFindings.length,
          resolvedFindingsCount: resolvedFindings.length,
          persistentFindingsCount: persistentFindings.length,
        },
        changes: {
          newFindings,
          resolvedFindings,
          persistentFindings,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  startScan,
  getScans,
  getScan,
  deleteScan,
  getFinding,
  updateFinding,
  addFindingNote,
  compareScans,
};
