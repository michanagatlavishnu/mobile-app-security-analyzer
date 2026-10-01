const express = require('express');
const { authenticateToken } = require('../middleware/authMiddleware');
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');

const router = express.Router();

router.use(authenticateToken);

/**
 * Get comprehensive dashboard analytics and score history
 * GET /api/dashboard/stats
 */
router.get('/stats', async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const [stats, scoreHistory, topIssues] = await Promise.all([
      Scan.getUserDashboardStats(userId, isAdmin),
      Scan.getUserScoreHistory(userId, isAdmin),
      Vulnerability.getTopVulnerabilities(isAdmin ? null : userId, 6),
    ]);

    return res.status(200).json({
      success: true,
      stats,
      scoreHistory: scoreHistory.map((s) => ({
        id: s.id,
        score: s.security_score,
        riskLevel: s.risk_level,
        apkName: s.original_filename,
        packageName: s.package_name,
        version: s.version_name,
        date: s.completed_at,
      })),
      topIssues: topIssues.map((t) => ({
        title: t.title,
        severity: t.severity,
        category: t.category,
        cwe: t.cwe,
        count: Number(t.count || 0),
      })),
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
