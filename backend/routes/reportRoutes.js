const express = require('express');
const rateLimit = require('express-rate-limit');
const { authenticateToken } = require('../middleware/authMiddleware');
const reportController = require('../controllers/reportController');

const router = express.Router();

// Sensitive rate limiter for report generation & exports (50 requests per 15 mins)
const reportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: {
    success: false,
    message: 'Report export limit exceeded. Please wait a few moments before requesting more reports.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

router.use(authenticateToken);
router.use(reportLimiter);

router.get('/:scanId/pdf', reportController.downloadPdf);
router.get('/:scanId/json', reportController.exportJson);
router.get('/:scanId/csv', reportController.exportCsv);

module.exports = router;
