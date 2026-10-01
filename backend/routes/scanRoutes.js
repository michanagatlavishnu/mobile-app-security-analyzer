const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const { authenticateToken } = require('../middleware/authMiddleware');

// All scan routes require authentication
router.use(authenticateToken);

// Scan comparison (placed before /:id)
router.get('/compare', scanController.compareScans);

// Primary scan management
router.get('/', scanController.getScans);
router.get('/:id', scanController.getScan);
router.post('/:id/start', scanController.startScan);
router.delete('/:id', scanController.deleteScan);

// Finding inspection & remediation tracking
router.get('/:scanId/findings/:findingId', scanController.getFinding);
router.patch('/:scanId/findings/:findingId', scanController.updateFinding);
router.post('/:scanId/findings/:findingId/notes', scanController.addFindingNote);

module.exports = router;
