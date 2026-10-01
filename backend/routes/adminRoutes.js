const express = require('express');
const router = express.Router();
const AdminController = require('../controllers/adminController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireAdmin } = require('../middleware/adminMiddleware');

// All admin routes mandate active session and administrative role
router.use(authenticateToken, requireAdmin);

router.get('/users', AdminController.getUsers);
router.put('/users/:id/role', AdminController.updateUserRole);
router.put('/users/:id/status', AdminController.updateUserStatus);
router.get('/metrics', AdminController.getSystemMetrics);
router.get('/audit-logs', AdminController.getAuditLogs);

module.exports = router;
