const express = require('express');
const router = express.Router();
const AdminController = require('../controllers/adminController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireAdmin } = require('../middleware/adminMiddleware');

// All admin routes mandate active authenticated session and administrator privileges
router.use(authenticateToken, requireAdmin);

// 1. Overview & Metrics
router.get('/dashboard', AdminController.getDashboardOverview);
router.get('/metrics', AdminController.getSystemMetrics);

// 2. User Management & Governance
router.get('/users', AdminController.getUsers);
router.get('/users/:id', AdminController.getUserDetails);
router.get('/users/:id/activity', AdminController.getUserActivity);
router.patch('/users/:id/role', AdminController.updateUserRole);
router.put('/users/:id/role', AdminController.updateUserRole);
router.patch('/users/:id/status', AdminController.updateUserStatus);
router.put('/users/:id/status', AdminController.updateUserStatus);

// 3. System-Wide Audit Logs
router.get('/audit-logs', AdminController.getAuditLogs);

// 4. Analytics
router.get('/analytics/registrations', AdminController.getRegistrationAnalytics);
router.get('/analytics/activity', AdminController.getActivityAnalytics);

// 5. Application Management
router.get('/applications', AdminController.getApplications);
router.get('/applications/:packageName', AdminController.getApplicationDetails);

// 6. Scan Management
router.get('/scans', AdminController.getScans);

// 7. Security Findings Analytics & Explorer
router.get('/findings', AdminController.getFindings);

// 8. Runtime System Health Telemetry
router.get('/system-health', AdminController.getSystemHealth);

module.exports = router;
