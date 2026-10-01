const express = require('express');
const router = express.Router();
const apkController = require('../controllers/apkController');
const upload = require('../middleware/uploadMiddleware');
const { authenticateToken } = require('../middleware/authMiddleware');

// All APK routes require authentication
router.use(authenticateToken);

// Ingest APK via multipart/form-data
router.post('/upload', upload.single('apk'), apkController.uploadApk);

// Get APK metadata
router.get('/:id', apkController.getApk);

// Delete APK record & file
router.delete('/:id', apkController.deleteApk);

module.exports = router;
