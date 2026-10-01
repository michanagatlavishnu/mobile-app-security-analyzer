const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const env = require('../config/env');
const logger = require('../utils/logger');

// Ensure upload directory exists securely
if (!fs.existsSync(env.storage.uploadDir)) {
  fs.mkdirSync(env.storage.uploadDir, { recursive: true });
}

// Multer disk storage engine with randomized UUID-style naming
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, env.storage.uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure randomized hex name with .apk extension to avoid collision & path traversal
    const randomHex = crypto.randomBytes(16).toString('hex');
    const safeFilename = `apk_${Date.now()}_${randomHex}.apk`;
    cb(null, safeFilename);
  },
});

// File filter: Only accept .apk files
const fileFilter = (req, file, cb) => {
  const extension = path.extname(file.originalname).toLowerCase();
  
  if (extension !== '.apk') {
    logger.warn('Rejected file upload due to non-APK extension', {
      originalName: file.originalname,
      extension,
      mimetype: file.mimetype,
    });
    return cb(new Error('Only Android package files (.apk) are supported'), false);
  }

  // Allowed APK MIME types
  const allowedMimes = [
    'application/vnd.android.package-archive',
    'application/octet-stream',
    'application/x-zip-compressed',
    'application/zip',
  ];

  if (file.mimetype && !allowedMimes.includes(file.mimetype)) {
    logger.warn('Suspicious MIME type for uploaded APK', {
      originalName: file.originalname,
      mimetype: file.mimetype,
    });
    // Still warn but allow if extension is strictly .apk since browsers/curl vary in octet-stream reporting
  }

  cb(null, true);
};

const maxFileSize = env.storage.maxFileSizeMB * 1024 * 1024;

const upload = multer({
  storage,
  limits: {
    fileSize: maxFileSize,
    files: 1,
  },
  fileFilter,
});

module.exports = upload;
