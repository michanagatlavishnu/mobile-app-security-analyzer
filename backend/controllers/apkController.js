const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ApkFile = require('../models/ApkFile');
const Scan = require('../models/Scan');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

// Security limits for archive inspection (Zip bomb & malicious entry defenses)
const MAX_ARCHIVE_ENTRIES = 50000;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024; // 1 GB uncompressed limit

/**
 * Calculates SHA-256 hash of a file using chunked streaming
 */
function calculateFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Validates APK archive structure, zip headers, entry limits, and required Android files.
 * Uses native Node binary zip header inspection without relying on external system binaries.
 */
function inspectApkArchive(filePath) {
  return new Promise((resolve, reject) => {
    fs.open(filePath, 'r', (err, fd) => {
      if (err) return reject(new Error('Cannot open uploaded file for inspection'));

      fs.fstat(fd, (err, stats) => {
        if (err) {
          fs.close(fd, () => {});
          return reject(new Error('Cannot stat file for inspection'));
        }

        const fileSize = stats.size;
        // A minimal zip must be at least 22 bytes (size of End of Central Directory Record)
        if (fileSize < 22) {
          fs.close(fd, () => {});
          return resolve({ isValid: false, reason: 'File is smaller than minimal ZIP structure' });
        }

        // Search for End of Central Directory Record (EOCD signature: 0x06054b50)
        // EOCD can be up to 65535 bytes + 22 bytes from the end of the file due to variable comment length
        const maxEocdSearchSize = Math.min(fileSize, 65535 + 22);
        const buffer = Buffer.alloc(maxEocdSearchSize);
        const readPosition = fileSize - maxEocdSearchSize;

        fs.read(fd, buffer, 0, maxEocdSearchSize, readPosition, (err, bytesRead) => {
          if (err) {
            fs.close(fd, () => {});
            return reject(new Error('Failed reading archive trailer'));
          }

          let eocdOffset = -1;
          for (let i = bytesRead - 22; i >= 0; i--) {
            if (buffer.readUInt32LE(i) === 0x06054b50) {
              eocdOffset = i;
              break;
            }
          }

          if (eocdOffset === -1) {
            fs.close(fd, () => {});
            return resolve({ isValid: false, reason: 'File is not a valid ZIP/APK archive (missing EOCD record)' });
          }

          const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
          const centralDirectorySize = buffer.readUInt32LE(eocdOffset + 12);
          const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);

          // Zip Bomb defense: Limit entry count
          if (totalEntries > MAX_ARCHIVE_ENTRIES) {
            fs.close(fd, () => {});
            return resolve({ isValid: false, reason: `Archive contains too many entries (${totalEntries}), possible compression bomb` });
          }

          // Read Central Directory to inspect filenames and compressed/uncompressed sizes
          if (centralDirectoryOffset + centralDirectorySize > fileSize) {
            fs.close(fd, () => {});
            return resolve({ isValid: false, reason: 'Corrupt ZIP central directory pointers' });
          }

          const cdBuffer = Buffer.alloc(centralDirectorySize);
          fs.read(fd, cdBuffer, 0, centralDirectorySize, centralDirectoryOffset, (err, cdBytesRead) => {
            fs.close(fd, () => {});
            if (err || cdBytesRead < centralDirectorySize) {
              return reject(new Error('Failed reading central directory'));
            }

            let offset = 0;
            let entryCount = 0;
            let totalUncompressedSize = 0;
            let hasManifest = false;
            let hasDex = false;

            while (offset + 46 <= centralDirectorySize) {
              if (cdBuffer.readUInt32LE(offset) !== 0x02014b50) {
                break; // Central directory header signature: 0x02014b50
              }

              const uncompressedSize = cdBuffer.readUInt32LE(offset + 24);
              const fileNameLength = cdBuffer.readUInt16LE(offset + 28);
              const extraFieldLength = cdBuffer.readUInt16LE(offset + 30);
              const commentLength = cdBuffer.readUInt16LE(offset + 32);

              totalUncompressedSize += uncompressedSize;
              // Zip Bomb defense: Total uncompressed byte threshold
              if (totalUncompressedSize > MAX_TOTAL_UNCOMPRESSED_BYTES) {
                return resolve({ isValid: false, reason: 'Uncompressed size exceeds security threshold (1 GB limit)' });
              }

              const fileNameBytes = cdBuffer.subarray(offset + 46, offset + 46 + fileNameLength);
              const entryName = fileNameBytes.toString('utf8');

              // Malicious path traversal check inside archive entries
              if (entryName.includes('..') || entryName.startsWith('/') || entryName.startsWith('\\')) {
                return resolve({ isValid: false, reason: `Malicious archive entry path detected: '${entryName}'` });
              }

              if (entryName === 'AndroidManifest.xml') {
                hasManifest = true;
              }
              if (entryName.startsWith('classes') && entryName.endsWith('.dex')) {
                hasDex = true;
              }

              entryCount++;
              offset += 46 + fileNameLength + extraFieldLength + commentLength;
            }

            if (!hasManifest) {
              return resolve({
                isValid: false,
                reason: 'Archive is a valid ZIP but is missing AndroidManifest.xml required for an Android APK',
              });
            }

            return resolve({
              isValid: true,
              totalEntries: entryCount,
              totalUncompressedSize,
              hasManifest,
              hasDex,
            });
          });
        });
      });
    });
  });
}

/**
 * Handle APK Upload
 * POST /api/apk/upload
 */
async function uploadApk(req, res, next) {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: 'No APK file was uploaded. Ensure field name is "apk"',
    });
  }

  const uploadedFilePath = req.file.path;
  const originalName = path.basename(req.file.originalname); // Sanitize path traversal in original filename

  try {
    // 1. Verify file extension strictly
    if (!originalName.toLowerCase().endsWith('.apk')) {
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);
      return res.status(400).json({
        success: false,
        message: 'Invalid file extension. Only Android package files (.apk) are supported',
      });
    }

    // 2. Validate archive integrity, presence of AndroidManifest.xml, and zip bomb thresholds
    const inspection = await inspectApkArchive(uploadedFilePath);
    if (!inspection.isValid) {
      logger.warn('Uploaded file failed APK structural validation', {
        filename: originalName,
        reason: inspection.reason,
        ip: req.ip,
      });
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);
      return res.status(400).json({
        success: false,
        message: `APK validation failed: ${inspection.reason}`,
      });
    }

    // 3. Compute SHA-256 hash server-side
    const sha256 = await calculateFileSha256(uploadedFilePath);
    const fileSize = req.file.size;
    const userId = req.user.userId;

    // 4. Duplicate Check (Option A: If user already uploaded identical APK by SHA-256, return existing APK & latest scan)
    const existingApk = await ApkFile.findBySha256ForUser(sha256, userId);
    if (existingApk) {
      logger.info(`Duplicate APK uploaded by user ${userId} (SHA256: ${sha256}). Reusing existing record.`);
      // Remove newly uploaded duplicate file to avoid redundant disk storage
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);

      // Fetch or create latest scan record for existing APK
      let scan = await Scan.findLatestByApkId(existingApk.id);
      if (!scan) {
        scan = await Scan.create({
          userId,
          apkId: existingApk.id,
          status: 'uploaded',
          progress: 0,
        });
      }

      return res.status(200).json({
        success: true,
        message: 'Existing APK identified by SHA-256. Reusing record.',
        isDuplicate: true,
        apk: {
          id: existingApk.id,
          filename: existingApk.original_filename,
          size: existingApk.file_size,
          sha256: existingApk.sha256,
          uploadedAt: existingApk.created_at,
        },
        scan: {
          id: scan.id,
          apkId: existingApk.id,
          status: scan.status,
          progress: scan.progress || 0,
        },
      });
    }

    // 5. Store APK record in MySQL
    let newApkRecord;
    try {
      newApkRecord = await ApkFile.create({
        userId,
        filename: req.file.filename, // Randomized storage name (e.g. apk_1720000000_abcdef.apk)
        originalFilename: originalName,
        fileSize,
        sha256,
        storagePath: uploadedFilePath, // Stored safely in backend/uploads/ outside public web root
      });
    } catch (dbErr) {
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);
      throw dbErr;
    }

    // 6. Create Scan record in MySQL with initial status 'uploaded'
    let scanRecord;
    try {
      scanRecord = await Scan.create({
        userId,
        apkId: newApkRecord.id,
        status: 'uploaded',
        progress: 0,
      });
    } catch (scanErr) {
      // Clean up APK record and file if scan creation fails
      await ApkFile.delete(newApkRecord.id);
      throw scanErr;
    }

    // 7. Audit Logging
    await AuditLog.log({
      userId,
      action: 'APK_UPLOADED',
      ipAddress: req.ip,
    });

    logger.info(`APK uploaded successfully: ${originalName} (ID: ${newApkRecord.id}, SHA: ${sha256})`);

    // 8. Return response without leaking internal physical file path
    return res.status(201).json({
      success: true,
      message: 'APK uploaded successfully. Security analysis has not started yet.',
      apk: {
        id: newApkRecord.id,
        filename: originalName,
        size: fileSize,
        sha256,
        uploadedAt: new Date().toISOString(),
      },
      scan: {
        id: scanRecord.id,
        apkId: newApkRecord.id,
        status: scanRecord.status,
        progress: scanRecord.progress,
      },
    });
  } catch (error) {
    if (fs.existsSync(uploadedFilePath)) {
      try {
        fs.unlinkSync(uploadedFilePath);
      } catch {}
    }
    next(error);
  }
}

/**
 * Get APK Metadata
 * GET /api/apk/:id
 */
async function getApk(req, res, next) {
  try {
    const apkId = parseInt(req.params.id, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const apk = await ApkFile.findByIdForUser(apkId, userId, isAdmin);
    if (!apk) {
      return res.status(404).json({
        success: false,
        message: 'APK record not found or access denied',
      });
    }

    // Never leak physical storage_path
    return res.status(200).json({
      success: true,
      apk: {
        id: apk.id,
        originalFilename: apk.original_filename,
        size: apk.file_size,
        sha256: apk.sha256,
        createdAt: apk.created_at,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Delete APK and associated scans/file
 * DELETE /api/apk/:id
 */
async function deleteApk(req, res, next) {
  try {
    const apkId = parseInt(req.params.id, 10);
    const userId = req.user.userId;
    const isAdmin = req.user.role === 'admin';

    const apk = await ApkFile.findByIdForUser(apkId, userId, isAdmin);
    if (!apk) {
      return res.status(404).json({
        success: false,
        message: 'APK record not found or access denied',
      });
    }

    await ApkFile.delete(apkId);

    await AuditLog.log({
      userId,
      action: 'APK_DELETED',
      ipAddress: req.ip,
    });

    logger.info(`APK deleted: ID ${apkId} by user ${userId}`);

    return res.status(200).json({
      success: true,
      message: 'APK and associated scan records deleted successfully',
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  uploadApk,
  getApk,
  deleteApk,
  calculateFileSha256,
  inspectApkArchive,
};
