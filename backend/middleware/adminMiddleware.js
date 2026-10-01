const logger = require('../utils/logger');

/**
 * Admin Role Verification Middleware
 * Requires authenticateToken to run first
 */
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    logger.warn('Unauthorized admin access attempt', {
      userId: req.user ? req.user.id : null,
      role: req.user ? req.user.role : null,
      ip: req.ip,
      path: req.originalUrl,
    });
    return res.status(403).json({
      success: false,
      message: 'Access forbidden: Administrator privileges required',
    });
  }
  next();
}

module.exports = {
  requireAdmin,
};
