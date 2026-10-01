const jwt = require('jsonwebtoken');
const env = require('../config/env');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * JWT Authentication Middleware
 * Validates the Authorization Bearer token header and checks active account status
 */
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access denied: Authentication token required',
    });
  }

  try {
    const decoded = jwt.verify(token, env.jwtSecret);
    const userId = decoded.userId || decoded.id;

    // Verify account exists and is not disabled
    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Account no longer exists',
      });
    }

    if (user.status && user.status !== 'active') {
      logger.warn(`Rejected request from disabled user #${userId}`, { ip: req.ip, status: user.status });
      return res.status(401).json({
        success: false,
        message: 'Account has been disabled. Please contact an administrator.',
      });
    }

    req.user = {
      userId: user.id,
      id: user.id,
      role: user.role,
      status: user.status,
    };
    next();
  } catch (error) {
    logger.warn('Invalid JWT token verification attempt', {
      ip: req.ip,
      reason: error.message,
    });
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token',
    });
  }
}

module.exports = {
  authenticateToken,
};
