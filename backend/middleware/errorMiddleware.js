const logger = require('../utils/logger');
const env = require('../config/env');

/**
 * 404 Route Not Found Middleware
 */
function notFoundHandler(req, res, next) {
  const error = new Error(`Resource not found - ${req.method} ${req.originalUrl}`);
  res.status(404);
  next(error);
}

/**
 * Centralized Application Error Handling Middleware
 */
function errorHandler(err, req, res, next) {
  // If it's a Multer error or file validation error, return 400 Bad Request
  let statusCode = res.statusCode === 200 ? 500 : res.statusCode || 500;
  
  if (err.name === 'MulterError' || (err.message && err.message.includes('Only Android package files'))) {
    statusCode = 400;
  }

  logger.error(`[${req.method}] ${req.originalUrl} - ${err.message}`, {
    statusCode,
    ip: req.ip,
  });

  // Never leak internal stack traces in production
  const response = {
    success: false,
    message: err.message || 'Internal Server Error',
    ...(env.nodeEnv !== 'production' && { stack: err.stack }),
  };

  res.status(statusCode).json(response);
}

module.exports = {
  notFoundHandler,
  errorHandler,
};
