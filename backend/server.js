const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const env = require('./config/env');
const logger = require('./utils/logger');
const { checkConnection, closePool } = require('./config/db');
const { notFoundHandler, errorHandler } = require('./middleware/errorMiddleware');

// Route imports
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const apkRoutes = require('./routes/apkRoutes');
const scanRoutes = require('./routes/scanRoutes');
const adminRoutes = require('./routes/adminRoutes');
const reportRoutes = require('./routes/reportRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes');

const app = express();

// 1. Security HTTP Headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// 2. CORS Configuration
const allowedOrigins = [env.clientUrl, 'http://localhost:5173', 'http://127.0.0.1:5173'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy does not allow access from this origin'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// 3. Request Body Parsers (Note: multipart/form-data is parsed by multer on specific routes)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Global Rate Limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
  },
});
app.use('/api', globalLimiter);

// 5. System Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Mobile App Security Analyzer API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

// 6. Database Health Check Endpoint
app.get('/api/health/db', async (req, res) => {
  const dbStatus = await checkConnection();
  if (dbStatus.connected) {
    return res.status(200).json({
      success: true,
      database: 'connected',
    });
  } else {
    return res.status(503).json({
      success: false,
      database: 'disconnected',
    });
  }
});

// 7. Core Application Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/apk', apkRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/vulnerabilities', vulnerabilityRoutes);

// 8. Error Handling Middleware
app.use(notFoundHandler);
app.use(errorHandler);

// 9. Server Initialization
const server = app.listen(env.port, () => {
  logger.info(`Mobile App Security Analyzer backend listening on port ${env.port} [${env.nodeEnv}]`);
  logger.info(`Health check endpoint: http://localhost:${env.port}/api/health`);
  logger.info(`Database check endpoint: http://localhost:${env.port}/api/health/db`);
});

// 10. Graceful Shutdown Handlers
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Initiating graceful shutdown...`);
  server.close(async () => {
    logger.info('HTTP server closed.');
    await closePool();
    process.exit(0);
  });

  setTimeout(() => {
    logger.error('Forcefully terminating process due to shutdown timeout.');
    process.exit(1);
  }, 5000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

module.exports = { app, server };
