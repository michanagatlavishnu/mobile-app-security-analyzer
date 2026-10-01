const path = require('path');
const dotenv = require('dotenv');
const logger = require('../utils/logger');

// Load .env file
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const INSECURE_DEFAULT_SECRETS = [
  'change_this_to_a_secure_random_secret_in_production_min_32_chars',
  'dev_insecure_fallback_secret_must_change',
  'dev_jwt_secret_key_randomly_generated_for_local_env_testing_987654321',
  'ProductionHardenedSecretKey_ChangeInProd_32BytesMin!',
];

function validateEnv() {
  const nodeEnv = process.env.NODE_ENV || 'development';
  const missing = [];

  // Critical variable checks
  if (!process.env.JWT_SECRET) {
    if (nodeEnv === 'production') {
      missing.push('JWT_SECRET (required in production)');
    }
  } else if (nodeEnv === 'production') {
    if (process.env.JWT_SECRET.length < 32) {
      missing.push('JWT_SECRET must be at least 32 characters in production');
    }
    if (INSECURE_DEFAULT_SECRETS.includes(process.env.JWT_SECRET)) {
      missing.push('JWT_SECRET cannot use default insecure placeholder in production');
    }
  }

  if (nodeEnv === 'production') {
    if (!process.env.DB_PASSWORD) {
      missing.push('DB_PASSWORD (required in production)');
    }
    if (!process.env.DB_USER) {
      missing.push('DB_USER (required in production)');
    }
  }

  if (missing.length > 0) {
    const errorMsg = `FATAL: Environment validation failed:\n - ${missing.join('\n - ')}`;
    logger.error(errorMsg);
    throw new Error(errorMsg);
  }

  // Enforce reasonable defaults
  const config = {
    port: parseInt(process.env.PORT, 10) || 5000,
    nodeEnv,
    jwtSecret: process.env.JWT_SECRET || 'dev_insecure_fallback_secret_must_change',
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
    db: {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT, 10) || 3306,
      name: process.env.DB_NAME || 'mobile_security_analyzer',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
    },
    storage: {
      uploadDir: path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './uploads'),
      reportDir: path.resolve(__dirname, '..', process.env.REPORT_DIR || './reports'),
      maxFileSizeMB: parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 200,
    },
    pythonPath: process.env.PYTHON_PATH || 'python',
    clientUrl: process.env.CLIENT_URL || 'http://localhost:5173',
    adminEmail: process.env.ADMIN_EMAIL || null,
    adminPassword: process.env.ADMIN_PASSWORD || null,
  };

  return config;
}

const env = validateEnv();

module.exports = env;
