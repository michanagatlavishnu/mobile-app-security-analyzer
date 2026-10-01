const mysql = require('mysql2/promise');
const env = require('./env');
const logger = require('../utils/logger');

// Create connection pool with parameterized query support
const pool = mysql.createPool({
  host: env.db.host,
  port: env.db.port,
  database: env.db.name,
  user: env.db.user,
  password: env.db.password,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
});

/**
 * Executes a parameterized SQL query safely
 * @param {string} sql - Parameterized SQL query string
 * @param {Array} params - Array of parameters
 * @returns {Promise<[any, any]>} - Query results
 */
async function query(sql, params = []) {
  try {
    return await pool.execute(sql, params);
  } catch (error) {
    logger.error('Database query execution error', {
      code: error.code,
      errno: error.errno,
      sqlState: error.sqlState,
      message: error.message,
    });
    throw error;
  }
}

/**
 * Health check helper to verify database connectivity without leaking credentials
 * @returns {Promise<{ connected: boolean, error?: string }>}
 */
async function checkConnection() {
  try {
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();
    return { connected: true };
  } catch (error) {
    logger.warn('Database health check ping failed', {
      code: error.code,
      message: error.message,
    });
    return {
      connected: false,
      error: error.code || 'CONNECTION_FAILED',
    };
  }
}

/**
 * Gracefully close the connection pool during shutdown
 */
async function closePool() {
  try {
    logger.info('Closing MySQL database connection pool...');
    await pool.end();
    logger.info('MySQL connection pool closed cleanly.');
  } catch (error) {
    logger.error('Error closing MySQL pool', { message: error.message });
  }
}

module.exports = {
  pool,
  query,
  checkConnection,
  closePool,
};
