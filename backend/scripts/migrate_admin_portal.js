const { query } = require('../config/db');

async function migrate() {
  console.log('[Migration] Starting Admin Portal schema optimizations...');

  // 1. Check & Add last_login to users
  const [cols] = await query(
    `SELECT COLUMN_NAME
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = 'mobile_security_analyzer'
       AND TABLE_NAME = 'users'
       AND COLUMN_NAME = 'last_login'`
  );

  if (cols.length === 0) {
    console.log('[Migration] Adding last_login column to users table...');
    await query(`ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL DEFAULT NULL AFTER updated_at`);
    console.log('[Migration] Column last_login successfully added.');
  } else {
    console.log('[Migration] Column last_login already present.');
  }

  // Helper to add index if missing
  async function ensureIndex(table, indexName, createSql) {
    const [indexes] = await query(
      `SELECT INDEX_NAME
       FROM information_schema.STATISTICS
       WHERE TABLE_SCHEMA = 'mobile_security_analyzer'
         AND TABLE_NAME = ?
         AND INDEX_NAME = ?`,
      [table, indexName]
    );

    if (indexes.length === 0) {
      console.log(`[Migration] Adding index ${indexName} to ${table}...`);
      await query(createSql);
      console.log(`[Migration] Index ${indexName} added successfully.`);
    } else {
      console.log(`[Migration] Index ${indexName} already present on ${table}.`);
    }
  }

  // 2. Add optimal indexes
  await ensureIndex('users', 'idx_users_status', 'CREATE INDEX idx_users_status ON users(status)');
  await ensureIndex('users', 'idx_users_created_at', 'CREATE INDEX idx_users_created_at ON users(created_at)');
  await ensureIndex('users', 'idx_users_last_login', 'CREATE INDEX idx_users_last_login ON users(last_login)');

  await ensureIndex('apk_files', 'idx_apk_package_name', 'CREATE INDEX idx_apk_package_name ON apk_files(package_name)');
  await ensureIndex('apk_files', 'idx_apk_created_at', 'CREATE INDEX idx_apk_created_at ON apk_files(created_at)');

  await ensureIndex('vulnerabilities', 'idx_vuln_created_at', 'CREATE INDEX idx_vuln_created_at ON vulnerabilities(created_at)');

  // 3. Backfill last_login from audit_logs for existing active users if available
  const [backfilled] = await query(`
    UPDATE users u
    JOIN (
      SELECT user_id, MAX(created_at) as max_login
      FROM audit_logs
      WHERE action IN ('USER_LOGIN', 'LOGIN', 'SYSTEM_INITIALIZATION_DEV_SEED') AND user_id IS NOT NULL
      GROUP BY user_id
    ) a ON u.id = a.user_id
    SET u.last_login = a.max_login
    WHERE u.last_login IS NULL
  `);
  console.log(`[Migration] Backfilled last_login for ${backfilled.affectedRows || 0} user(s) from audit log history.`);

  console.log('[Migration] Database optimization completed successfully.');
  process.exit(0);
}

migrate().catch((err) => {
  console.error('[Migration Error]', err);
  process.exit(1);
});
