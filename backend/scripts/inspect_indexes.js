const { query } = require('../config/db');

async function main() {
  const [rows] = await query(
    `SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME
     FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = 'mobile_security_analyzer'
     ORDER BY TABLE_NAME, INDEX_NAME`
  );
  rows.forEach((r) => {
    console.log(`${r.TABLE_NAME}.${r.INDEX_NAME} -> ${r.COLUMN_NAME}`);
  });
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
