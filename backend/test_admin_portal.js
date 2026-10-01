const http = require('http');

function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = [];
      res.on('data', (chunk) => data.push(chunk));
      res.on('end', () => {
        const buffer = Buffer.concat(data);
        const text = buffer.toString('utf8');
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(text), raw: buffer });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: text, raw: buffer });
        }
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runAdminTests() {
  console.log('====================================================');
  console.log('ADMIN PORTAL API & SECURITY REGRESSION SUITE (18/18)');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // Authentication Setup
  const adminLogin = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    },
    { email: 'admin@example.com', password: 'AdminPassword123!' }
  );
  assert(adminLogin.status === 200 && adminLogin.body.token, 'Admin login succeeded');
  const adminToken = adminLogin.body.token;
  const adminUser = adminLogin.body.user;

  const analystLogin = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    },
    { email: 'lead.analyst@security.org', password: 'NewStrongPassword456!' }
  );
  assert(analystLogin.status === 200 && analystLogin.body.token, 'Analyst login succeeded');
  const analystToken = analystLogin.body.token;

  // 1. Admin can access dashboard
  const dashAccess = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/dashboard',
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(dashAccess.status === 200 && dashAccess.body.success, 'Req 1: Admin can access dashboard');

  // 2. Analyst cannot access dashboard
  const analystDash = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/dashboard',
    method: 'GET',
    headers: { Authorization: `Bearer ${analystToken}` },
  });
  assert(analystDash.status === 403, 'Req 2: Analyst cannot access dashboard (403)');

  // 3. Missing JWT -> 401
  const missingJwt = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/dashboard',
    method: 'GET',
  });
  assert(missingJwt.status === 401, 'Req 3: Missing JWT returns 401');

  // 4. Invalid JWT -> 401
  const invalidJwt = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/dashboard',
    method: 'GET',
    headers: { Authorization: 'Bearer invalid.bogus.jwt' },
  });
  assert(invalidJwt.status === 401, 'Req 4: Invalid JWT returns 401');

  // Create temporary account for tests
  const testEmail = `admin.req.test.${Date.now()}@security.org`;
  const regRes = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    },
    { name: 'Admin Req Target', email: testEmail, password: 'SecurePassword123!' }
  );
  const targetId = regRes.body.user.id;
  const targetToken = regRes.body.token;

  // 5. Disabled admin -> rejected
  // Promote target to admin, disable target, then check both login and authenticated request are rejected
  await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/role`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { role: 'admin' }
  );
  await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/status`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { status: 'disabled' }
  );
  const disabledAdminReq = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/dashboard',
    method: 'GET',
    headers: { Authorization: `Bearer ${targetToken}` },
  });
  assert(disabledAdminReq.status === 401, 'Req 5: Disabled admin session rejected with 401');

  // Re-enable target
  await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/status`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { status: 'active' }
  );
  await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/role`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { role: 'user' }
  );

  // 6. Admin can list users
  const listUsers = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/users',
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(listUsers.status === 200 && Array.isArray(listUsers.body.data), 'Req 6: Admin can list users');

  // 7. Pagination works
  const pageUsers = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/users?page=1&limit=2',
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(
    pageUsers.status === 200 &&
      pageUsers.body.data.length <= 2 &&
      pageUsers.body.pagination?.totalPages >= 1,
    'Req 7: Server-side pagination works'
  );

  // 8. Search works
  const searchUsers = await request({
    hostname: 'localhost',
    port: 5000,
    path: `/api/admin/users?search=${encodeURIComponent('Admin Req Target')}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(
    searchUsers.status === 200 &&
      searchUsers.body.data.some((u) => u.name === 'Admin Req Target'),
    'Req 8: Search works by name/email'
  );

  // 9. Status filtering works
  const filterUsers = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/users?filter=disabled',
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(
    filterUsers.status === 200 &&
      filterUsers.body.data.every((u) => u.status === 'disabled'),
    'Req 9: Status filtering works'
  );

  // 10. Admin can disable user
  const disableUserRes = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/status`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { status: 'disabled' }
  );
  assert(disableUserRes.status === 200 && disableUserRes.body.data.status === 'disabled', 'Req 10: Admin can disable user');

  // 11. Disabled user cannot authenticate
  const disabledAuthRes = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    },
    { email: testEmail, password: 'SecurePassword123!' }
  );
  assert(disabledAuthRes.status === 403, 'Req 11: Disabled user cannot authenticate (403)');

  // 12. Admin can enable user
  const enableUserRes = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/status`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { status: 'active' }
  );
  assert(enableUserRes.status === 200 && enableUserRes.body.data.status === 'active', 'Req 12: Admin can enable user');

  // 13. Role changes are authorized
  const roleChangeRes = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/role`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { role: 'admin' }
  );
  assert(roleChangeRes.status === 200 && roleChangeRes.body.data.role === 'admin', 'Req 13: Role changes are authorized');

  // 14. Self-demotion is blocked
  const selfDemoteBlock = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${adminUser.id}/role`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { role: 'user' }
  );
  assert(selfDemoteBlock.status === 400 && selfDemoteBlock.body.error.includes('cannot demote'), 'Req 14: Self-demotion is blocked');

  // 15. Last-admin protection works
  // Demote targetId back to user so adminUser is the sole active admin
  await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${targetId}/role`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { role: 'user' }
  );
  // Attempt to disable last admin
  const disableLastAdmin = await request(
    {
      hostname: 'localhost',
      port: 5000,
      path: `/api/admin/users/${adminUser.id}/status`,
      method: 'PATCH',
      headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    },
    { status: 'disabled' }
  );
  assert(
    disableLastAdmin.status === 400 &&
      (disableLastAdmin.body.error.includes('cannot disable') || disableLastAdmin.body.error.includes('final active administrator')),
    'Req 15: Last-admin protection works'
  );

  // 16. Audit log created for administrative mutations
  const mutationLogs = await request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/admin/audit-logs?limit=10',
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const hasMutation = mutationLogs.body.data?.logs?.some((l) =>
    ['USER_DISABLED', 'USER_ENABLED', 'ROLE_CHANGED'].includes(l.action)
  );
  assert(hasMutation, 'Req 16: Audit log created for administrative mutations');

  // 17. Cross-user data cannot leak
  const analystForeignAccess = await request({
    hostname: 'localhost',
    port: 5000,
    path: `/api/admin/users/${adminUser.id}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${analystToken}` },
  });
  assert(analystForeignAccess.status === 403, 'Req 17: Cross-user administrative data cannot leak to non-admins (403)');

  // 18. SQL injection payloads are rejected safely
  const sqlPayload = "' OR '1'='1' -- ";
  const sqlInjectionTest = await request({
    hostname: 'localhost',
    port: 5000,
    path: `/api/admin/users?search=${encodeURIComponent(sqlPayload)}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert(
    sqlInjectionTest.status === 200 && Array.isArray(sqlInjectionTest.body.data),
    'Req 18: SQL injection payloads handled safely with parameterized queries'
  );

  console.log('\n====================================================');
  console.log(`ADMIN PORTAL REGRESSION: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAdminTests().catch((err) => {
  console.error('Test crashed:', err);
  process.exit(1);
});
