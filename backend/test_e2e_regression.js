const http = require('http');
const fs = require('fs');
const path = require('path');

function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = [];
      res.on('data', chunk => data.push(chunk));
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
      if (Buffer.isBuffer(body)) {
        req.write(body);
      } else {
        req.write(typeof body === 'string' ? body : JSON.stringify(body));
      }
    }
    req.end();
  });
}

async function runRegression() {
  console.log('====================================================');
  console.log('MOBILE APP SECURITY ANALYZER - PRODUCTION QA & E2E');
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

  // 1. Health Checks
  const healthRes = await request({ hostname: 'localhost', port: 5000, path: '/api/health', method: 'GET' });
  assert(healthRes.status === 200 && healthRes.body.success, 'GET /api/health returns 200 OK');

  const dbRes = await request({ hostname: 'localhost', port: 5000, path: '/api/health/db', method: 'GET' });
  assert(dbRes.status === 200 && dbRes.body.database === 'connected', 'GET /api/health/db reports connected');

  // 2. Authentication & Credential Security
  const adminLogin = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { email: 'admin@example.com', password: 'AdminPassword123!' });
  assert(adminLogin.status === 200 && adminLogin.body.token, 'Admin authentication successful');
  const adminToken = adminLogin.body.token;

  const analystLogin = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { email: 'lead.analyst@security.org', password: 'NewStrongPassword456!' });
  assert(analystLogin.status === 200 && analystLogin.body.token, 'Analyst authentication successful');
  const analystToken = analystLogin.body.token;

  // Case: Invalid login (wrong password)
  const invalidLogin = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { email: 'lead.analyst@security.org', password: 'WrongPassword999!' });
  assert(invalidLogin.status === 401, 'Invalid login attempt rejected with 401');

  // Case: SQL injection attempt in login
  const sqliLogin = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { email: "' OR '1'='1", password: "' OR '1'='1" });
  assert(sqliLogin.status === 401, 'SQL injection attempt in auth rejected with 401 without SQL errors');

  // Case: Missing JWT token
  const missingJwt = await request({
    hostname: 'localhost', port: 5000, path: '/api/scans', method: 'GET',
  });
  assert(missingJwt.status === 401, 'Request with missing JWT rejected with 401');

  // Case: Malformed / invalid JWT token
  const malformedJwt = await request({
    hostname: 'localhost', port: 5000, path: '/api/scans', method: 'GET',
    headers: { 'Authorization': 'Bearer malformed.invalid.token' },
  });
  assert(malformedJwt.status === 401, 'Request with invalid/malformed JWT rejected with 401');

  // 3. RBAC & Access Control
  const forbiddenAdmin = await request({
    hostname: 'localhost', port: 5000, path: '/api/admin/metrics', method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` },
  });
  assert(forbiddenAdmin.status === 403, 'Regular analyst rejected with 403 from /api/admin/metrics');

  const allowedAdmin = await request({
    hostname: 'localhost', port: 5000, path: '/api/admin/metrics', method: 'GET',
    headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  assert(allowedAdmin.status === 200 && allowedAdmin.body.success, 'Admin permitted access to /api/admin/metrics');

  // 4. Account Lifecycle: Disabled Account Protection
  const tempEmail = `test.disabled.${Date.now()}@security.org`;
  const registerRes = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/register', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { name: 'Temporary User', email: tempEmail, password: 'TempPassword123!' });
  assert(registerRes.status === 201 && registerRes.body.user?.id, 'Temporary test user registered');
  const tempUserId = registerRes.body.user.id;
  const tempUserToken = registerRes.body.token;

  // Admin disables this account
  const disableRes = await request({
    hostname: 'localhost', port: 5000, path: `/api/admin/users/${tempUserId}/status`, method: 'PUT',
    headers: { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
  }, { status: 'disabled' });
  assert(disableRes.status === 200, 'Admin disabled temporary test account');

  // Disabled user login attempt must fail with 403
  const disabledLogin = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/login', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { email: tempEmail, password: 'TempPassword123!' });
  assert(disabledLogin.status === 403, 'Disabled user login rejected with 403 Forbidden');

  // Active JWT for disabled user must be rejected immediately on protected route with 401
  const disabledTokenRequest = await request({
    hostname: 'localhost', port: 5000, path: '/api/scans', method: 'GET',
    headers: { 'Authorization': `Bearer ${tempUserToken}` },
  });
  assert(disabledTokenRequest.status === 401, 'Active JWT for disabled user rejected on protected route with 401');

  // 5. Upload Validation & Defense
  // Case: Invalid file extension
  const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';
  const invalidExtPayload = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="apk"; filename="malicious.exe"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    Buffer.from('EXECUTABLE_CONTENT'),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const invalidExtRes = await request({
    hostname: 'localhost', port: 5000, path: '/api/apk/upload', method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
  }, invalidExtPayload);
  assert(invalidExtRes.status === 400, 'Invalid file extension (.exe) rejected with 400');

  // Case: Corrupt APK (not a zip file)
  const corruptApkPayload = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="apk"; filename="corrupt.apk"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n`),
    Buffer.from('CORRUPT_NON_ZIP_BYTES_PADDING_PADDING_PADDING'),
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const corruptApkRes = await request({
    hostname: 'localhost', port: 5000, path: '/api/apk/upload', method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
  }, corruptApkPayload);
  assert(corruptApkRes.status === 400, 'Corrupt non-ZIP APK upload rejected with 400 validation failure');

  // 6. Legitimate APK Ingestion & Scanning
  const testApkPath = path.resolve(__dirname, '../analyzer/vulnerable_test_app.apk');
  assert(fs.existsSync(testApkPath), 'Vulnerable test APK exists on disk');

  const fileContent = fs.readFileSync(testApkPath);
  const legitimatePayload = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="apk"; filename="../../regression_test.apk"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n`),
    fileContent,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);

  const uploadRes = await request({
    hostname: 'localhost', port: 5000, path: '/api/apk/upload', method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
  }, legitimatePayload);
  assert((uploadRes.status === 200 || uploadRes.status === 201) && (uploadRes.body.scan?.id || uploadRes.body.scanId), 'APK upload accepted and queued for scan');
  const scanId = uploadRes.body.scan?.id || uploadRes.body.scanId;

  // Start analysis
  const startRes = await request({
    hostname: 'localhost', port: 5000, path: `/api/scans/${scanId}/start`, method: 'POST',
    headers: { 'Authorization': `Bearer ${analystToken}` },
  });
  assert(startRes.status === 200 || startRes.status === 409, `Scan #${scanId} execution started asynchronously`);

  // Poll for completion
  console.log(`Polling status of Scan #${scanId}...`);
  let scanComplete = false;
  let attempts = 0;
  let scanDetails = null;

  while (!scanComplete && attempts < 30) {
    await new Promise(r => setTimeout(r, 1000));
    const statusRes = await request({
      hostname: 'localhost', port: 5000, path: `/api/scans/${scanId}`, method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` },
    });
    if (statusRes.status === 200 && statusRes.body.scan?.status === 'completed') {
      scanComplete = true;
      scanDetails = statusRes.body;
      break;
    }
    attempts++;
  }

  const finalScore = scanDetails?.scan?.security_score ?? scanDetails?.scan?.securityScore ?? 0;
  assert(scanComplete, `Scan #${scanId} completed within timeout window with score ${finalScore}/100`);

  // 7. Security Findings & Verification
  const findings = scanDetails?.vulnerabilities || [];
  assert(findings.length > 0, `Verified ${findings.length} findings persisted into database`);
  assert(findings.some(f => f.title.includes('Debug Keystore') || f.title.includes('Certificate')), 'Certificate security finding detected');
  assert(findings.some(f => f.title.includes('ContentProvider')), 'ContentProvider security finding detected');
  assert(findings.some(f => f.title.includes('Transmission') || f.title.includes('Heuristic')), 'Source-to-sink correlation finding detected');

  // Verify secrets and strict MASKING guarantee
  const secrets = scanDetails?.secrets || [];
  assert(secrets.length > 0, `Secrets detected: ${secrets.length}`);
  const allMasked = secrets.every(s => s.masked_value && s.masked_value.includes('*'));
  assert(allMasked, 'Security Guarantee: ALL secret values are masked with asterisks');

  // 8. Cross-Tenant Data Isolation Checks
  // Register a secondary analyst user to verify they cannot access first analyst's scan/report/findings
  const secondaryEmail = `secondary.analyst.${Date.now()}@security.org`;
  const secReg = await request({
    hostname: 'localhost', port: 5000, path: '/api/auth/register', method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  }, { name: 'Secondary Analyst', email: secondaryEmail, password: 'SecondaryPass123!' });
  const secondaryToken = secReg.body.token;

  // Secondary user attempts to access first analyst's scan
  const foreignScanRes = await request({
    hostname: 'localhost', port: 5000, path: `/api/scans/${scanId}`, method: 'GET',
    headers: { 'Authorization': `Bearer ${secondaryToken}` },
  });
  assert(foreignScanRes.status === 404, 'Cross-tenant isolation: Foreign scan access rejected with 404');

  // Secondary user attempts to access first analyst's report
  const foreignReportRes = await request({
    hostname: 'localhost', port: 5000, path: `/api/reports/${scanId}/json`, method: 'GET',
    headers: { 'Authorization': `Bearer ${secondaryToken}` },
  });
  assert(foreignReportRes.status === 404, 'Cross-tenant isolation: Foreign report download rejected with 404');

  // 9. Reports Verification (JSON, CSV, PDF & CSV Injection Defense)
  const jsonReport = await request({
    hostname: 'localhost', port: 5000, path: `/api/reports/${scanId}/json`, method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` },
  });
  assert(jsonReport.status === 200 && (jsonReport.body.audit || jsonReport.body.application), 'GET /api/reports/:id/json returns structured report');

  const csvReport = await request({
    hostname: 'localhost', port: 5000, path: `/api/reports/${scanId}/csv`, method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` },
  });
  assert(csvReport.status === 200 && typeof csvReport.body === 'string' && csvReport.body.includes('Finding ID'), 'GET /api/reports/:id/csv returns CSV report');

  const pdfReport = await request({
    hostname: 'localhost', port: 5000, path: `/api/reports/${scanId}/pdf`, method: 'GET',
    headers: { 'Authorization': `Bearer ${analystToken}` },
  });
  assert(pdfReport.status === 200 && pdfReport.raw.slice(0, 4).toString() === '%PDF', 'GET /api/reports/:id/pdf generates valid PDF document');

  // 10. Security Operations & Finding Lifecycle
  if (findings.length > 0) {
    const targetFindingId = findings[0].id;
    const updateRes = await request({
      hostname: 'localhost', port: 5000, path: `/api/vulnerabilities/${targetFindingId}/status`, method: 'PUT',
      headers: { 'Authorization': `Bearer ${analystToken}`, 'Content-Type': 'application/json' },
    }, { status: 'RESOLVED', note: 'Regression verification sign-off' });
    assert(updateRes.status === 200 && updateRes.body.success, 'Finding lifecycle status update to RESOLVED');

    const historyRes = await request({
      hostname: 'localhost', port: 5000, path: `/api/vulnerabilities/${targetFindingId}/history`, method: 'GET',
      headers: { 'Authorization': `Bearer ${analystToken}` },
    });
    assert(historyRes.status === 200 && historyRes.body.data?.length > 0, 'Finding history audit trail retrieved');
  }

  // 11. Admin Telemetry
  const adminMetrics = await request({
    hostname: 'localhost', port: 5000, path: '/api/admin/metrics', method: 'GET',
    headers: { 'Authorization': `Bearer ${adminToken}` },
  });
  assert(adminMetrics.status === 200 && adminMetrics.body.data.scans.total >= 1, 'Global telemetry updated with new scan count');

  console.log('\n====================================================');
  console.log(`REGRESSION RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runRegression().catch(err => {
  console.error('Regression suite crashed:', err);
  process.exit(1);
});
