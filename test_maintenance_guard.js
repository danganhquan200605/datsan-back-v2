// test_maintenance_guard.js
// Automated verification suite for Minimal Production Maintenance Guard with strict assertions

const { spawn } = require('child_process');
const http = require('http');
const assert = require('assert');

const TEST_PORT = 5098;

function makeRequest(path, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const reqHeaders = {
      ...headers,
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {})
    };
    const req = http.request({
      hostname: 'localhost',
      port: TEST_PORT,
      path,
      method,
      headers: reqHeaders
    }, (res) => {
      let responseBody = '';
      res.on('data', chunk => responseBody += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(responseBody); } catch {}
        resolve({ status: res.statusCode, headers: res.headers, body: responseBody, json });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function startServer(maintenanceMode = 'false') {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', ['index.js'], {
      env: { ...process.env, PORT: String(TEST_PORT), MAINTENANCE_MODE: maintenanceMode },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let started = false;
    proc.stdout.on('data', (d) => {
      const msg = d.toString();
      if (msg.includes('DatSan API listening') && !started) {
        started = true;
        resolve(proc);
      }
    });
    proc.stderr.on('data', () => {});
    proc.on('error', reject);
    proc.on('exit', (code) => {
      if (!started) reject(new Error('Server exited with code ' + code));
    });
  });
}

async function runTests() {
  console.log('========================================================================');
  console.log('DATSANONLINE — STRICT MINIMAL MAINTENANCE GUARD TEST SUITE');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // STAGE 1: MAINTENANCE_MODE = false (NORMAL OPERATION)
  // -------------------------------------------------------------------------
  console.log('--- 1. NORMAL OPERATION (MAINTENANCE_MODE=false) ---');
  let server = await startServer('false');

  try {
    const health = await makeRequest('/api/health');
    assert.strictEqual(health.status, 200, 'GET /api/health must return 200');
    assert.strictEqual(health.json?.status, 'ok', 'Health status must be ok');
    console.log('  ✅ ASSERT PASS: GET /api/health returned 200 { status: "ok" }');

    const config = await makeRequest('/api/mock-payment/config');
    assert.strictEqual(config.status, 200, 'GET /api/mock-payment/config must return 200');
    assert.strictEqual(config.json?.financialMode, 'DEMO', 'financialMode must be DEMO');
    console.log('  ✅ ASSERT PASS: GET /api/mock-payment/config returned 200 { financialMode: "DEMO" }');

    const booking = await makeRequest('/api/bookings', 'POST', { masan: 1 });
    assert.notStrictEqual(booking.status, 503, 'POST /api/bookings must not be blocked by 503 when maintenance=false');
    assert.strictEqual(booking.status, 401, 'POST /api/bookings must reach auth layer (401 without token)');
    console.log('  ✅ ASSERT PASS: POST /api/bookings passed guard to auth layer (HTTP 401)');

    const cancel = await makeRequest('/api/customer/cancel-booking', 'POST', { bookingId: 1 });
    assert.notStrictEqual(cancel.status, 503, 'POST /api/customer/cancel-booking must not be 503');
    assert.strictEqual(cancel.status, 401, 'POST /api/customer/cancel-booking must reach auth layer (HTTP 401)');
    console.log('  ✅ ASSERT PASS: POST /api/customer/cancel-booking passed guard (HTTP 401)');

    const payment = await makeRequest('/api/mock-payment/process', 'POST', {});
    assert.notStrictEqual(payment.status, 503, 'POST /api/mock-payment/process must not be 503');
    assert.strictEqual(payment.status, 401, 'POST /api/mock-payment/process must reach auth layer (HTTP 401)');
    console.log('  ✅ ASSERT PASS: POST /api/mock-payment/process passed guard (HTTP 401)');
  } finally {
    server.kill();
    await new Promise(r => setTimeout(r, 1000));
  }

  // -------------------------------------------------------------------------
  // STAGE 2: MAINTENANCE_MODE = true (ACTIVE MAINTENANCE GUARD)
  // -------------------------------------------------------------------------
  console.log('\n--- 2. ACTIVE MAINTENANCE MODE (MAINTENANCE_MODE=true) ---');
  server = await startServer('true');

  try {
    // 1. Health Probe
    const health = await makeRequest('/api/health');
    assert.strictEqual(health.status, 200, 'GET /api/health must remain 200 during maintenance');
    console.log('  ✅ ASSERT PASS: GET /api/health remains accessible (HTTP 200)');

    // 2. Mock Payment Config
    const config = await makeRequest('/api/mock-payment/config');
    assert.strictEqual(config.status, 200, 'GET /api/mock-payment/config must remain 200');
    console.log('  ✅ ASSERT PASS: GET /api/mock-payment/config remains accessible (HTTP 200)');

    // 3. Mutating GET /api/owner/deposit
    const depositGet = await makeRequest('/api/owner/deposit');
    assert.strictEqual(depositGet.status, 503, 'Mutating GET /api/owner/deposit must return 503');
    assert.strictEqual(depositGet.json?.code, 'ERR_MAINTENANCE_MODE', 'Code must be ERR_MAINTENANCE_MODE');
    assert.strictEqual(depositGet.json?.maintenance, true, 'maintenance must be true');
    console.log('  ✅ ASSERT PASS: Mutating GET /api/owner/deposit strictly blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 4. Booking Write
    const booking = await makeRequest('/api/bookings', 'POST', { masan: 1 });
    assert.strictEqual(booking.status, 503, 'POST /api/bookings must return 503');
    assert.strictEqual(booking.json?.code, 'ERR_MAINTENANCE_MODE');
    assert.strictEqual(booking.json?.maintenance, true);
    console.log('  ✅ ASSERT PASS: POST /api/bookings blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 5. Cancellation Write
    const cancel = await makeRequest('/api/customer/cancel-booking', 'POST', { bookingId: 1 });
    assert.strictEqual(cancel.status, 503, 'POST /api/customer/cancel-booking must return 503');
    assert.strictEqual(cancel.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/customer/cancel-booking blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 6. Payment Write
    const payment = await makeRequest('/api/mock-payment/process', 'POST', {});
    assert.strictEqual(payment.status, 503, 'POST /api/mock-payment/process must return 503');
    assert.strictEqual(payment.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/mock-payment/process blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 7. Owner Settle Write
    const settle = await makeRequest('/api/owner/settle-booking', 'POST', {});
    assert.strictEqual(settle.status, 503, 'POST /api/owner/settle-booking must return 503');
    assert.strictEqual(settle.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/owner/settle-booking blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 8. Admin Verify Deposit Write
    const verifyDeposit = await makeRequest('/api/admin/deposits/verify', 'POST', {});
    assert.strictEqual(verifyDeposit.status, 503, 'POST /api/admin/deposits/verify must return 503');
    assert.strictEqual(verifyDeposit.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/admin/deposits/verify blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 9. Generic Frontend Write (/api/data)
    const apiData = await makeRequest('/api/data', 'POST', { table: 'datsan', action: 'insert' });
    assert.strictEqual(apiData.status, 503, 'POST /api/data must return 503');
    assert.strictEqual(apiData.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: Generic frontend POST /api/data blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    // 10. Authenticated Write with Bearer Token
    const authWrite = await makeRequest('/api/bookings', 'POST', { masan: 1 }, { Authorization: 'Bearer mock_jwt_token' });
    assert.strictEqual(authWrite.status, 503, 'Authenticated write must return 503');
    assert.strictEqual(authWrite.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: Authenticated request blocked with HTTP 503 ERR_MAINTENANCE_MODE (Auth preserved)');

    // 11. Auth OTP endpoints blocked during maintenance
    const authOtp = await makeRequest('/api/auth/otp', 'POST', { phone: '+84912345678' });
    assert.strictEqual(authOtp.status, 503, 'POST /api/auth/otp must return 503');
    assert.strictEqual(authOtp.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/auth/otp blocked with HTTP 503 ERR_MAINTENANCE_MODE');

    const authVerify = await makeRequest('/api/auth/verify', 'POST', { phone: '+84912345678', token: '123456' });
    assert.strictEqual(authVerify.status, 503, 'POST /api/auth/verify must return 503');
    assert.strictEqual(authVerify.json?.code, 'ERR_MAINTENANCE_MODE');
    console.log('  ✅ ASSERT PASS: POST /api/auth/verify (OTP 123456) blocked with HTTP 503 ERR_MAINTENANCE_MODE');
  } finally {
    server.kill();
    await new Promise(r => setTimeout(r, 1000));
  }

  // -------------------------------------------------------------------------
  // STAGE 3: RESTORATION VERIFICATION (MAINTENANCE_MODE TOGGLED BACK TO FALSE)
  // -------------------------------------------------------------------------
  console.log('\n--- 3. RESTORATION VERIFICATION (MAINTENANCE_MODE=false) ---');
  server = await startServer('false');

  try {
    const postReopen = await makeRequest('/api/bookings', 'POST', { masan: 1 });
    assert.strictEqual(postReopen.status, 401, 'POST /api/bookings must immediately resume normal handling (401)');
    assert.notStrictEqual(postReopen.status, 503, 'Must not be 503 after reopening');
    console.log('  ✅ ASSERT PASS: Normal service restored immediately when MAINTENANCE_MODE=false');
  } finally {
    server.kill();
  }

  console.log('\n========================================================================');
  console.log('ALL STRICT ASSERTION CHECKS PASSED WITH 100% SUCCESS!');
  console.log('========================================================================');
}

if (require.main === module) {
  runTests().catch(err => {
    console.error('TEST ASSERTION FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runTests };
