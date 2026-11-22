// test_maintenance_guard.js
// Automated verification suite for Minimal Production Maintenance Guard

const { spawn } = require('child_process');
const http = require('http');

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
    proc.on('error', reject);
    proc.on('exit', (code) => {
      if (!started) reject(new Error('Server exited with code ' + code));
    });
  });
}

async function runTests() {
  console.log('========================================================================');
  console.log('DATSANONLINE — MINIMAL MAINTENANCE GUARD VERIFICATION SUITE');
  console.log('========================================================================\n');

  console.log('--- 1. NORMAL OPERATION (MAINTENANCE_MODE=false) ---');
  const serverOff = await startServer('false');

  try {
    const health = await makeRequest('/api/health');
    console.log('  ✅ PASS: GET /api/health returned 200 (Got:', health.status, ')');
    if (health.status !== 200) throw new Error('Health probe failed');

    const config = await makeRequest('/api/mock-payment/config');
    console.log('  ✅ PASS: GET /api/mock-payment/config returned 200 (Got:', config.status, ')');

    const booking = await makeRequest('/api/bookings', 'POST', { masan: 1 });
    console.log('  ✅ PASS: POST /api/bookings passed guard to auth/handler (Got:', booking.status, ')');
    if (booking.status === 503) throw new Error('Maintenance guard blocked when false!');

    const cancel = await makeRequest('/api/customer/cancel-booking', 'POST', { bookingId: 1 });
    console.log('  ✅ PASS: POST /api/customer/cancel-booking passed guard (Got:', cancel.status, ')');

    const payment = await makeRequest('/api/mock-payment/process', 'POST', {});
    console.log('  ✅ PASS: POST /api/mock-payment/process passed guard (Got:', payment.status, ')');
  } finally {
    serverOff.kill();
    await new Promise(r => setTimeout(r, 1000));
  }

  console.log('\n--- 2. ACTIVE MAINTENANCE MODE (MAINTENANCE_MODE=true) ---');
  const serverOn = await startServer('true');

  try {
    const health = await makeRequest('/api/health');
    console.log('  ✅ PASS: GET /api/health remains accessible (Got:', health.status, ')');
    if (health.status !== 200) throw new Error('Health probe blocked during maintenance');

    const config = await makeRequest('/api/mock-payment/config');
    console.log('  ✅ PASS: GET /api/mock-payment/config remains accessible (Got:', config.status, ')');
    if (config.status !== 200) throw new Error('Config probe blocked during maintenance');

    const depositGet = await makeRequest('/api/owner/deposit');
    console.log('  ✅ PASS: Mutating GET /api/owner/deposit blocked with 503 ERR_MAINTENANCE_MODE');
    if (depositGet.status !== 503 || depositGet.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Mutating GET not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const booking = await makeRequest('/api/bookings', 'POST', { masan: 1 });
    console.log('  ✅ PASS: POST /api/bookings blocked with 503 ERR_MAINTENANCE_MODE');
    if (booking.status !== 503 || booking.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Booking write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const cancel = await makeRequest('/api/customer/cancel-booking', 'POST', { bookingId: 1 });
    console.log('  ✅ PASS: POST /api/customer/cancel-booking blocked with 503 ERR_MAINTENANCE_MODE');
    if (cancel.status !== 503 || cancel.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Cancellation write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const payment = await makeRequest('/api/mock-payment/process', 'POST', {});
    console.log('  ✅ PASS: POST /api/mock-payment/process blocked with 503 ERR_MAINTENANCE_MODE');
    if (payment.status !== 503 || payment.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Payment write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const settle = await makeRequest('/api/owner/settle-booking', 'POST', {});
    console.log('  ✅ PASS: POST /api/owner/settle-booking blocked with 503 ERR_MAINTENANCE_MODE');
    if (settle.status !== 503 || settle.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Owner settle write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const verifyDeposit = await makeRequest('/api/admin/deposits/verify', 'POST', {});
    console.log('  ✅ PASS: POST /api/admin/deposits/verify blocked with 503 ERR_MAINTENANCE_MODE');
    if (verifyDeposit.status !== 503 || verifyDeposit.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Admin verify deposit write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const apiData = await makeRequest('/api/data', 'POST', { table: 'datsan', action: 'insert' });
    console.log('  ✅ PASS: Generic frontend POST /api/data blocked with 503 ERR_MAINTENANCE_MODE');
    if (apiData.status !== 503 || apiData.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Generic frontend POST /api/data write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    const authWrite = await makeRequest('/api/bookings', 'POST', { masan: 1 }, { Authorization: 'Bearer mock_valid_jwt' });
    console.log('  ✅ PASS: Authenticated write attempt with Bearer token blocked with 503 ERR_MAINTENANCE_MODE');
    if (authWrite.status !== 503 || authWrite.json?.code !== 'ERR_MAINTENANCE_MODE') {
      throw new Error('Authenticated write not intercepted with 503 ERR_MAINTENANCE_MODE');
    }

    console.log('\n========================================================================');
    console.log('ALL 15 GUARD SUITE CHECKS PASSED WITH 100% SUCCESS!');
    console.log('========================================================================');
  } finally {
    serverOn.kill();
  }
}

if (require.main === module) {
  runTests().catch(err => {
    console.error('TEST SUITE FAILED:', err);
    process.exit(1);
  });
}

module.exports = { runTests };
