const http = require('http');

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : '';
    const reqHeaders = { ...headers };
    if (body) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(data);
    }
    const req = http.request({
      hostname: 'localhost', port: 5000, path, method, headers: reqHeaders
    }, (res) => {
      let respData = '';
      res.on('data', chunk => respData += chunk);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(respData); } catch { parsed = respData; }
        resolve({ status: res.statusCode, data: parsed });
      });
    });
    req.on('error', (err) => resolve({ status: 500, error: err.message }));
    if (body) req.write(data);
    req.end();
  });
}

async function runOtpSecurityTests() {
  console.log('========================================================');
  console.log('   DATSAN ONLINE - OTP SECURITY & RATE LIMITING TESTS   ');
  console.log('========================================================\n');

  const testPhone = '+84988776655';
  const testPhoneLock = '+84988112233';

  // Test 1: First OTP send -> 200 OK
  await request('POST', '/api/auth/otp/reset-limit', { phone: testPhone });
  const send1 = await request('POST', '/api/auth/otp', { phone: testPhone });
  console.log(`[TEST 1] First OTP Send: Status ${send1.status} | Data: ${JSON.stringify(send1.data)}`);
  const t1Pass = send1.status === 200 && send1.data.sent === true && send1.data.cooldown === 60;
  console.log(`         Result: ${t1Pass ? 'PASS' : 'FAIL'}`);

  // Test 2: Immediate second OTP send (< 60s) -> 429 Too Many Requests (Cooldown active)
  const send2 = await request('POST', '/api/auth/otp', { phone: testPhone });
  console.log(`[TEST 2] Immediate Second Send (Cooldown): Status ${send2.status} | Error: "${send2.data.error}"`);
  const t2Pass = send2.status === 429 && send2.data.error.includes('Vui lòng chờ') && send2.data.retryAfter > 0;
  console.log(`         Result: ${t2Pass ? 'PASS' : 'FAIL'}`);

  // Test 3: Invalid Phone format -> 400 Bad Request
  const sendBad = await request('POST', '/api/auth/otp', { phone: '090123' });
  console.log(`[TEST 3] Invalid Phone format: Status ${sendBad.status} | Error: "${sendBad.data.error}"`);
  const t3Pass = sendBad.status === 400;
  console.log(`         Result: ${t3Pass ? 'PASS' : 'FAIL'}`);

  // Test 4: Verify with wrong OTP -> 401 with remaining attempts warning
  await request('POST', '/api/auth/otp/reset-limit', { phone: testPhoneLock });
  await request('POST', '/api/auth/otp', { phone: testPhoneLock });

  const fail1 = await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '000000' });
  console.log(`[TEST 4] Wrong OTP (Attempt 1): Status ${fail1.status} | Error: "${fail1.data.error}" | Remaining: ${fail1.data.remainingAttempts}`);
  const t4Pass = fail1.status === 401 && fail1.data.remainingAttempts === 4;
  console.log(`         Result: ${t4Pass ? 'PASS' : 'FAIL'}`);

  // Test 5: Verify with wrong OTP 4 more times -> Lockout on 5th attempt
  await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '000000' }); // Attempt 2
  await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '000000' }); // Attempt 3
  await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '000000' }); // Attempt 4
  const fail5 = await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '000000' }); // Attempt 5
  console.log(`[TEST 5] Wrong OTP (Attempt 5 - Lockout): Status ${fail5.status} | Error: "${fail5.data.error}" | Lock: ${fail5.data.lockRemaining}s`);
  const t5Pass = fail5.status === 429 && fail5.data.error.includes('khóa xác minh');
  console.log(`         Result: ${t5Pass ? 'PASS' : 'FAIL'}`);

  // Test 6: Verify attempt while locked -> 429 Too Many Requests
  const failLocked = await request('POST', '/api/auth/verify', { phone: testPhoneLock, token: '123456' });
  console.log(`[TEST 6] Attempt while Locked: Status ${failLocked.status} | Error: "${failLocked.data.error}"`);
  const t6Pass = failLocked.status === 429 && failLocked.data.error.includes('khóa do nhập sai');
  console.log(`         Result: ${t6Pass ? 'PASS' : 'FAIL'}`);

  // Test 7: Request OTP while locked -> 429 Too Many Requests
  const otpWhileLocked = await request('POST', '/api/auth/otp', { phone: testPhoneLock });
  console.log(`[TEST 7] Request OTP while Locked: Status ${otpWhileLocked.status} | Error: "${otpWhileLocked.data.error}"`);
  const t7Pass = otpWhileLocked.status === 429 && otpWhileLocked.data.error.includes('khóa do nhập sai');
  console.log(`         Result: ${t7Pass ? 'PASS' : 'FAIL'}`);

  // Test 8: Valid login resets failed attempts and operates normally
  const adminPhone = '+84901111111';
  await request('POST', '/api/auth/otp/reset-limit', { phone: adminPhone });
  const adminLogin = await request('POST', '/api/auth/verify', { phone: adminPhone, token: '123456' });
  console.log(`[TEST 8] Valid Admin Login: Status ${adminLogin.status} | User: ${adminLogin.data?.user?.HoTen} (${adminLogin.data?.user?.VaiTro})`);
  const t8Pass = adminLogin.status === 200 && !!adminLogin.data.accessToken && adminLogin.data.user.VaiTro === 'ADMIN';
  console.log(`         Result: ${t8Pass ? 'PASS' : 'FAIL'}`);

  console.log('\n========================================================');
  const allPass = t1Pass && t2Pass && t3Pass && t4Pass && t5Pass && t6Pass && t7Pass && t8Pass;
  console.log(`OTP SECURITY SUITE RESULT: ${allPass ? 'ALL 8 TESTS PASS' : 'SOME TESTS FAILED'}`);
  console.log('========================================================\n');
}

runOtpSecurityTests().catch(console.error);
