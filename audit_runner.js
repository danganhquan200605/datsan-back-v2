const http = require('http');

async function runSecurityAudit() {
  const adminPhone = '+84901111111';
  const ownerAPhone = '+84905123456'; // Owner A (ID 7, pitch 33)
  const ownerBPhone = '+84901222222'; // Owner B (ID 25, pitch 34)
  const customerAPhone = '+84905111222'; // Customer A (ID 17)
  const customerBPhone = '+84905222334'; // Customer B (ID 18)
  const validOtp = '123456';
  const invalidOtp = '000000';

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
          resolve({ status: res.statusCode, data: parsed, headers: res.headers });
        });
      });
      req.on('error', (err) => resolve({ status: 500, error: err.message }));
      if (body) req.write(data);
      req.end();
    });
  }

  const results = [];
  function log(id, category, name, expected, actual, pass, details = '') {
    results.push({ id, category, name, expected, actual, status: pass ? 'PASS' : 'FAIL', details });
    console.log(`[${pass ? 'PASS' : 'FAIL'}] ${id} - ${name} | Exp: ${expected} | Got: ${actual}`);
    if (details) console.log(`   └─ Details: ${details}`);
  }

  console.log('====================================================');
  console.log('   DATSAN ONLINE - AUTOMATED SECURITY AUDIT SUITE   ');
  console.log('====================================================\n');

  // ==========================================
  // PHASE A: AUTHENTICATION TESTING
  // ==========================================
  console.log('--- PHASE A: Authentication Testing ---');
  // A01: Valid login
  const loginRes = await request('POST', '/api/auth/verify', { phone: adminPhone, token: validOtp });
  const adminToken = loginRes.data?.accessToken;
  log('SEC-A01', 'Auth', 'Login with valid credentials', 200, loginRes.status, loginRes.status === 200 && !!adminToken);

  // A02: Non-existent account
  const nonExistRes = await request('POST', '/api/auth/verify', { phone: '+84999999999', token: validOtp });
  log('SEC-A02', 'Auth', 'Login with non-existent account', '400 or 401', nonExistRes.status, [400, 401, 404].includes(nonExistRes.status), JSON.stringify(nonExistRes.data));

  // A03: Incorrect OTP
  const badOtpRes = await request('POST', '/api/auth/verify', { phone: adminPhone, token: invalidOtp });
  log('SEC-A03', 'Auth', 'Login with incorrect OTP', 400, badOtpRes.status, [400, 401].includes(badOtpRes.status), JSON.stringify(badOtpRes.data));

  // A04: Protected endpoint without JWT
  const noJwtRes = await request('GET', '/api/admin/overview');
  log('SEC-A04', 'Auth', 'Access protected endpoint without JWT', 401, noJwtRes.status, noJwtRes.status === 401);

  // A05: Expired / malformed JWT
  const malformedJwtRes = await request('GET', '/api/admin/overview', null, { Authorization: 'Bearer this.is.an.invalid.jwt' });
  log('SEC-A05', 'Auth', 'Access protected endpoint with malformed JWT', 401, malformedJwtRes.status, malformedJwtRes.status === 401);

  // A06: Tampered JWT signature
  const tamperedToken = adminToken ? adminToken.slice(0, -6) + 'xxxxxx' : 'tampered';
  const tamperedRes = await request('GET', '/api/admin/overview', null, { Authorization: 'Bearer ' + tamperedToken });
  log('SEC-A06', 'Auth', 'Access protected endpoint with tampered JWT signature', 401, tamperedRes.status, tamperedRes.status === 401);

  // A07: Sensitive credentials in response
  const rawBody = JSON.stringify(loginRes.data);
  const leaksServiceRole = rawBody.includes('service_role') || rawBody.includes('SUPABASE_SERVICE_ROLE');
  const leaksPassword = rawBody.includes('password_hash') || rawBody.includes('encrypted_password');
  log('SEC-A07', 'Auth', 'No sensitive credentials or service keys leaked in auth response', 'No Leaks', leaksServiceRole || leaksPassword ? 'Leaked' : 'No Leaks', !leaksServiceRole && !leaksPassword);

  // Get tokens for other roles
  const ownerALogin = await request('POST', '/api/auth/verify', { phone: ownerAPhone, token: validOtp });
  const ownerAToken = ownerALogin.data?.accessToken;
  const ownerBLogin = await request('POST', '/api/auth/verify', { phone: ownerBPhone, token: validOtp });
  const ownerBToken = ownerBLogin.data?.accessToken;
  const custALogin = await request('POST', '/api/auth/verify', { phone: customerAPhone, token: validOtp });
  const custAToken = custALogin.data?.accessToken;

  // ==========================================
  // PHASE B & C: RBAC & BACKEND API AUTHORIZATION
  // ==========================================
  console.log('\n--- PHASE B & C: RBAC & Backend API Authorization ---');
  // Admin Overview
  const custAdminOverview = await request('GET', '/api/admin/overview', null, { Authorization: 'Bearer ' + custAToken });
  log('SEC-B01', 'RBAC', 'Customer access GET /api/admin/overview', 403, custAdminOverview.status, custAdminOverview.status === 403);

  const ownerAdminOverview = await request('GET', '/api/admin/overview', null, { Authorization: 'Bearer ' + ownerAToken });
  log('SEC-B02', 'RBAC', 'Owner access GET /api/admin/overview', 403, ownerAdminOverview.status, ownerAdminOverview.status === 403);

  const adminAdminOverview = await request('GET', '/api/admin/overview', null, { Authorization: 'Bearer ' + adminToken });
  log('SEC-B03', 'RBAC', 'Super Admin access GET /api/admin/overview', 200, adminAdminOverview.status, adminAdminOverview.status === 200);

  // Admin Pitch Status Update
  const custPitchStatus = await request('POST', '/api/admin/fields/33/status', { status: 'HOATDONG' }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-B04', 'RBAC', 'Customer access POST /api/admin/fields/:id/status', 403, custPitchStatus.status, custPitchStatus.status === 403);

  const ownerPitchStatus = await request('POST', '/api/admin/fields/33/status', { status: 'HOATDONG' }, { Authorization: 'Bearer ' + ownerAToken });
  log('SEC-B05', 'RBAC', 'Owner access POST /api/admin/fields/:id/status', 403, ownerPitchStatus.status, ownerPitchStatus.status === 403);

  // Admin User Role Update
  const custUserRole = await request('POST', '/api/admin/users/17/role', { role: 'ADMIN' }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-B06', 'RBAC', 'Customer self-elevation POST /api/admin/users/:id/role', 403, custUserRole.status, custUserRole.status === 403);

  const ownerUserRole = await request('POST', '/api/admin/users/17/role', { role: 'ADMIN' }, { Authorization: 'Bearer ' + ownerAToken });
  log('SEC-B07', 'RBAC', 'Owner self-elevation POST /api/admin/users/:id/role', 403, ownerUserRole.status, ownerUserRole.status === 403);

  // Owner Overview
  const unauthOwnerOverview = await request('GET', '/api/owner/overview');
  log('SEC-C01', 'API Auth', 'Unauthenticated access GET /api/owner/overview', 401, unauthOwnerOverview.status, unauthOwnerOverview.status === 401);

  const custOwnerOverview = await request('GET', '/api/owner/overview', null, { Authorization: 'Bearer ' + custAToken });
  log('SEC-C02', 'API Auth', 'Customer access GET /api/owner/overview', 403, custOwnerOverview.status, custOwnerOverview.status === 403);

  const ownerAOverview = await request('GET', '/api/owner/overview', null, { Authorization: 'Bearer ' + ownerAToken });
  const ownerAPitches = ownerAOverview.data?.data?.fields || [];
  const onlyOwnerAPitches = ownerAPitches.every(p => Number(p.masan) === 33);
  log('SEC-C03', 'API Auth', 'Owner A GET /api/owner/overview (returns only own pitches)', '200 (Only pitch 33)', `${ownerAOverview.status} (Count: ${ownerAPitches.length})`, ownerAOverview.status === 200 && onlyOwnerAPitches, `Pitches: ${JSON.stringify(ownerAPitches.map(p=>p.masan))}`);

  // ==========================================
  // PHASE D: RESOURCE OWNERSHIP & IDOR TESTING
  // ==========================================
  console.log('\n--- PHASE D: Resource Ownership & IDOR Testing ---');
  // D01: Check existing bookings
  const adminOverview = adminAdminOverview.data?.data || {};
  const bookings = adminOverview.bookings || [];

  const bookingB = bookings.find(b => Number(b.masan) !== 33);
  const targetBookingId = bookingB ? bookingB.madatsan : 1;

  // Owner A attempts to confirm cash / settle a booking belonging to pitch B (not owned by Owner A)
  const idorSettle = await request('POST', '/api/owner/settle-booking', {
    action: 'CONFIRM_CASH',
    bookingId: targetBookingId
  }, { Authorization: 'Bearer ' + ownerAToken });
  log('SEC-D01', 'IDOR', `Owner A settles booking #${targetBookingId} on non-owned pitch`, 403, idorSettle.status, idorSettle.status === 403, JSON.stringify(idorSettle.data));

  // D02: Customer A queries /api/data for all users
  const custSelectAllUsers = await request('POST', '/api/data', {
    table: 'nguoidung', action: 'select', columns: '*'
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D02', 'IDOR', 'Customer A queries /api/data for all users', 403, custSelectAllUsers.status, custSelectAllUsers.status === 403);

  // D03: Customer A queries /api/data for another user profile (User 25)
  const custSelectOtherUser = await request('POST', '/api/data', {
    table: 'nguoidung', action: 'select', columns: '*', filters: [{ column: 'manguoidung', operator: 'eq', value: 25 }]
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D03', 'IDOR', 'Customer A queries /api/data for other user profile (ID 25)', 403, custSelectOtherUser.status, custSelectOtherUser.status === 403);

  // D04: Customer A queries self profile (ID 17)
  const custSelectSelf = await request('POST', '/api/data', {
    table: 'nguoidung', action: 'select', columns: '*', filters: [{ column: 'manguoidung', operator: 'eq', value: 17 }]
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D04', 'IDOR', 'Customer A queries /api/data for self profile (ID 17)', 200, custSelectSelf.status, custSelectSelf.status === 200);

  // D05: Customer A attempts to select global bookings on /api/data
  const custSelectGlobalBookings = await request('POST', '/api/data', {
    table: 'datsan', action: 'select', columns: '*'
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D05', 'IDOR', 'Customer A attempts to select global bookings on /api/data', 403, custSelectGlobalBookings.status, custSelectGlobalBookings.status === 403);

  // D06: Customer A attempts to update pitch approval status (trangthai) on /api/data
  const custUpdatePitchStatus = await request('POST', '/api/data', {
    table: 'san', action: 'update', values: { trangthai: 'HOATDONG' }, filters: [{ column: 'masan', operator: 'eq', value: 33 }]
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D06', 'IDOR', 'Customer A attempts to update pitch status on /api/data', 403, custUpdatePitchStatus.status, custUpdatePitchStatus.status === 403);

  // D07: Customer A attempts to alter role (vaitro) on /api/data
  const custUpdateRoleData = await request('POST', '/api/data', {
    table: 'nguoidung', action: 'update', values: { vaitro: 'ADMIN' }, filters: [{ column: 'manguoidung', operator: 'eq', value: 17 }]
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-D07', 'IDOR', 'Customer A attempts to alter role to ADMIN via /api/data', 403, custUpdateRoleData.status, custUpdateRoleData.status === 403);

  // ==========================================
  // PHASE E: INPUT VALIDATION & BUSINESS LOGIC
  // ==========================================
  console.log('\n--- PHASE E: Input Validation & Business Logic ---');
  // E01: Query unsupported table via /api/data
  const sqlInjectionTable = await request('POST', '/api/data', {
    table: 'information_schema.tables', action: 'select'
  }, { Authorization: 'Bearer ' + adminToken });
  log('SEC-E01', 'Input', 'Access unsupported/system table via /api/data', 400, sqlInjectionTable.status, sqlInjectionTable.status === 400);

  // E02: Bypass atomic booking by inserting directly to /api/data
  const directBookingInsert = await request('POST', '/api/data', {
    table: 'datsan', action: 'insert', values: { masan: 33, tongtien: 1000 }
  }, { Authorization: 'Bearer ' + custAToken });
  log('SEC-E02', 'Business', 'Bypass atomic booking via direct /api/data insert', 403, directBookingInsert.status, directBookingInsert.status === 403);

  // E03: Invalid role value in role update endpoint
  const invalidRoleUpdate = await request('POST', '/api/admin/users/17/role', {
    role: 'HACKER_ROLE'
  }, { Authorization: 'Bearer ' + adminToken });
  log('SEC-E03', 'Input', 'Set invalid role name via /api/admin/users/:id/role', 400, invalidRoleUpdate.status, invalidRoleUpdate.status === 400);

  // E04: Invalid status value in pitch update endpoint
  const invalidStatusUpdate = await request('POST', '/api/admin/fields/33/status', {
    status: 'DELETED_HACKED'
  }, { Authorization: 'Bearer ' + adminToken });
  log('SEC-E04', 'Input', 'Set invalid pitch status via /api/admin/fields/:id/status', 400, invalidStatusUpdate.status, invalidStatusUpdate.status === 400);

  // E05: Invalid settle action in /api/owner/settle-booking
  const invalidSettleAction = await request('POST', '/api/owner/settle-booking', {
    action: 'FORGE_CREDITS'
  }, { Authorization: 'Bearer ' + ownerAToken });
  log('SEC-E05', 'Business', 'Send forged action to /api/owner/settle-booking', 400, invalidSettleAction.status, invalidSettleAction.status === 400);

  console.log('\n====================================================');
  const passCount = results.filter(r => r.status === 'PASS').length;
  const failCount = results.filter(r => r.status === 'FAIL').length;
  console.log(`TOTAL AUDIT CHECKS: ${results.length} | PASS: ${passCount} | FAIL: ${failCount}`);
  console.log('====================================================\n');
}

runSecurityAudit().catch(console.error);
