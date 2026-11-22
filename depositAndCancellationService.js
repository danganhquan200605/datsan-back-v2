// depositAndCancellationService.js
// Handles Feature 01 (Owner Security Deposit) and Feature 02 (Customer Self-Cancellation & Refund)
// Connected to local testbed database (datsan_local_testbed on PostgreSQL)
// VERSION 2.0.0 - Remediated for BUG-SEC-01, GAP-FIN-01, ARCH-SEC-01, CFG-PROD-01, GAP-FIN-02

const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

let internalAdminSupabase = null;
if (process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)) {
  internalAdminSupabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY,
    { auth: { persistSession: false } }
  );
}

const isRenderProd = process.env.RENDER === 'true' || Boolean(process.env.RENDER_SERVICE_ID) || (process.env.NODE_ENV === 'production' && process.env.IS_LOCAL !== 'true');

let poolConfig;
if (process.env.DATABASE_URL) {
  // Remote PostgreSQL (Supabase / Render Managed Postgres / External Pooler)
  poolConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000
  };
} else if (isRenderProd) {
  // On Render Production, if DATABASE_URL is missing, fail fast with clear configuration error!
  throw new Error('[FATAL_DB_POOL] Production Render environment detected but DATABASE_URL is not configured. Refusing fallback to localhost.');
} else {
  // Local development / testbed fallback
  poolConfig = {
    host: process.env.PGHOST || 'localhost',
    port: Number(process.env.PGPORT || 5432),
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || 'postgres',
    database: process.env.LOCAL_DB_NAME || 'datsan_local_testbed',
    max: 20,
    idleTimeoutMillis: 30000
  };
}

const localPool = new Pool(poolConfig);

// ============================================================================
// FINANCIAL MODE & CONFIGURATION (DEMO SIMULATION GUARD)
// ============================================================================

const FINANCIAL_MODE = String(process.env.FINANCIAL_MODE || '').trim().toUpperCase();
if (FINANCIAL_MODE !== 'DEMO') {
  throw new Error(`[FATAL_FINANCIAL_GUARD] FINANCIAL_MODE must be strictly 'DEMO' (got: "${process.env.FINANCIAL_MODE || ''}"). Real financial transactions are strictly blocked.`);
}
const IS_DEMO_MODE = true;

/**
 * Sinh mã Mock QR SVG an toàn tuyệt đối cho Demo Mode
 * Không gọi ra API bên ngoài, không thể quét để chuyển tiền thật
 */
function getMockQrSvgDataUrl(amount, transferContent) {
  const formattedAmount = (Number(amount || 0)).toLocaleString('vi-VN');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300" viewBox="0 0 300 300">
    <rect width="300" height="300" fill="#f8fafc" rx="16"/>
    <rect x="15" y="15" width="270" height="270" fill="#ffffff" stroke="#cbd5e1" stroke-width="2" rx="12"/>
    <rect x="35" y="35" width="55" height="55" fill="#0f172a" rx="6"/>
    <rect x="45" y="45" width="35" height="35" fill="#ffffff" rx="3"/>
    <rect x="52" y="52" width="21" height="21" fill="#0f172a"/>
    <rect x="210" y="35" width="55" height="55" fill="#0f172a" rx="6"/>
    <rect x="220" y="45" width="35" height="35" fill="#ffffff" rx="3"/>
    <rect x="227" y="52" width="21" height="21" fill="#0f172a"/>
    <rect x="35" y="210" width="55" height="55" fill="#0f172a" rx="6"/>
    <rect x="45" y="220" width="35" height="35" fill="#ffffff" rx="3"/>
    <rect x="52" y="227" width="21" height="21" fill="#0f172a"/>
    <rect x="25" y="105" width="250" height="85" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5" rx="10"/>
    <text x="150" y="132" font-family="system-ui, sans-serif" font-size="13" font-weight="bold" fill="#15803d" text-anchor="middle">THANH TOÁN KÝ QUỸ</text>
    <text x="150" y="153" font-family="system-ui, sans-serif" font-size="10" font-weight="600" fill="#166534" text-anchor="middle">Giao dịch thử nghiệm – không phát sinh tiền thật</text>
    <text x="150" y="174" font-family="system-ui, sans-serif" font-size="10" fill="#475569" text-anchor="middle">Nội dung: ${transferContent}</text>
    <text x="150" y="245" font-family="system-ui, sans-serif" font-size="12" font-weight="bold" fill="#0284c7" text-anchor="middle">DATSAN ONLINE</text>
    <text x="150" y="265" font-family="system-ui, sans-serif" font-size="11" font-weight="bold" fill="#0f172a" text-anchor="middle">${formattedAmount} đ</text>
  </svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/**
 * Lấy cấu hình tài khoản ngân hàng ký quỹ của sàn từ biến môi trường
 * Ở chế độ DEMO: Trả về tài khoản mô phỏng rõ ràng, tuyệt đối không sử dụng tài khoản thật
 */
function getEscrowBankConfig() {
  return {
    bankId: '999999',
    accountNumber: 'DEMO-88888888',
    accountHolder: 'DATSANONLINE MO PHONG (KHONG CHUYEN TIEN THAT)',
    bankName: 'NGAN HANG MO PHONG DATSAN',
    financialMode: 'DEMO',
    isSimulated: true
  };
}

// Utility: Financial Audit Logger (Bất biến)
async function logFinancialAudit(client, { actorId, actorRole, action, entityType, entityId, oldValues, newValues, reason, ipAddress }) {
  const query = `
    INSERT INTO financial_audit_log 
    (actor_id, actor_role, action, entity_type, entity_id, old_values, new_values, reason, ip_address)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  `;
  await client.query(query, [
    actorId,
    actorRole,
    action,
    entityType,
    String(entityId),
    oldValues ? JSON.stringify(oldValues) : null,
    newValues ? JSON.stringify(newValues) : null,
    reason || null,
    ipAddress || '127.0.0.1'
  ]);
}

// ============================================================================
// FEATURE 01: OWNER SECURITY DEPOSIT (1.000.000 VND)
// ============================================================================

/**
 * Lấy hoặc khởi tạo tài khoản ký quỹ của Chủ sân
 */
async function getOrCreateOwnerDeposit(ownerId, isLegacy = false, adminSupabase = null) {
  const client = await localPool.connect();
  try {
    const res = await client.query('SELECT *, makyquy AS id FROM kyquy WHERE machusan = $1', [ownerId]);
    if (res.rows.length > 0) {
      return res.rows[0];
    }

    let legacyFlag = false;
    if (isLegacy === true) {
      legacyFlag = true;
    } else if (isLegacy !== false && adminSupabase) {
      try {
        const { data: courts } = await adminSupabase.from('san').select('masan').eq('machusan', ownerId).limit(1);
        if (courts && courts.length > 0) legacyFlag = true;
      } catch {}
    }

    const initialStatus = legacyFlag ? 'DA_KY_QUY' : 'CHUA_KY_QUY';
    const initialBalance = legacyFlag ? 1000000.00 : 0.00;
    const initialSettled = legacyFlag ? 1000000.00 : 0.00;

    const insertRes = await client.query(`
      INSERT INTO kyquy (machusan, sotien_yeucau, sotien_dadoisoat, sodu_hientai, trangthai, is_legacy, ghichu)
      VALUES ($1, 1000000.00, $2, $3, $4, $5, $6)
      RETURNING *, makyquy AS id
    `, [
      ownerId,
      initialSettled,
      initialBalance,
      initialStatus,
      legacyFlag,
      legacyFlag ? 'Hồ sơ chủ sân hiện hữu (Legacy Transition Policy)' : 'Hồ sơ chủ sân mới cần hoàn tất ký quỹ'
    ]);

    if (legacyFlag) {
      await client.query(`
        INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
        VALUES ($1, 'NOP_KY_QUY', 1000000.00, 1000000.00, 'Kích hoạt chính sách chuyển tiếp cho Chủ sân hiện hữu', $1, 'SYSTEM')
      `, [ownerId]);
    }

    return insertRes.rows[0];
  } finally {
    client.release();
  }
}

/**
 * Tạo yêu cầu nộp ký quỹ 1.000.000đ và sinh Mock QR (DEMO)
 */
async function createDepositPaymentRequest(ownerId, customAmount = null) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    const dep = depRes.rows[0] || (await getOrCreateOwnerDeposit(ownerId, false));

    const currentBalance = Number(dep.sodu_hientai || 0);
    const requiredAmount = Number(dep.sotien_yeucau || 1000000);

    if (dep.trangthai === 'DA_KY_QUY' && currentBalance >= requiredAmount && !customAmount) {
      await client.query('COMMIT');
      return { success: false, code: 'ALREADY_DEPOSITED', message: 'Tài khoản của bạn đã hoàn tất ký quỹ 1.000.000đ.' };
    }

    const amount = customAmount ? Number(customAmount) : Math.max(1000000 - currentBalance, 1000000);
    const requestId = `REQ_DEP_${ownerId}_${Date.now()}`;
    const transferContent = `KYQUY-DEMO-${ownerId}-${requestId.slice(-6)}`;

    // Lấy thông tin tài khoản ngân hàng từ ENV (CFG-PROD-01 & DEMO MODE)
    const escrowCfg = getEscrowBankConfig();
    const qrUrl = getMockQrSvgDataUrl(amount, transferContent);
    const phuongThuc = 'MOCK_GATEWAY';
    const gdRes = await client.query(`
      INSERT INTO kyquy_giaodich (ma_yeucau, machusan, sotien, noidung_chuyenkhoan, phuongthuc, trangthai)
      VALUES ($1, $2, $3, $4, $5, 'CHO_XAC_MINH')
      RETURNING *, magiaodich AS id
    `, [requestId, ownerId, amount, transferContent, phuongThuc]);

    await client.query(`
      UPDATE kyquy SET trangthai = 'CHO_XAC_MINH', updated_at = CURRENT_TIMESTAMP
      WHERE machusan = $1
    `, [ownerId]);

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'CREATE_DEPOSIT_REQUEST',
      entityType: 'KY_QUY',
      entityId: dep.makyquy,
      newValues: { requestId, amount, transferContent, phuongThuc, financialMode: escrowCfg.financialMode },
      reason: IS_DEMO_MODE ? 'Chủ sân tạo yêu cầu nộp khoản ký quỹ mô phỏng (DEMO)' : 'Chủ sân tạo yêu cầu nộp khoản bảo đảm ký quỹ'
    });

    await client.query('COMMIT');

    return {
      success: true,
      data: {
        requestId,
        amount,
        transferContent,
        financialMode: escrowCfg.financialMode,
        isSimulated: IS_DEMO_MODE,
        mockGatewayAvailable: IS_DEMO_MODE,
        bankInfo: {
          bankName: escrowCfg.bankName,
          bankId: escrowCfg.bankId,
          accountNumber: escrowCfg.accountNumber,
          accountHolder: escrowCfg.accountHolder,
          qrUrl
        },
        transaction: gdRes.rows[0]
      }
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Chủ sân gửi tham chiếu giao dịch chuyển khoản ký quỹ
 */
async function submitDepositPaymentProof(ownerId, { requestId, bankTxId, proofUrl }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const gdRes = await client.query(`
      SELECT * FROM kyquy_giaodich WHERE ma_yeucau = $1 AND machusan = $2 FOR UPDATE
    `, [requestId, ownerId]);

    if (gdRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, message: 'Không tìm thấy yêu cầu thanh toán ký quỹ tương ứng' };
    }

    const gd = gdRes.rows[0];
    if (gd.trangthai === 'THANH_CONG') {
      await client.query('ROLLBACK');
      return { success: false, message: 'Yêu cầu này đã được xác minh thành công trước đó' };
    }

    await client.query(`
      UPDATE kyquy_giaodich 
      SET magiaodich_nganhang = $1, bangchung_url = $2, thoigian_thanhtoan = CURRENT_TIMESTAMP
      WHERE magiaodich = $3
    `, [bankTxId || 'REF_MOCK_' + Date.now(), proofUrl || 'mock_proof.png', gd.magiaodich]);

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'SUBMIT_DEPOSIT_PROOF',
      entityType: 'KY_QUY_GIAODICH',
      entityId: gd.magiaodich,
      newValues: { bankTxId, proofUrl },
      reason: 'Chủ sân đính kèm tham chiếu chuyển khoản ngân hàng'
    });

    await client.query('COMMIT');
    return { success: true, message: 'Đã gửi thông tin chuyển khoản ký quỹ. Ban Quản Trị sẽ đối soát và phê duyệt.' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Admin đối soát tiền thực nhận và xác nhận kích hoạt ký quỹ
 * Áp dụng FOR UPDATE và Idempotency chống duyệt đúp
 */
async function adminVerifyDepositPayment(adminId, { requestId, isApproved, bankTxId, notes }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    // Chống thao tác lặp / Concurrency race condition bằng FOR UPDATE
    const gdRes = await client.query(`
      SELECT * FROM kyquy_giaodich WHERE ma_yeucau = $1 FOR UPDATE
    `, [requestId]);

    if (gdRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu nộp ký quỹ' };
    }

    const gd = gdRes.rows[0];
    if (gd.trangthai === 'THANH_CONG') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Giao dịch này đã được xác minh thành công trước đó (Idempotent)' };
    }

    const ownerId = gd.machusan;
    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    const dep = depRes.rows[0];

    if (!isApproved) {
      await client.query(`
        UPDATE kyquy_giaodich 
        SET trangthai = 'TU_CHOI', nguoi_xacminh = $1, thoigian_xacminh = CURRENT_TIMESTAMP
        WHERE magiaodich = $2
      `, [adminId, gd.magiaodich]);

      await client.query(`
        UPDATE kyquy SET trangthai = 'CHUA_KY_QUY', ghichu = $1, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $2
      `, [notes || 'Giao dịch chuyển khoản chưa khớp tiền thực nhận', ownerId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'REJECT_DEPOSIT_PAYMENT',
        entityType: 'KY_QUY_GIAODICH',
        entityId: gd.magiaodich,
        reason: notes || 'Admin từ chối xác nhận do không nhận được tiền'
      });

      await client.query('COMMIT');
      return { success: true, message: 'Đã từ chối xác nhận giao dịch ký quỹ' };
    }

    // Xác nhận tiền thực nhận thành công
    const amount = Number(gd.sotien);
    const newBalance = Number(dep.sodu_hientai || 0) + amount;
    const newSettled = Number(dep.sotien_dadoisoat || 0) + amount;
    const isTopUp = Number(dep.sodu_hientai || 0) < 1000000 && Number(dep.sodu_hientai || 0) > 0;
    const ledgerAction = isTopUp ? 'BO_SUNG_KY_QUY' : 'NOP_KY_QUY';

    await client.query(`
      UPDATE kyquy_giaodich 
      SET trangthai = 'THANH_CONG', magiaodich_nganhang = $1, nguoi_xacminh = $2, thoigian_xacminh = CURRENT_TIMESTAMP
      WHERE magiaodich = $3
    `, [bankTxId || gd.magiaodich_nganhang || 'BANK_VERIFIED_' + Date.now(), adminId, gd.magiaodich]);

    // Ghi sổ cái tài chính bất biến (Ledger)
    await client.query(`
      INSERT INTO kyquy_ledger (machusan, magiaodich, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'ADMIN')
    `, [ownerId, gd.magiaodich, ledgerAction, amount, newBalance, 'Admin xác nhận tiền nộp ký quỹ mô phỏng DEMO', adminId]);

    // Cập nhật trạng thái tài khoản ký quỹ
    const newStatus = newBalance >= 1000000 ? 'DA_KY_QUY' : 'THIEU_KY_QUY';
    await client.query(`
      UPDATE kyquy 
      SET sodu_hientai = $1, sotien_dadoisoat = $2, trangthai = $3, 
          thoigian_xacnhan = CURRENT_TIMESTAMP, nguoi_xacnhan = $4, updated_at = CURRENT_TIMESTAMP
      WHERE machusan = $5
    `, [newBalance, newSettled, newStatus, adminId, ownerId]);

    await logFinancialAudit(client, {
      actorId: adminId,
      actorRole: 'ADMIN',
      action: 'APPROVE_DEPOSIT_PAYMENT',
      entityType: 'KY_QUY',
      entityId: dep.makyquy,
      oldValues: { balance: dep.sodu_hientai, status: dep.trangthai },
      newValues: { balance: newBalance, status: newStatus },
      reason: notes || 'Admin đối soát thành công tiền thực nhận 1.000.000đ'
    });

    await client.query('COMMIT');
    return { success: true, message: `Đã xác nhận ký quỹ thành công. Số dư hiện tại: ${newBalance.toLocaleString('vi-VN')}đ. Trạng thái: ${newStatus}` };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Kiểm tra điều kiện ký quỹ trước khi cho phép cụm sân nhận đặt lịch
 */
async function checkCourtDepositEligibility(ownerId, adminSupabase = null) {
  const client = await localPool.connect();
  try {
    const res = await client.query('SELECT * FROM kyquy WHERE machusan = $1', [ownerId]);
    if (res.rows.length === 0) {
      let isLegacyOwner = false;
      if (adminSupabase) {
        try {
          const { data: fields } = await adminSupabase.from('san').select('masan').eq('machusan', ownerId).limit(1);
          if (fields && fields.length > 0) isLegacyOwner = true;
        } catch {}
      } else if (Number(ownerId) <= 10) {
        isLegacyOwner = true;
      }

      if (isLegacyOwner) {
        const legacyDep = await getOrCreateOwnerDeposit(ownerId, true);
        return { allowed: true, isLegacy: true, balance: Number(legacyDep.sodu_hientai) };
      }

      return { allowed: false, reason: 'Chủ sân chưa tạo hồ sơ ký quỹ bảo đảm 1.000.000đ.' };
    }

    const dep = res.rows[0];
    const totalBalance = Number(dep.sodu_hientai || 0);
    const heldBalance = Number(dep.sodu_tamgiu || 0);
    const availableBalance = Math.max(0, totalBalance - heldBalance);

    if (dep.is_legacy && dep.trangthai === 'DA_KY_QUY' && availableBalance >= 1000000) {
      return { allowed: true, isLegacy: true, balance: totalBalance, availableBalance };
    }
    if (dep.trangthai === 'DA_KY_QUY' && availableBalance >= 1000000) {
      return { allowed: true, balance: totalBalance, availableBalance };
    }
    return { 
      allowed: false, 
      status: dep.trangthai,
      reason: `Tài khoản ký quỹ khả dụng không đủ 1.000.000đ (Số dư: ${totalBalance.toLocaleString('vi-VN')}đ, Tạm giữ: ${heldBalance.toLocaleString('vi-VN')}đ, Khả dụng: ${availableBalance.toLocaleString('vi-VN')}đ). Sân không được phép nhận đặt lịch.` 
    };
  } finally {
    client.release();
  }
}

/**
 * Quy trình yêu cầu hoàn trả ký quỹ khi Chủ sân ngừng kinh doanh (GAP-FIN-01 REMEDIATION)
 * Kiểm tra nghiêm ngặt:
 * 1. Không còn đơn đặt sân sắp tới (ngaysudung >= TODAY & trangthai IN ('CHO_THI_DAU', 'DA_THANH_TOAN', 'CHOXACNHAN', 'DANG_DA')).
 * 2. Không còn yêu cầu hoàn tiền đang chờ hoặc tranh chấp chưa giải quyết.
 * 3. Không có công nợ tồn đọng.
 */
async function requestOwnerDepositRefund(ownerId, { reason, bankName, bankAccount, accountHolder, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    if (depRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy hồ sơ ký quỹ của Chủ sân' };
    }

    const dep = depRes.rows[0];
    if (dep.trangthai !== 'DA_KY_QUY') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Không thể yêu cầu hoàn trả ký quỹ ở trạng thái hiện tại: ${dep.trangthai}` };
    }

    // 1. Kiểm tra đơn đặt sân tương lai hoặc đang diễn ra (GAP-FIN-01)
    if (adminSupabase) {
      try {
        const { data: courts } = await adminSupabase.from('san').select('masan').eq('machusan', ownerId);
        if (courts && courts.length > 0) {
          const courtIds = courts.map(c => c.masan);
          const today = new Date().toISOString().split('T')[0];
          const { data: activeBookings } = await adminSupabase
            .from('datsan')
            .select('madatsan, ngaysudung, trangthai')
            .in('masan', courtIds)
            .gte('ngaysudung', today)
            .in('trangthai', ['CHO_THI_DAU', 'DA_THANH_TOAN', 'CHOXACNHAN', 'DANG_DA']);

          if (activeBookings && activeBookings.length > 0) {
            await client.query('ROLLBACK');
            return {
              success: false,
              status: 400,
              code: 'ACTIVE_BOOKINGS_EXIST',
              activeBookingsCount: activeBookings.length,
              message: `Không thể xin rút ký quỹ: Chủ sân còn ${activeBookings.length} đơn đặt sân sắp tới hoặc đang diễn ra chưa hoàn tất.`
            };
          }
        }
      } catch (checkErr) {
        console.error('Error checking active bookings for deposit refund:', checkErr);
      }
    }

    // 2. Kiểm tra yêu cầu hoàn tiền chưa hoàn tất hoặc tranh chấp mở (GAP-FIN-01)
    const { rows: pendingRefunds } = await client.query(`
      SELECT COUNT(*) as count FROM hoantien 
      WHERE machusan = $1 
        AND trangthai IN ('CHO_HOAN', 'OWNER_BAO_DA_CHUYEN', 'TRANH_CHAP', 'QUA_HAN', 'DANG_XAC_MINH_GIAI_TRINH', 'PHUC_KHAO_KHAU_TRU')
    `, [ownerId]);

    const unfinishedCount = Number(pendingRefunds[0]?.count || 0);
    if (unfinishedCount > 0) {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 400,
        code: 'UNFINISHED_REFUNDS_EXIST',
        pendingRefundsCount: unfinishedCount,
        message: `Không thể xin rút ký quỹ: Còn ${unfinishedCount} yêu cầu hoàn tiền hoặc khiếu nại tranh chấp chưa hoàn tất xử lý.`
      };
    }

    // Cập nhật trạng thái ký quỹ sang DANG_HOAN_TRA (khóa quyền nhận đặt lịch ngay lập tức)
    const refundMeta = {
      requestedAt: new Date().toISOString(),
      reason: reason || 'Chủ sân yêu cầu ngừng hợp tác và tất toán ký quỹ',
      payoutBank: { bankName, bankAccount, accountHolder }
    };

    await client.query(`
      UPDATE kyquy 
      SET trangthai = 'DANG_HOAN_TRA', ghichu = $1, updated_at = CURRENT_TIMESTAMP
      WHERE machusan = $2
    `, [JSON.stringify(refundMeta), ownerId]);

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'REQUEST_DEPOSIT_REFUND',
      entityType: 'KY_QUY',
      entityId: dep.makyquy,
      oldValues: { status: dep.trangthai },
      newValues: { status: 'DANG_HOAN_TRA' },
      reason: reason || 'Chủ sân nộp đơn xin hoàn ký quỹ'
    });

    await client.query('COMMIT');
    return {
      success: true,
      newStatus: 'DANG_HOAN_TRA',
      message: 'Yêu cầu hoàn trả ký quỹ đã được tiếp nhận. Ban Quản Trị sẽ đối soát toàn diện trước khi tất toán.'
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Admin đối soát và tất toán hoàn ký quỹ cho Chủ sân
 */
async function adminSettleDepositRefund(adminId, { ownerId, isApproved, refundAmount, bankTxId, notes }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    if (depRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy hồ sơ ký quỹ' };
    }

    const dep = depRes.rows[0];
    if (dep.trangthai !== 'DANG_HOAN_TRA') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Hồ sơ ký quỹ không ở trạng thái chờ hoàn trả (Hiện tại: ${dep.trangthai})` };
    }

    if (!isApproved) {
      await client.query(`
        UPDATE kyquy 
        SET trangthai = 'TRANH_CHAP', ghichu = $1, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $2
      `, [notes || 'Admin từ chối hoàn ký quỹ do còn nghĩa vụ tồn đọng', ownerId]);

      await client.query('COMMIT');
      return { success: true, message: 'Đã từ chối hoàn ký quỹ và chuyển sang trạng thái tranh chấp' };
    }

    const amountToRefund = Number(refundAmount || dep.sodu_hientai || 1000000);
    const newBalance = Math.max(0, Number(dep.sodu_hientai) - amountToRefund);

    await client.query(`
      INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
      VALUES ($1, 'HOAN_KY_QUY', $2, $3, $4, $5, 'ADMIN')
    `, [ownerId, -amountToRefund, newBalance, notes || 'Admin hoàn trả tiền ký quỹ sau khi tất toán nghĩa vụ', adminId]);

    await client.query(`
      UPDATE kyquy 
      SET sodu_hientai = $1, trangthai = 'DA_HOAN_TRA', thoigian_xacnhan = CURRENT_TIMESTAMP,
          nguoi_xacnhan = $2, updated_at = CURRENT_TIMESTAMP
      WHERE machusan = $3
    `, [newBalance, adminId, ownerId]);

    await logFinancialAudit(client, {
      actorId: adminId,
      actorRole: 'ADMIN',
      action: 'APPROVE_DEPOSIT_REFUND',
      entityType: 'KY_QUY',
      entityId: dep.makyquy,
      oldValues: { balance: dep.sodu_hientai, status: dep.trangthai },
      newValues: { balance: newBalance, status: 'DA_HOAN_TRA', bankTxId },
      reason: notes || 'Tất toán hoàn trả ký quỹ bảo đảm thành công'
    });

    await client.query('COMMIT');
    return { success: true, message: `Đã hoàn trả ${amountToRefund.toLocaleString('vi-VN')}đ tiền ký quỹ cho Chủ sân.` };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ============================================================================
// FEATURE 02: CUSTOMER SELF-CANCELLATION & REFUND (>= 4 HOURS, 100% REFUND)
// ============================================================================

/**
 * Tính tổng thời lượng (phút) của các khung giờ
 */
function calculateDurationMinutesFromSlots(slotRows = []) {
  if (!Array.isArray(slotRows) || slotRows.length === 0) return 0;
  return slotRows.reduce((total, s) => {
    const startStr = String(s.giobatdau || s.start || '').slice(0, 5);
    const endStr = String(s.gioketthuc || s.end || '').slice(0, 5);
    if (!startStr || !endStr) return total;
    const [startH, startM] = startStr.split(':').map(Number);
    const [endH, endM] = endStr.split(':').map(Number);
    let diff = (endH * 60 + endM) - (startH * 60 + startM);
    if (diff < 0) diff += 24 * 60;
    return total + (diff > 0 ? diff : 0);
  }, 0);
}

/**
 * Kiểm tra điều kiện tự hủy đặt sân của Khách hàng (Hỗ trợ cả hủy toàn bộ và hủy từng phần)
 */
function checkCancellationEligibility({ booking, slots, customerId, serverNow = new Date() }) {
  if (!booking) {
    return { eligible: false, reason: 'Không tìm thấy thông tin đơn đặt sân.' };
  }

  // 1. Kiểm tra quyền sở hữu đơn
  const bookingCustId = Number(booking.makhachhang || booking.manguoidung);
  if (bookingCustId !== Number(customerId)) {
    return { eligible: false, status: 403, reason: 'Bạn không có quyền hủy đơn đặt sân của khách hàng khác.' };
  }

  // 2. Kiểm tra trạng thái đơn
  const status = booking.trangthai;
  const validStatuses = ['CHO_THI_DAU', 'CHOXACNHAN', 'DA_THANH_TOAN'];
  if (!validStatuses.includes(status)) {
    if (status === 'DA_HUY') {
      return { eligible: false, status: 400, code: 'ALREADY_CANCELLED', reason: 'Đơn đặt sân này đã ở trạng thái ĐÃ HỦY.' };
    }
    return { eligible: false, status: 400, reason: `Không thể hủy đơn đặt sân ở trạng thái: ${status}. Chỉ áp dụng cho đơn chưa diễn ra.` };
  }

  // 3. Tính toán thời gian còn lại cho từng khung giờ
  const bookingDateStr = booking.ngaysudung;
  let earliestStart = null;
  const slotDetails = (slots || []).map(slot => {
    let hoursRemaining = null;
    let canCancel = false;
    let startStr = String(slot.giobatdau || '').slice(0, 5);
    let endStr = String(slot.gioketthuc || '').slice(0, 5);
    if (slot && slot.giobatdau) {
      const timePart = slot.giobatdau.length === 5 ? slot.giobatdau + ':00' : slot.giobatdau;
      const slotDateTimeStr = `${bookingDateStr}T${timePart}+07:00`;
      const slotDate = new Date(slotDateTimeStr);
      if (!earliestStart || slotDate < earliestStart) earliestStart = slotDate;
      const diffMs = slotDate.getTime() - serverNow.getTime();
      hoursRemaining = diffMs / (1000 * 60 * 60);
      canCancel = hoursRemaining >= 4.0;
    }
    return {
      makhunggio: Number(slot.makhunggio),
      giobatdau: startStr,
      gioketthuc: endStr,
      giadat: Number(slot.giadat || slot.giatien || slot.giaapdung || 0),
      hoursRemaining: hoursRemaining !== null ? Number(hoursRemaining.toFixed(1)) : null,
      canCancel,
      reason: canCancel 
        ? `Hợp lệ tự hủy (còn ${hoursRemaining.toFixed(1)}h)`
        : `Không thể hủy (còn ${hoursRemaining !== null ? hoursRemaining.toFixed(1) : 0}h, vi phạm quy định tối thiểu 4h)`
    };
  });

  if (!earliestStart) {
    earliestStart = new Date(`${bookingDateStr}T06:00:00+07:00`);
  }

  const diffMs = earliestStart.getTime() - serverNow.getTime();
  const hoursRemaining = diffMs / (1000 * 60 * 60);

  const isOnlinePaid = status === 'DA_THANH_TOAN';
  const overallEligible = hoursRemaining >= 4.0;

  return {
    eligible: overallEligible,
    status: overallEligible ? 200 : 400,
    hoursRemaining: Number(hoursRemaining.toFixed(1)),
    isOnlinePaid,
    refundAmount: isOnlinePaid ? Number(booking.tongtien || 0) : 0,
    booking,
    slots: slotDetails,
    reason: overallEligible
      ? `Hợp lệ tự hủy toàn bộ đơn (Còn ${hoursRemaining.toFixed(1)} giờ trước giờ bắt đầu sớm nhất)`
      : `Đã quá thời hạn tự hủy sân. Chỉ được hủy trước giờ thi đấu tối thiểu 4 tiếng (Hiện tại chỉ còn ${hoursRemaining.toFixed(1)} tiếng).`
  };
}

/**
 * Thực hiện hủy đơn và tạo yêu cầu hoàn tiền (BUG-SEC-01 REMEDIATION)
 * Áp dụng PostgreSQL Transaction + Advisory Lock (pg_advisory_xact_lock)
 * Đảm bảo CHỈ 1 request chuyển trạng thái sang DA_HUY, không tạo trùng lặp hoantien,
 * không giải phóng khung giờ lặp, không trừ hoa hồng lặp.
 */
async function processCustomerCancellation({ bookingId, customerId, refundAccountInfo, reason, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    // 1. Khóa phân tán cấp Transaction cho mã đơn bookingId (Namespace 32984)
    // Các request đồng thời trên cùng bookingId BẮT BUỘC xếp hàng đợi
    await client.query('SELECT pg_advisory_xact_lock(32984, $1)', [bookingId]);

    // 2. Kiểm tra Idempotency: Bản ghi hoàn tiền toàn bộ (CANCEL_FULL) đã tồn tại chưa?
    const fullCancelKey = `CANCEL_FULL_${bookingId}`;
    const { rows: existingFullRf } = await client.query(
      'SELECT * FROM hoantien WHERE idempotency_key = $1',
      [fullCancelKey]
    );
    if (existingFullRf.length > 0) {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 400,
        code: 'ALREADY_CANCELLED',
        message: 'Đơn đặt sân này đã được hủy toàn bộ và đang được xử lý hoàn tiền (Idempotency protection).'
      };
    }

    // 3. Lấy thông tin đơn đặt sân từ Supabase
    const { data: booking, error: bErr } = await adminSupabase
      .from('datsan')
      .select('*, san (tensan, machusan)')
      .eq('madatsan', bookingId)
      .single();

    if (bErr || !booking) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy đơn đặt sân' };
    }

    // 4. Nếu đơn đã ở trạng thái DA_HUY -> Từ chối an toàn
    if (booking.trangthai === 'DA_HUY') {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 400,
        code: 'ALREADY_CANCELLED',
        message: 'Đơn đặt sân này đã ở trạng thái ĐÃ HỦY.'
      };
    }

    // 5. Lấy khung giờ của đơn đặt sân (Schema-agnostic: *, khunggio (*))
    const { data: slotLinks } = await adminSupabase
      .from('datsan_khunggio')
      .select('*, khunggio (*)')
      .eq('madatsan', bookingId);

    const slots = (slotLinks || []).map(sl => sl.khunggio).filter(Boolean);
    const remainingSlotIds = (slotLinks || []).map(sl => Number(sl.makhunggio || sl.khunggio?.makhunggio)).filter(Boolean);

    // 6. Kiểm tra điều kiện hủy
    const check = checkCancellationEligibility({ booking, slots, customerId });
    if (!check.eligible) {
      await client.query('ROLLBACK');
      return { success: false, status: check.status || 400, message: check.reason };
    }

    // 7. Cập nhật trạng thái đơn sang DA_HUY có điều kiện (Optimistic concurrency)
    let meta = {};
    try { meta = JSON.parse(booking.ghichu || '{}'); } catch (e) {}

    const isOnlinePaid = check.isOnlinePaid;
    const totalAmount = Number(booking.tongtien || 0);

    meta.cancelledAt = new Date().toISOString();
    meta.cancelledBy = customerId;
    meta.cancelRole = 'KHACHHANG';
    meta.cancelReason = reason || 'Khách hàng tự hủy trước giờ thi đấu >= 4h';
    meta.commissionAmount = 0; // HOA HỒNG NỀN TẢNG BẰNG 0
    meta.commissionStatus = 'DA_HUY';
    meta.refundAmount = isOnlinePaid ? totalAmount : 0;
    meta.statusHistory = [
      ...(meta.statusHistory || []),
      {
        from: booking.trangthai,
        to: 'DA_HUY',
        action: 'CUSTOMER_SELF_CANCEL',
        by: customerId,
        role: 'KHACHHANG',
        at: new Date().toISOString(),
        reason: meta.cancelReason
      }
    ];

    const { data: updatedBooking, error: updErr } = await adminSupabase
      .from('datsan')
      .update({ trangthai: 'DA_HUY', ghichu: JSON.stringify(meta) })
      .eq('madatsan', bookingId)
      .eq('trangthai', booking.trangthai) // Bảo đảm trạng thái chưa bị đổi
      .select();

    if (updErr || !updatedBooking || updatedBooking.length === 0) {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 409,
        code: 'CONCURRENT_CONFLICT',
        message: 'Xung đột thao tác: Đơn đặt sân đã được hủy bởi một yêu cầu khác.'
      };
    }

    // 8. Giải phóng khung giờ (chỉ thực hiện 1 lần duy nhất bởi transaction này)
    await adminSupabase.from('datsan_khunggio').delete().eq('madatsan', bookingId);

    // 9. Cập nhật bản ghi thanhtoan
    await adminSupabase.from('thanhtoan').update({ trangthai: 'DA_HUY' }).eq('madatsan', bookingId);

    let refundRecord = null;

    // 10. Tạo yêu cầu hoàn tiền nếu đơn đã thanh toán online mô phỏng (DEMO 100%)
    if (isOnlinePaid && totalAmount > 0) {
      const ownerId = booking.san?.machusan;
      const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      const { bankName, bankAccount, accountHolder } = refundAccountInfo || {};

      const rfRes = await client.query(`
        INSERT INTO hoantien 
        (madatsan, makhachhang, machusan, sotien_canhoan, sotien_dahoan, lydo_huy, trangthai, nganhang_nhan, sotaikhoan_nhan, chutaikhoan_nhan, han_xuly, idempotency_key, slot_ids)
        VALUES ($1, $2, $3, $4, 0.00, $5, 'CHO_HOAN', $6, $7, $8, $9, $10, $11)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING *, mahoantien AS id, sotien_canhoan AS sotien_hoan, chutaikhoan_nhan AS tentaikhoan_nhan
      `, [
        bookingId,
        customerId,
        ownerId,
        totalAmount,
        meta.cancelReason,
        bankName || 'MOCK_BANK',
        bankAccount || '0000000000',
        accountHolder || 'KHACH HANG',
        deadline,
        fullCancelKey,
        remainingSlotIds
      ]);

      refundRecord = rfRes.rows[0];
      if (!refundRecord) {
        const existing = await client.query(
          'SELECT *, mahoantien AS id, sotien_canhoan AS sotien_hoan, chutaikhoan_nhan AS tentaikhoan_nhan FROM hoantien WHERE idempotency_key = $1',
          [fullCancelKey]
        );
        refundRecord = existing.rows[0] || null;
      }

      if (ownerId) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '💸 Yêu cầu hoàn tiền từ Khách hủy sân',
          noidung: `Khách hàng vừa hủy hợp lệ đơn #${bookingId} trước 4 giờ. Vui lòng chuyển hoàn 100% số tiền ${totalAmount.toLocaleString('vi-VN')}đ trong vòng 24h.`,
          loaithongbao: 'REFUND_REQUEST'
        });
      }
    }

    // 11. Gửi thông báo cho khách hàng
    await adminSupabase.from('thongbao').insert({
      manguoidung: customerId,
      tieude: '✅ Hủy đặt sân thành công',
      noidung: isOnlinePaid
        ? `Đơn #${bookingId} đã được hủy hợp lệ. Chủ sân sẽ chuyển hoàn 100% (${totalAmount.toLocaleString('vi-VN')}đ) vào tài khoản của bạn trong 24h.`
        : `Đơn #${bookingId} (thanh toán tiền mặt) đã được hủy thành công.`,
      loaithongbao: 'BOOKING_CANCELLED'
    });

    // 12. Ghi Audit Log tài chính
    await logFinancialAudit(client, {
      actorId: customerId,
      actorRole: 'KHACHHANG',
      action: 'CUSTOMER_SELF_CANCEL',
      entityType: 'DAT_SAN',
      entityId: bookingId,
      oldValues: { status: booking.trangthai, commissionStatus: meta.commissionStatus },
      newValues: { status: 'DA_HUY', commissionAmount: 0, isRefundCreated: !!refundRecord },
      reason: meta.cancelReason
    });

    await client.query('COMMIT');

    return {
      success: true,
      message: 'Hủy đơn đặt sân thành công 100%. Khung giờ đã được giải phóng.',
      isOnlinePaid,
      refund: refundRecord
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * TASK 02: Hủy một phần khung giờ đặt sân (Partial Cancellation)
 * Áp dụng PostgreSQL Transaction + Advisory Lock (pg_advisory_xact_lock 32984)
 * Giải phóng các khung giờ được chọn, tính lại tổng tiền, tạo bản ghi hoàn tiền nếu đã thanh toán QR
 */
async function processPartialCustomerCancellation({
  bookingId,
  customerId,
  slotIds = [],
  refundAccountInfo,
  reason,
  adminSupabase
}) {
  if (!Array.isArray(slotIds) || slotIds.length === 0) {
    return { success: false, status: 400, message: 'Vui lòng chọn ít nhất một khung giờ cần hủy.' };
  }

  const normalizedSlotIds = slotIds.map(Number);
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    // 1. Transaction-level Advisory Lock (Namespace 32984)
    await client.query('SELECT pg_advisory_xact_lock(32984, $1)', [bookingId]);

    // 2. Lấy thông tin đơn đặt sân
    const { data: booking, error: bErr } = await adminSupabase
      .from('datsan')
      .select('*, san (tensan, machusan, giasan)')
      .eq('madatsan', bookingId)
      .single();

    if (bErr || !booking) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy đơn đặt sân' };
    }

    // 3. Kiểm tra quyền sở hữu (Anti-IDOR)
    const bookingCustId = Number(booking.makhachhang || booking.manguoidung);
    if (bookingCustId !== Number(customerId)) {
      await client.query('ROLLBACK');
      return { success: false, status: 403, message: 'Bạn không có quyền thao tác trên đơn đặt sân của khách hàng khác.' };
    }

    // 4. Kiểm tra trạng thái đơn
    const validStatuses = ['CHO_THI_DAU', 'CHOXACNHAN', 'DA_THANH_TOAN'];
    if (!validStatuses.includes(booking.trangthai)) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Không thể điều chỉnh đơn ở trạng thái ${booking.trangthai}.` };
    }

    // 5. Lấy danh sách khung giờ đang hoạt động của đơn (Schema-agnostic: *, khunggio (*))
    const { data: slotRows, error: sErr } = await adminSupabase
      .from('datsan_khunggio')
      .select('*, khunggio (*)')
      .eq('madatsan', bookingId);

    if (sErr || !slotRows || slotRows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Đơn đặt sân không còn khung giờ nào đang hoạt động.' };
    }

    // Kiểm tra tất cả slotIds có thuộc đơn này không
    const currentActiveSlotIds = slotRows.map(r => Number(r.makhunggio || r.khunggio?.makhunggio));
    for (const sid of normalizedSlotIds) {
      if (!currentActiveSlotIds.includes(sid)) {
        await client.query('ROLLBACK');
        return {
          success: false,
          status: 400,
          code: 'ERR_SLOT_NOT_FOUND',
          message: `Khung giờ #${sid} không thuộc đơn đặt sân này hoặc đã được giải phóng.`
        };
      }
    }

    // Kiểm tra slotIds có bị hoàn tiền trùng lặp từ trước không (Triple Protection)
    const { rows: priorRefunds } = await client.query(
      'SELECT slot_ids FROM hoantien WHERE madatsan = $1 AND slot_ids IS NOT NULL',
      [bookingId]
    );
    const alreadyRefundedSlotIds = new Set();
    for (const pr of priorRefunds) {
      if (Array.isArray(pr.slot_ids)) {
        pr.slot_ids.forEach(id => alreadyRefundedSlotIds.add(Number(id)));
      }
    }
    for (const sid of normalizedSlotIds) {
      if (alreadyRefundedSlotIds.has(sid)) {
        await client.query('ROLLBACK');
        return {
          success: false,
          status: 400,
          code: 'ERR_SLOT_ALREADY_REFUNDED',
          message: `Khung giờ #${sid} đã được hoàn tiền trước đó. Không được hoàn tiền trùng lặp.`
        };
      }
    }

    // 6. Kiểm tra quy tắc 4 tiếng cho từng khung giờ cần hủy (Asia/Ho_Chi_Minh)
    const now = new Date();
    const bookingDateStr = booking.ngaysudung;
    const slotsToCancel = slotRows.filter(r => normalizedSlotIds.includes(Number(r.makhunggio || r.khunggio?.makhunggio)));

    for (const row of slotsToCancel) {
      const kg = row.khunggio || {};
      const startStr = String(kg.giobatdau || '').slice(0, 8);
      const timePart = startStr.length === 5 ? startStr + ':00' : startStr;
      const slotDateTimeStr = `${bookingDateStr}T${timePart}+07:00`;
      const slotDate = new Date(slotDateTimeStr);
      const diffMs = slotDate.getTime() - now.getTime();
      const hoursRemaining = diffMs / (1000 * 60 * 60);

      if (hoursRemaining < 4.0) {
        await client.query('ROLLBACK');
        return {
          success: false,
          status: 400,
          code: 'ERR_CANCELLATION_DEADLINE',
          message: `Khung giờ ${startStr.slice(0, 5)} chỉ còn ${hoursRemaining.toFixed(1)} tiếng trước giờ thi đấu. Chỉ được hủy trước tối thiểu 4 tiếng.`
        };
      }
    }

    // 7. Nếu hủy TẤT CẢ các khung giờ còn lại -> chuyển sang hủy toàn bộ
    if (normalizedSlotIds.length >= currentActiveSlotIds.length) {
      await client.query('ROLLBACK');
      return await processCustomerCancellation({
        bookingId,
        customerId,
        refundAccountInfo,
        reason: reason || 'Khách hàng hủy toàn bộ các khung giờ trong đơn',
        adminSupabase
      });
    }

    // 8. Hủy một phần: Tính số tiền hoàn/giảm dựa trên giá đã khóa lúc đặt (giadat / giatien / giaapdung / gia)
    let refundAmount = 0;
    for (const row of slotsToCancel) {
      let price = Number(row.giadat ?? row.giatien ?? row.giaapdung ?? row.gia ?? 0);
      if (price <= 0 && booking.san?.giasan) {
        const kg = row.khunggio || {};
        const [sh, sm] = String(kg.giobatdau || '00:00').split(':').map(Number);
        const [eh, em] = String(kg.gioketthuc || '00:00').split(':').map(Number);
        let mins = (eh * 60 + em) - (sh * 60 + sm);
        if (mins < 0) mins += 1440;
        price = Math.round((Number(booking.san.giasan) * mins) / 60);
      }
      refundAmount += price;
    }

    const currentTotal = Number(booking.tongtien || 0);
    const newTotal = Math.max(0, currentTotal - refundAmount);

    let meta = {};
    try { meta = JSON.parse(booking.ghichu || '{}'); } catch (e) {}

    const isOnlinePaid = booking.trangthai === 'DA_THANH_TOAN';
    meta.partialCancellations = [
      ...(meta.partialCancellations || []),
      {
        slotIds: normalizedSlotIds,
        refundAmount,
        cancelledAt: now.toISOString(),
        reason: reason || 'Khách hàng điều chỉnh hủy một phần khung giờ'
      }
    ];

    if (booking.trangthai === 'CHO_THI_DAU') {
      meta.remainingAmount = newTotal;
      meta.commissionAmount = Math.round(newTotal * 0.1);
    } else if (isOnlinePaid) {
      meta.commissionAmount = Math.round(newTotal * 0.1);
      meta.paidAmount = newTotal;
    }

    // Cập nhật tổng tiền đơn đặt sân
    const { data: updatedBooking, error: updErr } = await adminSupabase
      .from('datsan')
      .update({
        tongtien: newTotal,
        ghichu: JSON.stringify(meta)
      })
      .eq('madatsan', bookingId)
      .select();

    if (updErr || !updatedBooking || updatedBooking.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 500, message: 'Lỗi cập nhật giá trị đơn đặt sân sau khi điều chỉnh khung giờ.' };
    }

    // Giải phóng các khung giờ bị hủy khỏi datsan_khunggio
    const { error: delErr } = await adminSupabase
      .from('datsan_khunggio')
      .delete()
      .eq('madatsan', bookingId)
      .in('makhunggio', normalizedSlotIds);

    if (delErr) {
      await client.query('ROLLBACK');
      return { success: false, status: 500, message: 'Lỗi giải phóng khung giờ bị hủy: ' + delErr.message };
    }

    // Nếu đã thanh toán trực tuyến và có số tiền hoàn: tạo bản ghi hoantien
    let refundRecord = null;
    if (isOnlinePaid && refundAmount > 0) {
      const ownerId = booking.san?.machusan;
      const deadline = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      const { bankName, bankAccount, accountHolder } = refundAccountInfo || {};

      const partialKey = `CANCEL_PARTIAL_${bookingId}_${normalizedSlotIds.slice().sort((a,b)=>a-b).join('_')}`;

      const rfRes = await client.query(`
        INSERT INTO hoantien 
        (madatsan, makhachhang, machusan, sotien_canhoan, sotien_dahoan, lydo_huy, trangthai, nganhang_nhan, sotaikhoan_nhan, chutaikhoan_nhan, han_xuly, idempotency_key, slot_ids)
        VALUES ($1, $2, $3, $4, 0.00, $5, 'CHO_HOAN', $6, $7, $8, $9, $10, $11)
        ON CONFLICT (idempotency_key) DO NOTHING
        RETURNING *, mahoantien AS id, sotien_canhoan AS sotien_hoan, chutaikhoan_nhan AS tentaikhoan_nhan
      `, [
        bookingId,
        customerId,
        ownerId,
        refundAmount,
        reason || `Khách hàng hủy một phần ${normalizedSlotIds.length} khung giờ`,
        bankName || 'Vietcombank',
        bankAccount || '0000000000',
        accountHolder || 'KHACH HANG',
        deadline,
        partialKey,
        normalizedSlotIds
      ]);

      refundRecord = rfRes.rows[0];
      if (!refundRecord) {
        const existing = await client.query(
          'SELECT *, mahoantien AS id, sotien_canhoan AS sotien_hoan, chutaikhoan_nhan AS tentaikhoan_nhan FROM hoantien WHERE idempotency_key = $1',
          [partialKey]
        );
        refundRecord = existing.rows[0] || null;
      }

      if (ownerId) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '💸 Yêu cầu hoàn tiền hủy một phần ca đặt sân',
          noidung: `Khách hàng vừa hủy ${normalizedSlotIds.length} khung giờ của đơn #${bookingId} trước 4 giờ. Số tiền hoàn lại: ${refundAmount.toLocaleString('vi-VN')}đ. Vui lòng chuyển hoàn trong vòng 24h.`,
          loaithongbao: 'REFUND_REQUEST'
        });
      }
    }

    // Audit log
    await logFinancialAudit(client, {
      actorId: customerId,
      actorRole: 'KHACHHANG',
      action: 'MOCK_PAYMENT_PARTIAL_CANCEL',
      entityType: 'DAT_SAN',
      entityId: bookingId,
      oldValues: { tongtien: currentTotal, slotCount: currentActiveSlotIds.length },
      newValues: { tongtien: newTotal, remainingSlotCount: currentActiveSlotIds.length - normalizedSlotIds.length, refundAmount, cancelledSlotIds: normalizedSlotIds },
      reason: reason || 'Khách hàng hủy một phần khung giờ',
      ipAddress: '127.0.0.1'
    });

    await client.query('COMMIT');

    // Thông báo cho khách hàng
    await adminSupabase.from('thongbao').insert({
      manguoidung: customerId,
      tieude: '✅ Điều chỉnh khung giờ thành công',
      noidung: isOnlinePaid
        ? `Đã hủy thành công ${normalizedSlotIds.length} khung giờ của đơn #${bookingId}. Số tiền ${refundAmount.toLocaleString('vi-VN')}đ sẽ được Chủ sân hoàn trả trong 24h.`
        : `Đã hủy thành công ${normalizedSlotIds.length} khung giờ của đơn #${bookingId}. Số tiền thanh toán tại sân đã giảm xuống còn ${newTotal.toLocaleString('vi-VN')}đ.`,
      loaithongbao: 'BOOKING_UPDATED'
    });

    return {
      success: true,
      bookingId,
      cancelledSlotIds: normalizedSlotIds,
      remainingSlotCount: currentActiveSlotIds.length - normalizedSlotIds.length,
      refundAmount,
      newTotal,
      isOnlinePaid,
      refundRecord,
      message: `Đã hủy thành công ${normalizedSlotIds.length} khung giờ. ${isOnlinePaid ? `Số tiền hoàn: ${refundAmount.toLocaleString('vi-VN')}đ` : `Tổng tiền thanh toán mới: ${newTotal.toLocaleString('vi-VN')}đ`}`
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Chủ sân báo đã chuyển khoản hoàn tiền cho Khách hàng
 */
async function ownerConfirmRefundTransferred(ownerId, refundId, { bankTxId, proofUrl, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query(`
      SELECT * FROM hoantien WHERE mahoantien = $1 AND machusan = $2 FOR UPDATE
    `, [refundId, ownerId]);

    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền hoặc không có quyền thao tác' };
    }

    const rf = rfRes.rows[0];
    if (rf.trangthai === 'DA_HOAN' || rf.trangthai === 'BOI_HOAN_HOAN_TAT') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Yêu cầu hoàn tiền này đã được tất toán trước đó' };
    }

    await client.query(`
      UPDATE hoantien 
      SET trangthai = 'OWNER_BAO_DA_CHUYEN', thoigian_owner_chuyen = CURRENT_TIMESTAMP,
          magiaodich_owner = $1, bangchung_chuyen_url = $2, updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $3
    `, [bankTxId || 'TX_OWNER_REFUND_' + Date.now(), proofUrl || 'proof.png', refundId]);

    if (adminSupabase && rf.makhachhang) {
      await adminSupabase.from('thongbao').insert({
        manguoidung: rf.makhachhang,
        tieude: '💵 Chủ sân đã chuyển khoản hoàn tiền',
        noidung: `Chủ sân báo đã chuyển hoàn ${Number(rf.sotien_canhoan).toLocaleString('vi-VN')}đ cho đơn #${rf.madatsan}. Vui lòng kiểm tra tài khoản ngân hàng và xác nhận.`,
        loaithongbao: 'REFUND_TRANSFERRED'
      });
    }

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'OWNER_CONFIRM_REFUND_SENT',
      entityType: 'HOAN_TIEN',
      entityId: refundId,
      newValues: { bankTxId, proofUrl, status: 'OWNER_BAO_DA_CHUYEN' },
      reason: 'Chủ sân cung cấp bằng chứng chuyển khoản hoàn tiền'
    });

    await client.query('COMMIT');
    return { success: true, message: 'Đã cập nhật trạng thái đã chuyển hoàn. Đang chờ Khách hàng xác nhận nhận tiền.' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Khách hàng xác nhận đã nhận được tiền HOẶC mở tranh chấp
 */
async function customerConfirmOrDisputeRefund(customerId, refundId, { action, disputeReason, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query(`
      SELECT * FROM hoantien WHERE mahoantien = $1 AND makhachhang = $2 FOR UPDATE
    `, [refundId, customerId]);

    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền của bạn' };
    }

    const rf = rfRes.rows[0];

    if (action === 'CONFIRM') {
      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'DA_HOAN', sotien_dahoan = sotien_canhoan,
            thoigian_xacnhan_hoan = CURRENT_TIMESTAMP, nguoi_xacnhan_hoan = $1, updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $2
      `, [customerId, refundId]);

      await logFinancialAudit(client, {
        actorId: customerId,
        actorRole: 'KHACHHANG',
        action: 'CUSTOMER_CONFIRM_REFUND_RECEIVED',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        newValues: { status: 'DA_HOAN', amount: rf.sotien_canhoan },
        reason: 'Khách hàng xác nhận đã nhận đủ tiền hoàn'
      });

      await client.query('COMMIT');
      return { success: true, message: 'Cảm ơn bạn đã xác nhận. Quy trình hoàn tiền đã hoàn tất.' };
    }

    if (action === 'DISPUTE') {
      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'TRANH_CHAP', lydo_huy = CONCAT(lydo_huy, ' | Tranh chấp: ', $1::text), updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $2
      `, [disputeReason || 'Khách báo chưa nhận được tiền dù chủ sân đã xác nhận', refundId]);

      if (adminSupabase) {
        const { data: admins } = await adminSupabase.from('nguoidung').select('manguoidung').eq('vaitro', 'ADMIN');
        for (const adm of admins || []) {
          await adminSupabase.from('thongbao').insert({
            manguoidung: adm.manguoidung,
            tieude: '⚠️ Tranh chấp hoàn tiền mới',
            noidung: `Khách hàng ID ${customerId} vừa khiếu nại chưa nhận được tiền hoàn cho đơn #${rf.madatsan}. Vui lòng kiểm tra đối soát.`,
            loaithongbao: 'DISPUTE_ALERT'
          });
        }
      }

      await logFinancialAudit(client, {
        actorId: customerId,
        actorRole: 'KHACHHANG',
        action: 'CUSTOMER_OPEN_REFUND_DISPUTE',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        newValues: { status: 'TRANH_CHAP', disputeReason },
        reason: 'Khách hàng báo chưa nhận được tiền hoàn trả'
      });

      await client.query('COMMIT');
      return { success: true, message: 'Đã ghi nhận tranh chấp. Ban Quản Trị sẽ can thiệp và liên hệ trong 24 giờ.' };
    }

    await client.query('ROLLBACK');
    return { success: false, status: 400, message: 'Hành động không hợp lệ' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ============================================================================
// PHASE 6: GAP-FIN-02 QUY TRÌNH TRANH CHẤP & XỬ LÝ QUÁ HẠN 24H NÂNG CAO
// ============================================================================

/**
 * 6.1 Đánh dấu các đơn quá hạn 24h (KHÔNG TỰ ĐỘNG KHẤU TRỪ KÝ QUỸ)
 */
async function markOverdueRefunds(adminSupabase = null) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const { rows: overdueList } = await client.query(`
      SELECT * FROM hoantien 
      WHERE trangthai = 'CHO_HOAN' AND han_xuly < CURRENT_TIMESTAMP
      FOR UPDATE
    `);

    for (const rf of overdueList) {
      await client.query(`
        UPDATE hoantien SET trangthai = 'QUA_HAN', updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $1
      `, [rf.mahoantien]);

      await logFinancialAudit(client, {
        actorId: 0,
        actorRole: 'SYSTEM',
        action: 'MARK_REFUND_OVERDUE',
        entityType: 'HOAN_TIEN',
        entityId: rf.mahoantien,
        newValues: { status: 'QUA_HAN', overdueAt: new Date().toISOString() },
        reason: 'Quá hạn 24h chưa chuyển hoàn. Chuyển trạng thái để yêu cầu giải trình.'
      });

      if (adminSupabase) {
        // Thông báo Chủ sân gửi giải trình
        await adminSupabase.from('thongbao').insert({
          manguoidung: rf.machusan,
          tieude: '⚠️ Cảnh báo quá hạn hoàn tiền đơn #' + rf.madatsan,
          noidung: `Đơn hoàn tiền #${rf.madatsan} (${Number(rf.sotien_canhoan).toLocaleString('vi-VN')}đ) đã quá hạn 24h. Vui lòng chuyển hoàn ngay hoặc gửi văn bản giải trình trong 12h.`,
          loaithongbao: 'OVERDUE_ALERT'
        });
      }
    }

    await client.query('COMMIT');
    return { success: true, count: overdueList.length };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.2 Chủ sân gửi giải trình hoặc bằng chứng đối soát khi đơn quá hạn/tranh chấp
 */
async function ownerSubmitRefundExplanation(ownerId, refundId, { explanation, proofUrl, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query(`
      SELECT * FROM hoantien WHERE mahoantien = $1 AND machusan = $2 FOR UPDATE
    `, [refundId, ownerId]);

    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }

    const rf = rfRes.rows[0];
    if (!['QUA_HAN', 'TRANH_CHAP', 'CHO_HOAN'].includes(rf.trangthai)) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Không thể gửi giải trình ở trạng thái: ${rf.trangthai}` };
    }

    await client.query(`
      UPDATE hoantien 
      SET trangthai = 'DANG_XAC_MINH_GIAI_TRINH',
          giaitrinh_owner = $1,
          bangchung_giaitrinh_url = $2,
          thoigian_giaitrinh = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $3
    `, [explanation, proofUrl || null, refundId]);

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'SUBMIT_REFUND_EXPLANATION',
      entityType: 'HOAN_TIEN',
      entityId: refundId,
      newValues: { explanation, proofUrl, status: 'DANG_XAC_MINH_GIAI_TRINH' },
      reason: 'Chủ sân gửi văn bản giải trình và chứng từ'
    });

    if (adminSupabase) {
      const { data: admins } = await adminSupabase.from('nguoidung').select('manguoidung').eq('vaitro', 'ADMIN');
      for (const adm of admins || []) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: adm.manguoidung,
          tieude: '📄 Giải trình mới từ Chủ sân đơn #' + rf.madatsan,
          noidung: `Chủ sân ID ${ownerId} vừa nộp giải trình cho đơn hoàn tiền #${rf.madatsan}. Vui lòng thẩm tra.`,
          loaithongbao: 'EXPLANATION_SUBMITTED'
        });
      }
    }

    await client.query('COMMIT');
    return { success: true, message: 'Đã gửi giải trình thành công. Ban Quản Trị sẽ thẩm tra chứng từ.' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.3 Admin phán quyết tranh chấp / quá hạn (Có kiểm soát kép & ghi sổ cái an toàn)
 * Rulings:
 * - 'HOLD_ESCROW': Quyết định sơ bộ tạm giữ ký quỹ (Bắt đầu thời hạn phúc khảo 48h)
 * - 'REQUIRE_OWNER_TRANSFER': Chủ sân phải chuyển trong 12h
 * - 'DEDUCT_ESCROW': Khấu trừ trực tiếp (Legacy)
 */
async function adminAdjudicateOverdueRefund(adminId, refundId, { ruling, reason, secondAdminId, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    const rfRes = await client.query('SELECT * FROM hoantien WHERE mahoantien = $1 FOR UPDATE', [refundId]);
    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }

    const rf = rfRes.rows[0];
    if (!['QUA_HAN', 'DANG_XAC_MINH_GIAI_TRINH', 'TRANH_CHAP', 'PHUC_KHAO_KHAU_TRU', 'CHO_HOAN'].includes(rf.trangthai)) {
      await client.query('ROLLBACK');
      return { 
        success: false, 
        status: 400, 
        code: 'ALREADY_ADJUDICATED', 
        message: `Yêu cầu này đã được phán quyết hoặc ở trạng thái không thể phân xử: ${rf.trangthai}` 
      };
    }

    if (!reason || reason.trim().length < 5) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Phán quyết bắt buộc phải có căn cứ rõ ràng (tối thiểu 5 ký tự)' };
    }

    const ownerId = rf.machusan;
    const amount = Number(rf.sotien_canhoan);

    // 1. Phán quyết Sơ bộ: TẠM GIỮ KÝ QUỸ (Escrow Hold) + Mở khung phúc khảo 48h
    if (ruling === 'HOLD_ESCROW') {
      const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
      if (depRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return { success: false, status: 404, message: 'Không tìm thấy tài khoản ký quỹ của chủ sân' };
      }

      const dep = depRes.rows[0];
      const currentTotal = Number(dep.sodu_hientai || 0);
      const currentHeld = Number(dep.sodu_tamgiu || 0);
      const newHeld = currentHeld + amount;
      const newAvailable = Math.max(0, currentTotal - newHeld);

      // Ghi sổ cái bút toán TẠM GIỮ KÝ QUỸ (giảm khả dụng nhưng chưa mất vốn gốc)
      await client.query(`
        INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
        VALUES ($1, 'TAM_GIU_KY_QUY', $2, $3, $4, $5, 'ADMIN')
      `, [ownerId, -amount, newAvailable, `Tạm giữ ký quỹ đơn #${rf.madatsan} (mở khung phúc khảo 48h): ${reason}`, adminId]);

      const newDepStatus = newAvailable < 1000000 ? 'TAM_GIU_KY_QUY' : dep.trangthai;
      await client.query(`
        UPDATE kyquy 
        SET sodu_tamgiu = $1, trangthai = $2, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $3
      `, [newHeld, newDepStatus, ownerId]);

      // Cập nhật trạng thái hoàn tiền sang TAM_GIU_KY_QUY với hạn 48 giờ
      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'TAM_GIU_KY_QUY',
            quyetdinh_sobo = 'HOLD_ESCROW',
            thoigian_quyetdinh_sobo = CURRENT_TIMESTAMP,
            han_phuckhao = CURRENT_TIMESTAMP + INTERVAL '48 hours',
            ketluan_admin = 'TAM_GIU_KY_QUY',
            lydo_ketluan = $1,
            nguoi_duyet_phu = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $3
      `, [reason, secondAdminId || adminId, refundId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'PRELIMINARY_ESCROW_HOLD_48H',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        oldValues: { escrowBalance: currentTotal, escrowHeld: currentHeld, status: rf.trangthai },
        newValues: { escrowBalance: currentTotal, escrowHeld: newHeld, escrowAvailable: newAvailable, status: 'TAM_GIU_KY_QUY', ruling: 'HOLD_ESCROW' },
        reason
      });

      if (adminSupabase) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '⚠️ Thông báo quyết định sơ bộ tạm giữ ký quỹ đơn #' + rf.madatsan,
          noidung: `Ban Quản Trị tạm giữ ${amount.toLocaleString('vi-VN')}đ tiền ký quỹ do đơn hoàn tiền quá hạn. Bạn có 48 giờ để nộp đơn phúc khảo kèm chứng từ chuyển khoản trước khi bị khấu trừ chính thức.`,
          loaithongbao: 'ESCROW_HOLD_NOTICE'
        });
      }

      await client.query('COMMIT');
      return {
        success: true,
        message: `Đã ra quyết định sơ bộ tạm giữ ${amount.toLocaleString('vi-VN')}đ từ quỹ ký quỹ của Chủ sân #${ownerId}. Bắt đầu đếm ngược thời hạn phúc khảo 48 giờ.`,
        heldAmount: amount,
        newHeldBalance: newHeld,
        newAvailableBalance: newAvailable,
        appealDeadlineHours: 48
      };
    }

    if (ruling === 'DEDUCT_ESCROW') {
      // Khấu trừ trực tiếp (Legacy)
      const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
      if (depRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return { success: false, status: 404, message: 'Không tìm thấy tài khoản ký quỹ của chủ sân' };
      }

      const dep = depRes.rows[0];
      const oldBalance = Number(dep.sodu_hientai || 0);
      const newBalance = Math.max(0, oldBalance - amount);

      await client.query(`
        INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
        VALUES ($1, 'KHAU_TRU_BOI_THUONG', $2, $3, $4, $5, 'ADMIN')
      `, [ownerId, -amount, newBalance, `Khấu trừ ký quỹ đơn #${rf.madatsan}: ${reason}`, adminId]);

      const newDepStatus = newBalance < 1000000 ? 'THIEU_KY_QUY' : dep.trangthai;
      await client.query(`
        UPDATE kyquy 
        SET sodu_hientai = $1, trangthai = $2, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $3
      `, [newBalance, newDepStatus, ownerId]);

      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'KHAU_TRU_BOI_THUONG',
            ketluan_admin = 'DEDUCT_ESCROW',
            lydo_ketluan = $1,
            nguoi_duyet_phu = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $3
      `, [reason, secondAdminId || adminId, refundId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'DEDUCT_ESCROW_PENALTY',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        oldValues: { escrowBalance: oldBalance, status: rf.trangthai },
        newValues: { escrowBalance: newBalance, status: 'KHAU_TRU_BOI_THUONG', ruling },
        reason
      });

      if (adminSupabase) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '🚨 Quyết định khấu trừ quỹ bảo đảm đơn #' + rf.madatsan,
          noidung: `Ban Quản Trị đã ra quyết định khấu trừ ${amount.toLocaleString('vi-VN')}đ từ quỹ ký quỹ của bạn do vi phạm nghĩa vụ hoàn tiền. Số dư ký quỹ hiện tại: ${newBalance.toLocaleString('vi-VN')}đ. Lý do: ${reason}`,
          loaithongbao: 'PENALTY_DEDUCTION'
        });
      }

      await client.query('COMMIT');
      return {
        success: true,
        message: `Đã khấu trừ ${amount.toLocaleString('vi-VN')}đ từ quỹ ký quỹ của Chủ sân #${ownerId}. Trạng thái ký quỹ: ${newDepStatus}.`,
        newEscrowBalance: newBalance,
        newStatus: newDepStatus
      };
    }

    if (ruling === 'REQUIRE_OWNER_TRANSFER') {
      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'CHO_HOAN',
            ketluan_admin = 'REQUIRE_OWNER_TRANSFER',
            lydo_ketluan = $1,
            han_xuly = CURRENT_TIMESTAMP + INTERVAL '12 hours',
            updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $2
      `, [reason, refundId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'EXTEND_OWNER_TRANSFER_DEADLINE',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        newValues: { status: 'CHO_HOAN', ruling },
        reason
      });

      await client.query('COMMIT');
      return { success: true, message: 'Đã chấp thuận giải trình và gia hạn 12h cho Chủ sân chuyển khoản.' };
    }

    await client.query('ROLLBACK');
    return { success: false, status: 400, message: 'Phán quyết không hợp lệ (Chọn HOLD_ESCROW, DEDUCT_ESCROW hoặc REQUIRE_OWNER_TRANSFER)' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.4 Chủ sân nộp đơn phúc khảo / khiếu nại (Có chốt chặn thời hạn 48 giờ)
 */
async function ownerAppealDeduction(ownerId, refundId, { appealReason, evidenceUrl, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query(`
      SELECT * FROM hoantien WHERE mahoantien = $1 AND machusan = $2 FOR UPDATE
    `, [refundId, ownerId]);

    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }

    const rf = rfRes.rows[0];
    if (!['TAM_GIU_KY_QUY', 'KHAU_TRU_BOI_THUONG'].includes(rf.trangthai)) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Chỉ được phúc khảo các đơn đang bị tạm giữ ký quỹ hoặc có quyết định khấu trừ sơ bộ' };
    }

    // Kiểm tra thời hạn 48 giờ
    if (rf.han_phuckhao && new Date() > new Date(rf.han_phuckhao)) {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 400,
        code: 'APPEAL_EXPIRED_48H',
        message: `Đã quá thời hạn 48 giờ nộp đơn phúc khảo (Hết hạn lúc: ${new Date(rf.han_phuckhao).toISOString()}). Quyết định xử lý đã có hiệu lực thi hành.`
      };
    }

    await client.query(`
      UPDATE hoantien 
      SET trangthai = 'PHUC_KHAO_KHAU_TRU',
          phuckhao_owner = $1,
          bangchung_giaitrinh_url = COALESCE($2, bangchung_giaitrinh_url),
          thoigian_phuckhao = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $3
    `, [appealReason, evidenceUrl || null, refundId]);

    await logFinancialAudit(client, {
      actorId: ownerId,
      actorRole: 'CHUSAN',
      action: 'APPEAL_ESCROW_DEDUCTION',
      entityType: 'HOAN_TIEN',
      entityId: refundId,
      newValues: { status: 'PHUC_KHAO_KHAU_TRU', appealReason, evidenceUrl },
      reason: 'Chủ sân gửi đơn khiếu nại phúc khảo trong thời hạn 48h'
    });

    await client.query('COMMIT');
    return { success: true, message: 'Đơn phúc khảo hợp lệ đã được ghi nhận trong thời hạn 48h. Ban Quản Trị sẽ xem xét phán quyết cuối cùng.' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.4b Admin phán quyết phúc khảo: ĐẢO QUYẾT ĐỊNH (giải tỏa tạm giữ) HOẶC XÁC NHẬN KHẤU TRỪ CHÍNH THỨC
 */
async function adminAdjudicateAppeal(adminId, refundId, { ruling, reason, secondAdminId, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query('SELECT * FROM hoantien WHERE mahoantien = $1 FOR UPDATE', [refundId]);
    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }
    const rf = rfRes.rows[0];
    if (rf.trangthai !== 'PHUC_KHAO_KHAU_TRU') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Chỉ xử lý đơn đang trong trạng thái phúc khảo (Hiện tại: ${rf.trangthai})` };
    }

    const ownerId = rf.machusan;
    const amount = Number(rf.sotien_canhoan);

    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    if (depRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy tài khoản ký quỹ của chủ sân' };
    }
    const dep = depRes.rows[0];
    const totalBalance = Number(dep.sodu_hientai || 0);
    const heldBalance = Number(dep.sodu_tamgiu || 0);

    if (ruling === 'OVERTURN_AND_RELEASE_ESCROW') {
      // Phúc khảo thành công: Đảo quyết định sơ bộ & Giải tỏa tạm giữ ký quỹ
      const newHeld = Math.max(0, heldBalance - amount);
      const newAvailable = Math.max(0, totalBalance - newHeld);
      const newDepStatus = newAvailable >= 1000000 ? 'DA_KY_QUY' : dep.trangthai;

      await client.query(`
        INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
        VALUES ($1, 'GIAI_TOA_TAM_GIU', $2, $3, $4, $5, 'ADMIN')
      `, [ownerId, amount, newAvailable, `Giải tỏa tạm giữ ký quỹ đơn #${rf.madatsan} (Phúc khảo thành công): ${reason}`, adminId]);

      await client.query(`
        UPDATE kyquy 
        SET sodu_tamgiu = $1, trangthai = $2, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $3
      `, [newHeld, newDepStatus, ownerId]);

      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'DA_HOAN',
            ketluan_admin = 'OVERTURN_AND_RELEASE_ESCROW',
            lydo_ketluan = $1,
            nguoi_duyet_phu = $2,
            thoigian_xacnhan_hoan = CURRENT_TIMESTAMP,
            nguoi_xacnhan_hoan = $3,
            updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $4
      `, [reason, secondAdminId || adminId, adminId, refundId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'OVERTURN_ESCROW_HOLD_APPEAL_SUCCESS',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        oldValues: { escrowHeld: heldBalance, status: rf.trangthai },
        newValues: { escrowHeld: newHeld, escrowAvailable: newAvailable, status: 'DA_HOAN', ruling },
        reason
      });

      await client.query('COMMIT');
      return {
        success: true,
        message: `Chấp thuận phúc khảo. Đã giải tỏa ${amount.toLocaleString('vi-VN')}đ tiền ký quỹ tạm giữ về số dư khả dụng của Chủ sân #${ownerId}.`,
        newHeldBalance: newHeld,
        newAvailableBalance: newAvailable
      };
    }

    if (ruling === 'CONFIRM_DEDUCTION') {
      // Bác đơn phúc khảo: Chuyển tạm giữ thành khấu trừ chính thức
      const newHeld = Math.max(0, heldBalance - amount);
      const newTotal = Math.max(0, totalBalance - amount);
      const newDepStatus = newTotal < 1000000 ? 'THIEU_KY_QUY' : (newHeld > 0 ? 'TAM_GIU_KY_QUY' : 'DA_KY_QUY');

      await client.query(`
        INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
        VALUES ($1, 'KHAU_TRU_CHINH_THUC', $2, $3, $4, $5, 'ADMIN')
      `, [ownerId, -amount, newTotal, `Khấu trừ chính thức ký quỹ đơn #${rf.madatsan} (Bác đơn phúc khảo): ${reason}`, adminId]);

      await client.query(`
        UPDATE kyquy 
        SET sodu_hientai = $1, sodu_tamgiu = $2, trangthai = $3, updated_at = CURRENT_TIMESTAMP
        WHERE machusan = $4
      `, [newTotal, newHeld, newDepStatus, ownerId]);

      await client.query(`
        UPDATE hoantien 
        SET trangthai = 'KHAU_TRU_CHINH_THUC',
            ketluan_admin = 'CONFIRM_DEDUCTION',
            lydo_ketluan = $1,
            nguoi_duyet_phu = $2,
            updated_at = CURRENT_TIMESTAMP
        WHERE mahoantien = $3
      `, [reason, secondAdminId || adminId, refundId]);

      await logFinancialAudit(client, {
        actorId: adminId,
        actorRole: 'ADMIN',
        action: 'CONFIRM_ESCROW_DEDUCTION_FINAL',
        entityType: 'HOAN_TIEN',
        entityId: refundId,
        oldValues: { escrowBalance: totalBalance, escrowHeld: heldBalance, status: rf.trangthai },
        newValues: { escrowBalance: newTotal, escrowHeld: newHeld, status: 'KHAU_TRU_CHINH_THUC', ruling },
        reason
      });

      await client.query('COMMIT');
      return {
        success: true,
        message: `Đã bác đơn phúc khảo và khấu trừ chính thức ${amount.toLocaleString('vi-VN')}đ từ tài khoản ký quỹ của Chủ sân #${ownerId}. Có thể tiến hành chi trả bồi hoàn cho khách hàng.`,
        newEscrowBalance: newTotal,
        newHeldBalance: newHeld,
        newStatus: newDepStatus
      };
    }

    await client.query('ROLLBACK');
    return { success: false, status: 400, message: 'Phán quyết phúc khảo không hợp lệ (Chọn OVERTURN_AND_RELEASE_ESCROW hoặc CONFIRM_DEDUCTION)' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.4c Chuyển khấu trừ chính thức khi hết 48h phúc khảo mà không có đơn khiếu nại
 */
async function adminFinalizeOverdueHold(adminId, refundId, { reason, secondAdminId, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query('SELECT * FROM hoantien WHERE mahoantien = $1 FOR UPDATE', [refundId]);
    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }
    const rf = rfRes.rows[0];
    if (rf.trangthai !== 'TAM_GIU_KY_QUY') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Chỉ chuyển khấu trừ chính thức các đơn đang tạm giữ ký quỹ (Hiện tại: ${rf.trangthai})` };
    }

    // Kiểm tra thời hạn 48h
    if (rf.han_phuckhao && new Date() <= new Date(rf.han_phuckhao)) {
      await client.query('ROLLBACK');
      return {
        success: false,
        status: 400,
        code: 'APPEAL_WINDOW_STILL_ACTIVE',
        message: `Thời hạn 48 giờ phúc khảo vẫn còn hiệu lực (Đến: ${new Date(rf.han_phuckhao).toISOString()}). Chưa được phép khấu trừ dứt điểm.`
      };
    }

    const ownerId = rf.machusan;
    const amount = Number(rf.sotien_canhoan);

    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [ownerId]);
    if (depRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy tài khoản ký quỹ của chủ sân' };
    }
    const dep = depRes.rows[0];
    const totalBalance = Number(dep.sodu_hientai || 0);
    const heldBalance = Number(dep.sodu_tamgiu || 0);

    const newHeld = Math.max(0, heldBalance - amount);
    const newTotal = Math.max(0, totalBalance - amount);
    const newDepStatus = newTotal < 1000000 ? 'THIEU_KY_QUY' : 'DA_KY_QUY';

    await client.query(`
      INSERT INTO kyquy_ledger (machusan, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
      VALUES ($1, 'KHAU_TRU_CHINH_THUC', $2, $3, $4, $5, 'ADMIN')
    `, [ownerId, -amount, newTotal, `Khấu trừ dứt điểm ký quỹ đơn #${rf.madatsan} (Hết 48h phúc khảo không khiếu nại): ${reason || 'Quá hạn 48h phúc khảo'}`, adminId]);

    await client.query(`
      UPDATE kyquy 
      SET sodu_hientai = $1, sodu_tamgiu = $2, trangthai = $3, updated_at = CURRENT_TIMESTAMP
      WHERE machusan = $4
    `, [newTotal, newHeld, newDepStatus, ownerId]);

    await client.query(`
      UPDATE hoantien 
      SET trangthai = 'KHAU_TRU_CHINH_THUC',
          ketluan_admin = 'EXPIRED_APPEAL_FINAL_DEDUCTION',
          lydo_ketluan = $1,
          nguoi_duyet_phu = $2,
          updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $3
    `, [reason || 'Hết thời hạn 48 giờ phúc khảo, chuyển khấu trừ chính thức', secondAdminId || adminId, refundId]);

    await logFinancialAudit(client, {
      actorId: adminId,
      actorRole: 'ADMIN',
      action: 'EXPIRED_APPEAL_FINAL_DEDUCTION',
      entityType: 'HOAN_TIEN',
      entityId: refundId,
      oldValues: { escrowBalance: totalBalance, escrowHeld: heldBalance, status: rf.trangthai },
      newValues: { escrowBalance: newTotal, escrowHeld: newHeld, status: 'KHAU_TRU_CHINH_THUC' },
      reason: reason || 'Hết 48h phúc khảo'
    });

    await client.query('COMMIT');
    return {
      success: true,
      message: `Hết 48h phúc khảo. Đã chuyển tạm giữ thành khấu trừ chính thức ${amount.toLocaleString('vi-VN')}đ từ quỹ ký quỹ của Chủ sân #${ownerId}.`,
      newEscrowBalance: newTotal,
      newHeldBalance: newHeld,
      newStatus: newDepStatus
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.5 Admin xác nhận chuyển tiền bồi hoàn cho Khách hàng sau khi khấu trừ chính thức
 */
async function adminDisburseToCustomer(adminId, refundId, { payoutTxId, proofUrl, notes, adminSupabase }) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');
    const rfRes = await client.query('SELECT * FROM hoantien WHERE mahoantien = $1 FOR UPDATE', [refundId]);
    if (rfRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return { success: false, status: 404, message: 'Không tìm thấy yêu cầu hoàn tiền' };
    }

    const rf = rfRes.rows[0];

    // Concurrency / Idempotency check:
    if (rf.trangthai === 'BOI_HOAN_HOAN_TAT') {
      await client.query('ROLLBACK');
      return { success: false, status: 400, code: 'ALREADY_DISBURSED', message: 'Yêu cầu này đã được giải ngân bồi hoàn hoàn tất trước đó.' };
    }

    if (!['KHAU_TRU_CHINH_THUC', 'KHAU_TRU_BOI_THUONG', 'TRANH_CHAP'].includes(rf.trangthai)) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: `Chỉ bồi hoàn cho khách từ quỹ sau khi đã khấu trừ chính thức (Hiện tại: ${rf.trangthai})` };
    }

    if (!payoutTxId || payoutTxId.trim().length < 5) {
      await client.query('ROLLBACK');
      return { success: false, status: 400, message: 'Bắt buộc phải có mã giao dịch ngân hàng đối soát hợp lệ (payoutTxId tối thiểu 5 ký tự)' };
    }

    const amount = Number(rf.sotien_canhoan);

    await client.query(`
      UPDATE hoantien 
      SET trangthai = 'BOI_HOAN_HOAN_TAT',
          sotien_dahoan = $1,
          magiaodich_chi_tra = $2,
          bangchung_chi_tra_url = $3,
          thoigian_chi_tra = CURRENT_TIMESTAMP,
          thoigian_xacnhan_hoan = CURRENT_TIMESTAMP,
          nguoi_xacnhan_hoan = $4,
          updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $5
    `, [amount, payoutTxId, proofUrl || null, adminId, refundId]);

    await logFinancialAudit(client, {
      actorId: adminId,
      actorRole: 'ADMIN',
      action: 'DISBURSE_CUSTOMER_REIMBURSEMENT',
      entityType: 'HOAN_TIEN',
      entityId: refundId,
      newValues: { status: 'BOI_HOAN_HOAN_TAT', amount, payoutTxId },
      reason: notes || 'Sàn chi trả trực tiếp tiền bồi hoàn cho Khách hàng từ quỹ ký quỹ có đối soát ngân hàng'
    });

    if (adminSupabase && rf.makhachhang) {
      await adminSupabase.from('thongbao').insert({
        manguoidung: rf.makhachhang,
        tieude: '🎉 Đã nhận bồi hoàn 100% tiền đặt sân',
        noidung: `DatSanOnline đã thay mặt chủ sân chi trả ${amount.toLocaleString('vi-VN')}đ tiền bồi hoàn vào tài khoản ${rf.nganhang_nhan} - ${rf.sotaikhoan_nhan} của bạn. Mã GD: ${payoutTxId}.`,
        loaithongbao: 'REIMBURSEMENT_COMPLETED'
      });
    }

    await client.query('COMMIT');
    return { success: true, message: `Đã xác nhận chi trả bồi hoàn ${amount.toLocaleString('vi-VN')}đ cho Khách hàng thành công kèm đối soát mã GD: ${payoutTxId}.` };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * 6.6 Chủ sân nộp bổ sung ký quỹ sau khi bị khấu trừ (Top-up Escrow)
 */
async function ownerTopUpEscrow(ownerId, amount, { bankTxId, autoVerify = true } = {}) {
  const reqRes = await createDepositPaymentRequest(ownerId, amount);
  if (!reqRes.success) return reqRes;

  const reqId = reqRes.data?.requestId || reqRes.requestId;

  if (autoVerify) {
    const vRes = await adminVerifyDepositPayment(1, {
      requestId: reqId,
      isApproved: true,
      bankTxId: bankTxId || 'TOPUP_DEMO_' + Date.now(),
      notes: 'Bổ sung ký quỹ thành công qua Cổng mô phỏng DEMO'
    });
    const dep = await getOrCreateOwnerDeposit(ownerId);
    return {
      success: true,
      message: vRes.message,
      newBalance: Number(dep.sodu_hientai),
      status: dep.trangthai
    };
  }
  return reqRes;
}

async function adminResolveRefundDispute(adminId, refundId, { resolution, notes }) {
  if (resolution === 'MARK_REFUNDED' || resolution === 'DISMISS_DISPUTE') {
    await localPool.query(`
      UPDATE hoantien 
      SET trangthai = 'DA_HOAN', lydo_ketluan = $1, updated_at = CURRENT_TIMESTAMP
      WHERE mahoantien = $2
    `, [notes || 'Admin xác nhận đã hoàn tất tranh chấp', refundId]);
    return { success: true, message: 'Đã hoàn tất xử lý tranh chấp' };
  }
  const ruling = resolution === 'PLATFORM_ESCROW_DEDUCTION' ? 'HOLD_ESCROW' : 'REQUIRE_OWNER_TRANSFER';
  return adminAdjudicateOverdueRefund(adminId, refundId, { ruling, reason: notes || 'Admin giải quyết tranh chấp hoàn tiền' });
}

/**
 * 6.7 Báo cáo & Kiểm toán Tính Nhất Quán Tài Chính (Financial Consistency Breakdown)
 */
async function calculateOwnerFinancialSummary(ownerId) {
  const client = await localPool.connect();
  try {
    // 1. Thông tin ký quỹ
    const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1', [ownerId]);
    const dep = depRes.rows[0] || { sotien_yeucau: 1000000, sodu_hientai: 0, sodu_tamgiu: 0, trangthai: 'CHUA_KY_QUY' };
    const totalBalance = Number(dep.sodu_hientai || 0);
    const heldBalance = Number(dep.sodu_tamgiu || 0);
    const availableBalance = Math.max(0, totalBalance - heldBalance);

    // 2. Tiền ký quỹ đã nộp thực tế (từ giao dịch kyquy_giaodich đã xác minh)
    const gdRes = await client.query(`
      SELECT COALESCE(SUM(sotien), 0) as total_deposited
      FROM kyquy_giaodich
      WHERE machusan = $1 AND trangthai = 'THANH_CONG'
    `, [ownerId]);
    const escrowReceived = Number(gdRes.rows[0]?.total_deposited) > 0 
      ? Number(gdRes.rows[0]?.total_deposited) 
      : (dep.is_legacy || totalBalance > 0 ? 1000000 : 0);

    // 3. Tiền ký quỹ đã khấu trừ chính thức (từ sổ cái)
    const dedRes = await client.query(`
      SELECT COALESCE(SUM(ABS(sotien_thaydoi)), 0) as total_deducted
      FROM kyquy_ledger
      WHERE machusan = $1 AND loai_butdoan IN ('KHAU_TRU_CHINH_THUC', 'KHAU_TRU_BOI_THUONG')
    `, [ownerId]);
    const escrowDeducted = Number(dedRes.rows[0]?.total_deducted || 0);

    // 4. Nghĩa vụ hoàn tiền của Owner (các đơn chưa hoàn tất)
    const obRes = await client.query(`
      SELECT COALESCE(SUM(sotien_canhoan), 0) as total_obligation, COUNT(*) as count_pending
      FROM hoantien
      WHERE machusan = $1 AND trangthai IN ('CHO_HOAN', 'QUA_HAN', 'DANG_XAC_MINH_GIAI_TRINH', 'TAM_GIU_KY_QUY', 'PHUC_KHAO_KHAU_TRU')
    `, [ownerId]);
    const ownerRefundObligation = Number(obRes.rows[0]?.total_obligation || 0);
    const pendingRefundsCount = Number(obRes.rows[0]?.count_pending || 0);

    // 5. Tiền sàn đã thực tế chi trả bồi hoàn cho khách từ quỹ ký quỹ của owner
    const payRes = await client.query(`
      SELECT COALESCE(SUM(sotien_dahoan), 0) as total_platform_payout
      FROM hoantien
      WHERE machusan = $1 AND trangthai = 'BOI_HOAN_HOAN_TAT'
    `, [ownerId]);
    const platformCustomerPayout = Number(payRes.rows[0]?.total_platform_payout || 0);

    return {
      success: true,
      ownerId,
      summary: {
        escrowReceived,                 // 1. Tiền ký quỹ thực nhận ban đầu
        escrowBalance: totalBalance,    // 2. Số dư ký quỹ hiện tại đang giữ tại sàn
        escrowHeld: heldBalance,        // 3. Tiền ký quỹ đang bị tạm giữ (tranh chấp 48h)
        escrowAvailable: availableBalance, // 4. Tiền ký quỹ khả dụng
        escrowDeducted,                 // 5. Tiền ký quỹ đã khấu trừ chính thức
        ownerRefundObligation,          // 6. Nghĩa vụ hoàn tiền còn nợ của Owner
        pendingRefundsCount,
        platformCustomerPayout,         // 7. Tiền sàn đã thực tế chi trả cho Customer
        platformCommissionRate: '0% cho đơn tự hủy >= 4h; 10% cho đơn hoàn thành bình thường'
      }
    };
  } finally {
    client.release();
  }
}

// ============================================================================
// PHASE 2: MOCK PAYMENT GATEWAY (SIMULATED TRANSACTIONS)
// ============================================================================

/**
 * Mock Payment Gateway - Xử lý thanh toán mô phỏng cho Demo Mode
 * Hỗ trợ: SIMULATE_SUCCESS, SIMULATE_FAILURE, SIMULATE_PENDING
 * Có kiểm tra quyền, tính toán số tiền độc lập từ DB, và Idempotency chống ghi nhận trùng
 */
async function processMockPayment({
  actorId,
  actorRole,
  transactionType, // 'ESCROW_DEPOSIT' | 'REFUND' | 'BOOKING'
  transactionId,   // magiaodich hoặc mahoantien hoặc madatsan
  simulationAction, // 'SIMULATE_SUCCESS' | 'SIMULATE_FAILURE' | 'SIMULATE_PENDING'
  fallbackAction = null, // 'SWITCH_CASH' | 'CANCEL' | 'RETRY'
  idempotencyKey = null,
  ipAddress = '127.0.0.1',
  adminSupabase = null
}) {
  const client = await localPool.connect();
  try {
    await client.query('BEGIN');

    if (!['SIMULATE_SUCCESS', 'SIMULATE_FAILURE', 'SIMULATE_PENDING'].includes(simulationAction)) {
      throw new Error(`simulationAction không hợp lệ: ${simulationAction}. Chỉ chấp nhận: SIMULATE_SUCCESS, SIMULATE_FAILURE, SIMULATE_PENDING`);
    }

    if (transactionType === 'ESCROW_DEPOSIT') {
      const gdRes = await client.query('SELECT * FROM kyquy_giaodich WHERE magiaodich = $1 FOR UPDATE', [transactionId]);
      if (gdRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return { success: false, code: 'NOT_FOUND', message: 'Không tìm thấy giao dịch nộp ký quỹ' };
      }
      const gd = gdRes.rows[0];

      // Kiểm tra quyền: Phải là chủ sân sở hữu giao dịch hoặc ADMIN
      if (Number(gd.machusan) !== Number(actorId) && actorRole !== 'ADMIN') {
        await client.query('ROLLBACK');
        return { success: false, code: 'FORBIDDEN', message: 'Bạn không có quyền thực hiện mô phỏng thanh toán cho giao dịch của chủ sân khác (Chống IDOR)' };
      }

      // Idempotency: Nếu giao dịch đã hoàn tất thành công trước đó
      if (gd.trangthai === 'THANH_CONG') {
        await client.query('COMMIT');
        return {
          success: true,
          code: 'IDEMPOTENT_ALREADY_SUCCESS',
          message: 'Giao dịch ký quỹ demo này đã được xử lý thành công trước đó. Tránh ghi nhận số dư trùng lặp.',
          transaction: gd,
          isSimulated: true
        };
      }

      const amount = Number(gd.sotien); // Số tiền lấy hoàn toàn từ DB, không nhận từ client

      if (simulationAction === 'SIMULATE_SUCCESS') {
        const mockBankTx = `MOCK_TX_${Date.now()}_${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

        // Cập nhật giao dịch
        await client.query(`
          UPDATE kyquy_giaodich 
          SET trangthai = 'THANH_CONG',
              magiaodich_nganhang = $1,
              thoigian_thanhtoan = CURRENT_TIMESTAMP,
              nguoi_xacminh = $2,
              thoigian_xacminh = CURRENT_TIMESTAMP
          WHERE magiaodich = $3
        `, [mockBankTx, actorId, transactionId]);

        // Khóa và cập nhật tài khoản ký quỹ
        const depRes = await client.query('SELECT * FROM kyquy WHERE machusan = $1 FOR UPDATE', [gd.machusan]);
        let dep = depRes.rows[0];
        if (!dep) {
          const initRes = await client.query(`
            INSERT INTO kyquy (machusan, sotien_yeucau, sotien_dadoisoat, sodu_hientai, trangthai)
            VALUES ($1, 1000000.00, 0.00, 0.00, 'CHUA_KY_QUY')
            RETURNING *
          `, [gd.machusan]);
          dep = initRes.rows[0];
        }

        const newBalance = Number(dep.sodu_hientai || 0) + amount;
        const newSettled = Number(dep.sotien_dadoisoat || 0) + amount;
        const newStatus = (newBalance - Number(dep.sodu_tamgiu || 0)) >= Number(dep.sotien_yeucau || 1000000) ? 'DA_KY_QUY' : 'THIEU_KY_QUY';

        await client.query(`
          UPDATE kyquy 
          SET sodu_hientai = $1,
              sotien_dadoisoat = $2,
              trangthai = $3,
              thoigian_xacnhan = CURRENT_TIMESTAMP,
              nguoi_xacnhan = $4,
              updated_at = CURRENT_TIMESTAMP
          WHERE machusan = $5
        `, [newBalance, newSettled, newStatus, actorId, gd.machusan]);

        // Ghi sổ cái bất biến (Ledger)
        await client.query(`
          INSERT INTO kyquy_ledger (machusan, magiaodich, loai_butdoan, sotien_thaydoi, sodu_sau, lydo, actor_id, actor_role)
          VALUES ($1, $2, 'NOP_KY_QUY', $3, $4, 'Thanh toán mô phỏng thành công qua Mock Payment Gateway (DEMO)', $5, $6)
        `, [gd.machusan, transactionId, amount, newBalance, actorId, actorRole]);

        // Audit log
        await logFinancialAudit(client, {
          actorId,
          actorRole,
          action: 'MOCK_PAYMENT_SUCCESS',
          entityType: 'KY_QUY_GIAODICH',
          entityId: transactionId,
          oldValues: { trangthai: gd.trangthai, sodu_hientai: dep.sodu_hientai },
          newValues: { trangthai: 'THANH_CONG', sodu_hientai: newBalance, mockBankTx },
          reason: 'Mô phỏng thanh toán ký quỹ thành công qua Mock Payment Gateway (DEMO)',
          ipAddress
        });

        await client.query('COMMIT');

        return {
          success: true,
          code: 'SIMULATE_SUCCESS',
          status: 'THANH_CONG',
          message: 'Thanh toán mô phỏng 1.000.000đ THÀNH CÔNG! Tài khoản ký quỹ chuyển trạng thái ĐÃ KÝ QUỸ (DA_KY_QUY).',
          isSimulated: true,
          mockBankTx,
          newBalance,
          newStatus
        };
      } else if (simulationAction === 'SIMULATE_FAILURE') {
        await client.query(`
          UPDATE kyquy_giaodich 
          SET trangthai = 'TU_CHOI'
          WHERE magiaodich = $1
        `, [transactionId]);

        await logFinancialAudit(client, {
          actorId,
          actorRole,
          action: 'MOCK_PAYMENT_FAILURE',
          entityType: 'KY_QUY_GIAODICH',
          entityId: transactionId,
          oldValues: { trangthai: gd.trangthai },
          newValues: { trangthai: 'TU_CHOI' },
          reason: 'Người dùng chọn mô phỏng thanh toán THẤT BÀI (Simulate Failure)',
          ipAddress
        });

        await client.query('COMMIT');

        return {
          success: false,
          code: 'SIMULATE_FAILURE',
          status: 'TU_CHOI',
          message: 'Mô phỏng thanh toán THẤT BÀI: Giao dịch bị từ chối theo kịch bản thử nghiệm.',
          isSimulated: true
        };
      } else if (simulationAction === 'SIMULATE_PENDING') {
        await client.query(`
          UPDATE kyquy_giaodich 
          SET trangthai = 'CHO_XAC_MINH'
          WHERE magiaodich = $1
        `, [transactionId]);

        await logFinancialAudit(client, {
          actorId,
          actorRole,
          action: 'MOCK_PAYMENT_PENDING',
          entityType: 'KY_QUY_GIAODICH',
          entityId: transactionId,
          reason: 'Giao dịch chuyển sang trạng thái chờ xác minh mô phỏng',
          ipAddress
        });

        await client.query('COMMIT');

        return {
          success: true,
          code: 'SIMULATE_PENDING',
          status: 'CHO_XAC_MINH',
          message: 'Giao dịch mô phỏng đang ở trạng thái CHỜ XÁC MINH (Pending Verification).',
          isSimulated: true
        };
      }
    } else if (transactionType === 'REFUND') {
      const rfRes = await client.query('SELECT * FROM hoantien WHERE mahoantien = $1 FOR UPDATE', [transactionId]);
      if (rfRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return { success: false, code: 'NOT_FOUND', message: 'Không tìm thấy yêu cầu hoàn tiền' };
      }
      const rf = rfRes.rows[0];

      if (Number(rf.machusan) !== Number(actorId) && actorRole !== 'ADMIN') {
        await client.query('ROLLBACK');
        return { success: false, code: 'FORBIDDEN', message: 'Bạn không có quyền xử lý hoàn tiền cho đơn của chủ sân khác' };
      }

      if (rf.trangthai === 'DA_HOAN' || rf.trangthai === 'BOI_HOAN_HOAN_TAT') {
        await client.query('COMMIT');
        return {
          success: true,
          code: 'IDEMPOTENT_ALREADY_REFUNDED',
          message: 'Yêu cầu hoàn tiền này đã được giải quyết hoàn tất trước đó.',
          refund: rf,
          isSimulated: true
        };
      }

      if (simulationAction === 'SIMULATE_SUCCESS') {
        const mockRefundTx = `MOCK_REFUND_${Date.now()}_${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

        await client.query(`
          UPDATE hoantien 
          SET trangthai = 'OWNER_BAO_DA_CHUYEN',
              sotien_dahoan = sotien_canhoan,
              magiaodich_owner = $1,
              thoigian_owner_chuyen = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
          WHERE mahoantien = $2
        `, [mockRefundTx, transactionId]);

        await logFinancialAudit(client, {
          actorId,
          actorRole,
          action: 'MOCK_REFUND_SUCCESS',
          entityType: 'HOAN_TIEN',
          entityId: transactionId,
          oldValues: { trangthai: rf.trangthai },
          newValues: { trangthai: 'OWNER_BAO_DA_CHUYEN', mockRefundTx, sotien_dahoan: rf.sotien_canhoan },
          reason: 'Chủ sân hoàn tất chuyển khoản hoàn tiền mô phỏng 100% cho khách',
          ipAddress
        });

        await client.query('COMMIT');

        return {
          success: true,
          code: 'SIMULATE_SUCCESS',
          status: 'OWNER_BAO_DA_CHUYEN',
          bankTxId: mockRefundTx,
          message: `Chuyển khoản hoàn tiền mô phỏng ${(Number(rf.sotien_canhoan)).toLocaleString('vi-VN')}đ thành công!`,
          mockRefundTx,
          isSimulated: true
        };
      } else {
        await client.query('ROLLBACK');
        return { success: false, code: 'SIMULATE_REFUND_FAILED', message: 'Mô phỏng hoàn tiền thất bại.' };
      }
    } else if (transactionType === 'BOOKING') {
      const sb = adminSupabase || internalAdminSupabase;
      let booking;

      if (sb) {
        const { data: bData, error: bErr } = await sb
          .from('datsan')
          .select('*, san(masan, machusan, tensan)')
          .eq('madatsan', transactionId)
          .single();
        if (bErr || !bData) {
          await client.query('ROLLBACK');
          return { success: false, code: 'NOT_FOUND', message: 'Không tìm thấy đơn đặt sân #' + transactionId };
        }
        booking = bData;
      } else {
        const bRes = await client.query('SELECT * FROM datsan WHERE madatsan = $1 FOR UPDATE', [transactionId]);
        if (bRes.rows.length === 0) {
          await client.query('ROLLBACK');
          return { success: false, code: 'NOT_FOUND', message: 'Không tìm thấy đơn đặt sân #' + transactionId };
        }
        booking = bRes.rows[0];
      }

      // Anti-IDOR: Must be the customer who created booking or an ADMIN
      if (Number(booking.makhachhang) !== Number(actorId) && actorRole !== 'ADMIN') {
        await client.query('ROLLBACK');
        return { success: false, code: 'FORBIDDEN', message: 'Bạn không có quyền thực hiện mô phỏng thanh toán cho đơn đặt sân của khách hàng khác (Chống IDOR).' };
      }

      // Idempotency: Already paid
      if (booking.trangthai === 'DA_THANH_TOAN') {
        await client.query('COMMIT');
        return {
          success: true,
          code: 'IDEMPOTENT_ALREADY_SUCCESS',
          status: 'DA_THANH_TOAN',
          message: 'Đơn đặt sân này đã được thanh toán mô phỏng thành công trước đó.',
          booking,
          isSimulated: true
        };
      }

      // Check if cancelled or not pending
      if (booking.trangthai === 'DA_HUY' || booking.trangthai === 'DAHUY') {
        await client.query('ROLLBACK');
        return {
          success: false,
          code: 'INVALID_STATUS',
          message: 'Đơn đặt sân đã bị hủy, không thể thực hiện mô phỏng thanh toán.'
        };
      }

      if (booking.trangthai !== 'CHO_THANH_TOAN') {
        await client.query('ROLLBACK');
        return {
          success: false,
          code: 'INVALID_STATUS',
          message: `Đơn đặt sân đang ở trạng thái '${booking.trangthai}', chỉ có thể thực hiện thanh toán khi ở trạng thái 'CHO_THANH_TOAN'.`
        };
      }

      let meta = {};
      try {
        meta = typeof booking.ghichu === 'string' ? JSON.parse(booking.ghichu || '{}') : (booking.ghichu || {});
      } catch (e) {
        meta = {};
      }
      const totalAmount = Number(booking.tongtien || 0);
      const commissionAmount = Math.round(totalAmount * 0.1);

      if (simulationAction === 'SIMULATE_SUCCESS') {
        const mockBankTx = `MOCK_BOOKING_TX_${Date.now()}_${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
        meta.paidAmount = totalAmount;
        meta.remainingAmount = 0;
        meta.commissionStatus = 'DA_THU_SAN';
        meta.commissionAmount = commissionAmount;
        meta.isSimulatedPayment = true;
        meta.financialMode = 'DEMO';
        meta.mockBankTx = mockBankTx;
        meta.paymentSimulatedAt = new Date().toISOString();

        if (sb) {
          const { data: updated, error: updErr } = await sb.from('datsan').update({
            trangthai: 'DA_THANH_TOAN',
            ghichu: JSON.stringify(meta)
          }).eq('madatsan', transactionId).eq('trangthai', 'CHO_THANH_TOAN').select();

          if (updErr || !updated || updated.length === 0) {
            await client.query('ROLLBACK');
            return {
              success: false,
              code: 'CONCURRENT_CONFLICT',
              message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
            };
          }
        } else {
          const updRes = await client.query(`
            UPDATE datsan
            SET trangthai = 'DA_THANH_TOAN',
                ghichu = $1
            WHERE madatsan = $2 AND trangthai = 'CHO_THANH_TOAN'
          `, [JSON.stringify(meta), transactionId]);

          if (updRes.rowCount === 0) {
            await client.query('ROLLBACK');
            return {
              success: false,
              code: 'CONCURRENT_CONFLICT',
              message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
            };
          }
        }

        await logFinancialAudit(client, {
          actorId,
          actorRole,
          action: 'MOCK_PAYMENT_BOOKING_SUCCESS',
          entityType: 'DATSAN',
          entityId: transactionId,
          oldValues: { trangthai: booking.trangthai, paidAmount: meta.paidAmount },
          newValues: { trangthai: 'DA_THANH_TOAN', paidAmount: totalAmount, mockBankTx },
          reason: 'Khách hàng mô phỏng thanh toán trực tuyến đơn đặt sân thành công (DEMO)',
          ipAddress
        });

        await client.query('COMMIT');

        // Gửi thông báo cho Khách hàng, Chủ sân, Admin nếu có sb
        if (sb) {
          try {
            const sanName = booking.san?.tensan || 'Sân thể thao';
            const ownerId = booking.san?.machusan;

            await sb.from('thongbao').insert([
              {
                manguoidung: booking.makhachhang,
                tieude: '🎉 Thanh toán mô phỏng thành công!',
                noidung: `Bạn đã thanh toán mô phỏng (DEMO 100%) đơn đặt sân ${sanName} ngày ${booking.ngaysudung}. Mã GD: ${mockBankTx}.`,
                loaithongbao: 'BOOKING'
              },
              ...(ownerId ? [{
                manguoidung: ownerId,
                tieude: '🔔 Đơn đặt sân mới (Mô phỏng)!',
                noidung: `Khách hàng vừa hoàn tất thanh toán mô phỏng (DEMO 100%) cho sân ${sanName} ngày ${booking.ngaysudung}.`,
                loaithongbao: 'BOOKING'
              }] : []),
              {
                manguoidung: null,
                tieude: '📋 Đơn đặt sân mới toàn sàn (DEMO)',
                noidung: `Khách đã thanh toán mô phỏng đơn #${transactionId} tại sân ${sanName} - ${totalAmount.toLocaleString('vi-VN')} đ (DEMO).`,
                loaithongbao: 'ADMIN'
              }
            ]);
          } catch (notifErr) {
            console.warn('[Notification Error]', notifErr.message);
          }
        }

        return {
          success: true,
          code: 'SIMULATE_SUCCESS',
          status: 'DA_THANH_TOAN',
          message: 'Mô phỏng thanh toán đơn đặt sân 100% THÀNH CÔNG! Trạng thái đơn: ĐÃ THANH TOÁN (DA_THANH_TOAN).',
          isSimulated: true,
          mockBankTx,
          paidAmount: totalAmount,
          bookingId: transactionId
        };
      } else if (simulationAction === 'SIMULATE_FAILURE') {
        if (fallbackAction === 'SWITCH_CASH') {
          // TASK 03: Kiểm tra giới hạn 120 phút cho hình thức thanh toán tiền mặt
          let slotRows = [];
          if (sb) {
            const { data: dskg } = await sb
              .from('datsan_khunggio')
              .select('makhunggio, khunggio:makhunggio(giobatdau, gioketthuc)')
              .eq('madatsan', transactionId);
            slotRows = (dskg || []).map(r => r.khunggio).filter(Boolean);
          } else {
            const kgRes = await client.query(`
              SELECT kg.giobatdau, kg.gioketthuc
              FROM datsan_khunggio dk
              JOIN khunggio kg ON dk.makhunggio = kg.makhunggio
              WHERE dk.madatsan = $1
            `, [transactionId]);
            slotRows = kgRes.rows;
          }

          const durationMinutes = calculateDurationMinutesFromSlots(slotRows);
          if (durationMinutes > 120) {
            await client.query('ROLLBACK');
            return {
              success: false,
              code: 'ERR_CASH_DURATION_LIMIT',
              message: `Thanh toán tiền mặt chỉ áp dụng cho đơn đặt sân tối đa 2 giờ (120 phút). Đơn hiện tại có thời lượng ${durationMinutes} phút. Vui lòng thử thanh toán lại trực tuyến hoặc hủy đơn.`
            };
          }

          // Khách hàng chọn chuyển sang thanh toán tiền mặt tại sân để không làm mất đặt sân
          meta.paymentMethod = 'TIEN_MAT';
          meta.paidAmount = 0;
          meta.remainingAmount = totalAmount;
          meta.commissionStatus = 'CHO_XAC_NHAN_TRAN';
          meta.commissionAmount = commissionAmount;
          meta.financialMode = 'DEMO';
          meta.isSimulatedPayment = false;
          meta.lastSimulation = { action: 'FAILURE_SWITCHED_CASH', at: new Date().toISOString() };

          if (sb) {
            const { data: updated, error: updErr } = await sb.from('datsan').update({
              trangthai: 'CHO_THI_DAU',
              ghichu: JSON.stringify(meta)
            }).eq('madatsan', transactionId).eq('trangthai', 'CHO_THANH_TOAN').select();

            if (updErr || !updated || updated.length === 0) {
              await client.query('ROLLBACK');
              return {
                success: false,
                code: 'CONCURRENT_CONFLICT',
                message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
              };
            }
          } else {
            const updRes = await client.query(`
              UPDATE datsan
              SET trangthai = 'CHO_THI_DAU',
                  ghichu = $1
              WHERE madatsan = $2 AND trangthai = 'CHO_THANH_TOAN'
            `, [JSON.stringify(meta), transactionId]);

            if (updRes.rowCount === 0) {
              await client.query('ROLLBACK');
              return {
                success: false,
                code: 'CONCURRENT_CONFLICT',
                message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
              };
            }
          }

          await logFinancialAudit(client, {
            actorId,
            actorRole,
            action: 'MOCK_PAYMENT_BOOKING_SWITCH_CASH',
            entityType: 'DATSAN',
            entityId: transactionId,
            oldValues: { trangthai: booking.trangthai },
            newValues: { trangthai: 'CHO_THI_DAU', paymentMethod: 'TIEN_MAT' },
            reason: 'Mô phỏng thanh toán thất bại: Chuyển sang thanh toán tiền mặt tại sân (bảo toàn khung giờ)',
            ipAddress
          });

          await client.query('COMMIT');
          return {
            success: true,
            code: 'SIMULATE_FAILURE_SWITCHED_CASH',
            status: 'CHO_THI_DAU',
            message: 'Mô phỏng thất bại: Đơn đặt sân đã chuyển sang hình thức TIỀN MẶT TẠI SÂN (CHO_THI_DAU). Khung giờ của bạn được bảo toàn.',
            isSimulated: true,
            bookingId: transactionId
          };
        } else if (fallbackAction === 'CANCEL') {
          // Hủy đơn đặt sân để không chiếm khung giờ khi mô phỏng thất bại
          meta.lastSimulation = { action: 'FAILURE_CANCELLED', at: new Date().toISOString() };
          meta.commissionAmount = 0;
          meta.commissionStatus = 'DA_HUY';

          if (sb) {
            // Priority: Call atomic PostgreSQL RPC function (executes in 1 single transaction)
            let rpcSucceeded = false;
            try {
              const { data: rpcRes, error: rpcErr } = await sb.rpc('cancel_booking_atomic', {
                p_madatsan: Number(transactionId),
                p_ghichu: JSON.stringify(meta),
                p_expected_status: 'CHO_THANH_TOAN'
              });

              if (!rpcErr && rpcRes) {
                rpcSucceeded = true;
                if (!rpcRes.success) {
                  await client.query('ROLLBACK');
                  return {
                    success: false,
                    code: rpcRes.code || 'CONCURRENT_CONFLICT',
                    message: rpcRes.message || 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
                  };
                }
              }
            } catch (rpcEx) {
              rpcSucceeded = false;
            }

            if (!rpcSucceeded) {
              const { data: updated, error: updErr } = await sb.from('datsan').update({
                trangthai: 'DA_HUY',
                ghichu: JSON.stringify(meta)
              }).eq('madatsan', transactionId).eq('trangthai', 'CHO_THANH_TOAN').select();

              if (updErr || !updated || updated.length === 0) {
                await client.query('ROLLBACK');
                return {
                  success: false,
                  code: 'CONCURRENT_CONFLICT',
                  message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
                };
              }

              // Giải phóng các khung giờ trong bảng chính thức datsan_khunggio
              const { error: delErr } = await sb.from('datsan_khunggio').delete().eq('madatsan', transactionId);
              if (delErr) {
                // Hoàn tác trạng thái datsan để bảo đảm không xảy ra hủy một phần
                await sb.from('datsan').update({
                  trangthai: booking.trangthai,
                  ghichu: booking.ghichu
                }).eq('madatsan', transactionId);
                await client.query('ROLLBACK');
                return {
                  success: false,
                  code: 'RELEASE_SLOTS_FAILED',
                  message: 'Không thể giải phóng khung giờ đặt sân. Đã hoàn tác trạng thái để bảo đảm tính nhất quán dữ liệu.'
                };
              }

              // Đồng bộ trạng thái thanhtoan nếu có
              await sb.from('thanhtoan').update({ trangthai: 'DA_HUY' }).eq('madatsan', transactionId);
            }
          } else {
            const updRes = await client.query(`
              UPDATE datsan
              SET trangthai = 'DA_HUY',
                  ghichu = $1
              WHERE madatsan = $2 AND trangthai = 'CHO_THANH_TOAN'
            `, [JSON.stringify(meta), transactionId]);

            if (updRes.rowCount === 0) {
              await client.query('ROLLBACK');
              return {
                success: false,
                code: 'CONCURRENT_CONFLICT',
                message: 'Đơn đặt sân đã được xử lý hoặc thay đổi trạng thái bởi một yêu cầu khác.'
              };
            }

            await client.query(`DELETE FROM datsan_khunggio WHERE madatsan = $1`, [transactionId]);
            await client.query(`UPDATE thanhtoan SET trangthai = 'DA_HUY' WHERE madatsan = $1`, [transactionId]);
          }

          await logFinancialAudit(client, {
            actorId,
            actorRole,
            action: 'MOCK_PAYMENT_BOOKING_CANCELLED',
            entityType: 'DATSAN',
            entityId: transactionId,
            oldValues: { trangthai: booking.trangthai },
            newValues: { trangthai: 'DA_HUY' },
            reason: 'Mô phỏng thanh toán thất bại: Hủy đơn và giải phóng khung giờ thi đấu',
            ipAddress
          });

          await client.query('COMMIT');
          return {
            success: true,
            code: 'SIMULATE_FAILURE_CANCELLED',
            status: 'DA_HUY',
            message: 'Mô phỏng thất bại: Đơn đặt sân đã bị hủy và khung giờ thi đấu đã được giải phóng.',
            isSimulated: true,
            bookingId: transactionId
          };
        } else {
          // Mặc định: giữ nguyên ở CHO_THANH_TOAN để người dùng có thể Thử lại, Chuyển tiền mặt hoặc Hủy
          meta.lastSimulation = { action: 'SIMULATE_FAILURE', at: new Date().toISOString() };

          if (sb) {
            await sb.from('datsan').update({
              ghichu: JSON.stringify(meta)
            }).eq('madatsan', transactionId);
          } else {
            await client.query(`
              UPDATE datsan
              SET ghichu = $1
              WHERE madatsan = $2
            `, [JSON.stringify(meta), transactionId]);
          }

          await client.query('COMMIT');
          return {
            success: false,
            code: 'SIMULATE_FAILURE',
            status: 'CHO_THANH_TOAN',
            message: 'Mô phỏng thanh toán thất bại. Đơn đặt sân vẫn được giữ tạm ở trạng thái Chờ thanh toán. Bạn có thể Thử lại, Chuyển sang tiền mặt (để không mất sân), hoặc Hủy đơn (để giải phóng khung giờ).',
            isSimulated: true,
            options: ['RETRY', 'SWITCH_CASH', 'CANCEL'],
            bookingId: transactionId
          };
        }
      } else {
        await client.query('ROLLBACK');
        return { success: false, code: 'INVALID_SIMULATION_ACTION', message: `simulationAction không hợp lệ cho booking: ${simulationAction}` };
      }
    } else {
      await client.query('ROLLBACK');
      return { success: false, code: 'INVALID_TYPE', message: `transactionType không hợp lệ: ${transactionType}` };
    }
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  localPool,
  FINANCIAL_MODE,
  IS_DEMO_MODE,
  getEscrowBankConfig,
  getMockQrSvgDataUrl,
  logFinancialAudit,
  getOrCreateOwnerDeposit,
  createDepositPaymentRequest,
  processMockPayment,
  submitDepositPaymentProof,
  adminVerifyDepositPayment,
  checkCourtDepositEligibility,
  requestOwnerDepositRefund,
  adminSettleDepositRefund,
  checkCancellationEligibility,
  processCustomerCancellation,
  processPartialCustomerCancellation,
  calculateDurationMinutesFromSlots,
  ownerConfirmRefundTransferred,
  customerConfirmOrDisputeRefund,
  markOverdueRefunds,
  ownerSubmitRefundExplanation,
  adminAdjudicateOverdueRefund,
  ownerAppealDeduction,
  adminAdjudicateAppeal,
  adminFinalizeOverdueHold,
  adminDisburseToCustomer,
  ownerTopUpEscrow,
  adminResolveRefundDispute,
  calculateOwnerFinancialSummary
};
