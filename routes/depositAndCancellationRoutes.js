// routes/depositAndCancellationRoutes.js
// Mounts REST API endpoints for Feature 01 (Owner Security Deposit) & Feature 02 (Customer Self-Cancellation)
// Remediated for Financial Security & Complete Dispute Flow

const service = require('../depositAndCancellationService');

function mountDepositAndCancellationRoutes(app, { adminSupabase, getAuthenticatedProfile }) {

  // Helper SQL selection to standardize DTO across all consumers
  const REFUND_DTO_SELECT = `
    SELECT 
      *,
      mahoantien AS id,
      sotien_canhoan AS sotien_hoan,
      chutaikhoan_nhan AS tentaikhoan_nhan,
      magiaodich_owner AS chusan_nganhang_txid
    FROM hoantien
  `;

  // ==========================================================================
  // PHASE 2: MOCK PAYMENT GATEWAY ENDPOINTS (DEMO FINANCIAL SIMULATION)
  // ==========================================================================

  // 0.1 Cấu hình Demo Financial Mode & Mock Payment Gateway
  app.get('/api/mock-payment/config', (req, res) => {
    const escrowCfg = service.getEscrowBankConfig();
    return res.json({
      success: true,
      financialMode: escrowCfg.financialMode,
      isDemoMode: service.IS_DEMO_MODE,
      supportedSimulations: ['SIMULATE_SUCCESS', 'SIMULATE_FAILURE', 'SIMULATE_PENDING'],
      disclaimer: 'HỆ THỐNG MÔ PHỎNG TÀI CHÍNH (DEMO) — TOÀN BỘ TIỀN TỆ LÀ GIẢ LẬP, KHÔNG SỬ DỤNG TIỀN THẬT',
      bankInfo: escrowCfg
    });
  });

  // 0.2 Xử lý thanh toán mô phỏng (Mock Payment Process)
  app.post('/api/mock-payment/process', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const actorId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const actorRole = authData.profile?.vaitro || authData.profile?.VaiTro;

    const { transactionType, transactionId, simulationAction, fallbackAction, idempotencyKey } = req.body;

    if (!transactionType || !transactionId || !simulationAction) {
      return res.status(400).json({ error: 'Thiếu thông tin bắt buộc: transactionType, transactionId, simulationAction' });
    }

    try {
      const result = await service.processMockPayment({
        actorId,
        actorRole,
        transactionType,
        transactionId: Number(transactionId),
        simulationAction,
        fallbackAction,
        idempotencyKey,
        ipAddress: req.ip,
        adminSupabase
      });

      if (!result.success && result.code === 'FORBIDDEN') {
        return res.status(403).json(result);
      }
      if (!result.success && result.code === 'NOT_FOUND') {
        return res.status(404).json(result);
      }

      return res.json(result);
    } catch (err) {
      console.error('Mock Payment Error:', err);
      return res.status(500).json({ error: 'Lỗi xử lý thanh toán mô phỏng: ' + err.message });
    }
  });

  // ==========================================================================
  // FEATURE 01: OWNER SECURITY DEPOSIT (1.000.000 VND)
  // ==========================================================================

  // 1.1 Lấy trạng thái ký quỹ của Chủ sân hiện tại
  app.get('/api/owner/deposit', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    try {
      const deposit = await service.getOrCreateOwnerDeposit(ownerId, false, adminSupabase);
      const { rows: ledger } = await service.localPool.query(`
        SELECT * FROM kyquy_ledger WHERE machusan = $1 ORDER BY created_at DESC
      `, [ownerId]);

      const { rows: transactions } = await service.localPool.query(`
        SELECT * FROM kyquy_giaodich WHERE machusan = $1 ORDER BY created_at DESC
      `, [ownerId]);

      return res.json({
        success: true,
        financialMode: service.FINANCIAL_MODE,
        isDemoMode: service.IS_DEMO_MODE,
        deposit,
        ledger,
        transactions,
        escrowPolicy: {
          requiredAmount: 1000000,
          isRefundable: true,
          description: service.IS_DEMO_MODE 
            ? 'Khoản bảo đảm ký quỹ mô phỏng (1.000.000đ). Phục vụ demo, không sử dụng tiền thật.'
            : 'Khoản bảo đảm trách nhiệm kinh doanh sân bãi có hoàn lại (1.000.000đ). Không phải phí đăng ký.'
        }
      });
    } catch (err) {
      console.error('Error fetching owner deposit:', err);
      return res.status(500).json({ error: 'Lỗi tải thông tin ký quỹ' });
    }
  });

  // 1.2 Tạo yêu cầu nộp ký quỹ VietQR
  app.post('/api/owner/deposit/request', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    try {
      const result = await service.createDepositPaymentRequest(ownerId);
      if (!result.success) {
        return res.status(400).json({
          ...result,
          error: result.message || 'Không thể tạo yêu cầu thanh toán ký quỹ'
        });
      }
      return res.json({
        ...result,
        paymentDetails: result.data
      });
    } catch (err) {
      console.error('[Deposit Request Error] Owner:', ownerId, err.message);
      return res.status(500).json({ error: 'Lỗi tạo yêu cầu thanh toán ký quỹ: ' + err.message });
    }
  });

  // 1.3 Chủ sân gửi tham chiếu bằng chứng đã chuyển khoản
  app.post('/api/owner/deposit/submit-proof', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { requestId, bankTxId, proofUrl } = req.body || {};

    if (!requestId) return res.status(400).json({ error: 'Thiếu mã yêu cầu thanh toán (requestId)' });

    try {
      const result = await service.submitDepositPaymentProof(ownerId, { requestId, bankTxId, proofUrl });
      if (!result.success) return res.status(400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error submitting deposit proof:', err);
      return res.status(500).json({ error: 'Lỗi gửi xác nhận chuyển khoản' });
    }
  });

  // 1.4 Admin: Xem danh sách tài khoản ký quỹ và yêu cầu chờ đối soát
  app.get('/api/admin/deposits', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    try {
      const { rows: deposits } = await service.localPool.query(`
        SELECT k.*, 
               (SELECT COUNT(*) FROM kyquy_giaodich g WHERE g.machusan = k.machusan AND g.trangthai = 'CHO_XAC_MINH') as pending_count
        FROM kyquy k 
        ORDER BY k.updated_at DESC
      `);

      const { rows: pendingRequests } = await service.localPool.query(`
        SELECT g.*, k.sodu_hientai, k.trangthai as kyquy_status
        FROM kyquy_giaodich g
        LEFT JOIN kyquy k ON g.machusan = k.machusan
        WHERE g.trangthai = 'CHO_XAC_MINH'
        ORDER BY g.created_at ASC
      `);

      return res.json({
        success: true,
        deposits,
        pendingRequests
      });
    } catch (err) {
      console.error('Error fetching admin deposits:', err);
      return res.status(500).json({ error: 'Lỗi tải danh sách ký quỹ' });
    }
  });

  // 1.5 Admin: Đối soát & xác minh kích hoạt ký quỹ
  app.post('/api/admin/deposits/verify', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { requestId, isApproved, bankTxId, notes } = req.body || {};

    if (!requestId) return res.status(400).json({ error: 'Thiếu mã yêu cầu thanh toán (requestId)' });

    try {
      const result = await service.adminVerifyDepositPayment(adminId, {
        requestId,
        isApproved: Boolean(isApproved),
        bankTxId,
        notes
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error verifying deposit:', err);
      return res.status(500).json({ error: 'Lỗi xử lý xác minh ký quỹ' });
    }
  });

  // 1.6 Chủ sân: Nộp đơn xin ngừng hợp tác & hoàn trả ký quỹ (GAP-FIN-01 Remediation)
  app.post('/api/owner/deposit/refund-request', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { reason, bankName, bankAccount, accountHolder } = req.body || {};

    if (!bankName || !bankAccount || !accountHolder) {
      return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ thông tin tài khoản nhận tiền hoàn ký quỹ' });
    }

    try {
      const result = await service.requestOwnerDepositRefund(ownerId, { 
        reason, 
        bankName, 
        bankAccount, 
        accountHolder,
        adminSupabase 
      });
      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error requesting deposit refund:', err);
      return res.status(500).json({ error: 'Lỗi gửi yêu cầu hoàn ký quỹ' });
    }
  });

  // 1.7 Admin: Đối soát & tất toán hoàn trả ký quỹ cho Chủ sân
  app.post('/api/admin/deposits/settle-refund', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { ownerId, isApproved, refundAmount, bankTxId, notes } = req.body || {};

    if (!ownerId) return res.status(400).json({ error: 'Thiếu mã chủ sân (ownerId)' });

    try {
      const result = await service.adminSettleDepositRefund(adminId, {
        ownerId: Number(ownerId),
        isApproved: Boolean(isApproved),
        refundAmount: Number(refundAmount || 1000000),
        bankTxId,
        notes
      });

      if (!result.success) return res.status(400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error settling deposit refund:', err);
      return res.status(500).json({ error: 'Lỗi tất toán hoàn trả ký quỹ' });
    }
  });

  // 1.8 Chủ sân: Nộp bổ sung ký quỹ (Top-up) sau khi bị khấu trừ bồi thường
  app.post('/api/owner/deposit/top-up', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { amount } = req.body || {};

    try {
      const result = await service.ownerTopUpEscrow(ownerId, amount);
      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error topping up escrow:', err);
      return res.status(500).json({ error: 'Lỗi nạp bổ sung ký quỹ' });
    }
  });

  // ==========================================================================
  // FEATURE 02: CUSTOMER SELF-CANCELLATION & REFUND (>= 4 HOURS)
  // ==========================================================================

  // 2.1 Khách hàng: Kiểm tra điều kiện tự hủy đơn đặt sân
  app.get('/api/customer/cancellation-check/:bookingId', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const customerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const bookingId = Number(req.params.bookingId);

    try {
      const { data: booking, error: bErr } = await adminSupabase
        .from('datsan')
        .select('*, san (tensan, machusan)')
        .eq('madatsan', bookingId)
        .single();

      if (bErr || !booking) return res.status(404).json({ error: 'Không tìm thấy đơn đặt sân' });

      const { data: slotLinks } = await adminSupabase
        .from('datsan_khunggio')
        .select('*, khunggio (*)')
        .eq('madatsan', bookingId);

      const slots = (slotLinks || []).map(sl => ({
        makhunggio: sl.makhunggio || sl.khunggio?.makhunggio,
        giobatdau: sl.khunggio?.giobatdau,
        gioketthuc: sl.khunggio?.gioketthuc,
        giadat: sl.giadat ?? sl.giatien ?? sl.giaapdung
      })).filter(s => s.giobatdau);

      const check = service.checkCancellationEligibility({ booking, slots, customerId });

      return res.json({
        success: true,
        eligible: check.eligible,
        status: check.status,
        reason: check.reason,
        hoursRemaining: check.hoursRemaining,
        isOnlinePaid: check.isOnlinePaid,
        refundAmount: check.refundAmount,
        slots: check.slots || [],
        bookingSummary: {
          madatsan: booking.madatsan,
          tensan: booking.san?.tensan,
          ngaysudung: booking.ngaysudung,
          tongtien: booking.tongtien,
          trangthai: booking.trangthai
        }
      });
    } catch (err) {
      console.error('Error checking cancellation eligibility:', err);
      return res.status(500).json({ error: 'Lỗi kiểm tra điều kiện hủy' });
    }
  });

  // 2.2 Khách hàng: Thực hiện hủy đặt sân (BUG-SEC-01 Advisory Lock Protected)
  app.post('/api/customer/cancel-booking', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const customerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { bookingId, reason, bankName, bankAccount, accountHolder } = req.body || {};

    if (!bookingId) return res.status(400).json({ error: 'Thiếu mã đơn đặt sân' });

    try {
      const result = await service.processCustomerCancellation({
        bookingId: Number(bookingId),
        customerId,
        refundAccountInfo: { bankName, bankAccount, accountHolder },
        reason,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error processing customer cancellation:', err);
      return res.status(500).json({ error: 'Lỗi xử lý hủy đặt sân' });
    }
  });

  // 2.3 Khách hàng: Thực hiện hủy một phần khung giờ (TASK 02 Partial Cancellation)
  app.post('/api/customer/cancel-partial-booking', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const customerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const { bookingId, slotIds, reason, bankName, bankAccount, accountHolder } = req.body || {};

    if (!bookingId) return res.status(400).json({ error: 'Thiếu mã đơn đặt sân' });
    if (!Array.isArray(slotIds) || slotIds.length === 0) {
      return res.status(400).json({ error: 'Vui lòng chọn ít nhất một khung giờ cần hủy' });
    }

    try {
      const result = await service.processPartialCustomerCancellation({
        bookingId: Number(bookingId),
        customerId,
        slotIds: slotIds.map(Number),
        refundAccountInfo: { bankName, bankAccount, accountHolder },
        reason,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error processing partial cancellation:', err);
      return res.status(500).json({ error: 'Lỗi xử lý điều chỉnh khung giờ' });
    }
  });

  // 2.3 Chủ sân: Danh sách yêu cầu hoàn tiền cần xử lý (Standardized DTO)
  app.get('/api/owner/refunds', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    try {
      const { rows: refunds } = await service.localPool.query(`
        ${REFUND_DTO_SELECT}
        WHERE machusan = $1 
        ORDER BY created_at DESC
      `, [ownerId]);

      return res.json({ success: true, refunds });
    } catch (err) {
      console.error('Error fetching owner refunds:', err);
      return res.status(500).json({ error: 'Lỗi tải danh sách hoàn tiền' });
    }
  });

  // 2.4 Chủ sân: Báo đã chuyển khoản hoàn tiền kèm mã giao dịch
  app.post('/api/owner/refunds/:id/confirm-sent', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { bankTxId, proofUrl } = req.body || {};

    try {
      const result = await service.ownerConfirmRefundTransferred(ownerId, refundId, {
        bankTxId,
        proofUrl,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error owner confirming refund sent:', err);
      return res.status(500).json({ error: 'Lỗi xác nhận hoàn tiền' });
    }
  });

  // 2.4b Chủ sân: Gửi giải trình quá hạn 24h kèm bằng chứng (GAP-FIN-02)
  app.post('/api/owner/refunds/:id/explain', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { explanation, proofUrl } = req.body || {};

    try {
      const result = await service.ownerSubmitRefundExplanation(ownerId, refundId, {
        explanation,
        proofUrl,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error submitting refund explanation:', err);
      return res.status(500).json({ error: 'Lỗi gửi giải trình hoàn tiền' });
    }
  });

  // 2.4c Chủ sân: Khiếu nại / Phúc khảo phán quyết khấu trừ ký quỹ (GAP-FIN-02)
  app.post('/api/owner/refunds/:id/appeal', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { appealReason, evidenceUrl } = req.body || {};

    try {
      const result = await service.ownerAppealDeduction(ownerId, refundId, {
        appealReason,
        evidenceUrl,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error submitting refund appeal:', err);
      return res.status(500).json({ error: 'Lỗi gửi khiếu nại phán quyết' });
    }
  });

  // 2.5 Khách hàng: Xác nhận đã nhận đủ tiền hoàn HOẶC Mở tranh chấp
  app.post('/api/customer/refunds/:id/confirm-received', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const customerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { action, disputeReason } = req.body || {}; // action: 'CONFIRM' hoặc 'DISPUTE'

    if (!['CONFIRM', 'DISPUTE'].includes(action)) {
      return res.status(400).json({ error: 'Hành động không hợp lệ (Chọn CONFIRM hoặc DISPUTE)' });
    }

    try {
      const result = await service.customerConfirmOrDisputeRefund(customerId, refundId, {
        action,
        disputeReason,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error customer confirming refund:', err);
      return res.status(500).json({ error: 'Lỗi xác nhận nhận tiền' });
    }
  });

  // 2.5b Khách hàng: Lấy danh sách các khoản hoàn tiền của bản thân (Standardized DTO)
  app.get('/api/customer/refunds', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Vui lòng đăng nhập' });

    const customerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    try {
      const { rows: refunds } = await service.localPool.query(`
        ${REFUND_DTO_SELECT}
        WHERE makhachhang = $1 
        ORDER BY created_at DESC
      `, [customerId]);
      return res.json({ success: true, refunds });
    } catch (err) {
      console.error('Error fetching customer refunds:', err);
      return res.status(500).json({ error: 'Lỗi tải danh sách hoàn tiền' });
    }
  });

  // 2.6 Admin: Quản lý danh sách hoàn tiền, quá hạn 24h & Tranh chấp (Standardized DTO)
  app.get('/api/admin/refunds', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    try {
      const { rows: allRefunds } = await service.localPool.query(`
        ${REFUND_DTO_SELECT}
        ORDER BY created_at DESC
      `);

      const { rows: overdueRefunds } = await service.localPool.query(`
        ${REFUND_DTO_SELECT}
        WHERE trangthai IN ('CHO_HOAN', 'QUA_HAN', 'DANG_XAC_MINH_GIAI_TRINH')
          AND (han_xuly < CURRENT_TIMESTAMP OR trangthai IN ('QUA_HAN', 'DANG_XAC_MINH_GIAI_TRINH'))
        ORDER BY han_xuly ASC
      `);

      const { rows: disputes } = await service.localPool.query(`
        ${REFUND_DTO_SELECT}
        WHERE trangthai IN ('TRANH_CHAP', 'PHUC_KHAO_KHAU_TRU', 'CHO_CHI_TRA')
        ORDER BY updated_at DESC
      `);

      return res.json({
        success: true,
        allRefunds,
        overdueRefunds,
        disputes
      });
    } catch (err) {
      console.error('Error fetching admin refunds:', err);
      return res.status(500).json({ error: 'Lỗi tải danh sách hoàn tiền' });
    }
  });

  // 2.6b Quét và đánh dấu các đơn quá hạn 24h (GAP-FIN-02 Cron/Manual)
  app.post('/api/admin/refunds/check-overdue', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    try {
      const result = await service.markOverdueRefunds(adminSupabase);
      return res.json(result);
    } catch (err) {
      console.error('Error checking overdue refunds:', err);
      return res.status(500).json({ error: 'Lỗi quét đơn hoàn tiền quá hạn' });
    }
  });

  // 2.7 Admin: Phán quyết xử lý đơn hoàn tiền quá hạn / giải trình / tranh chấp (GAP-FIN-02)
  app.post('/api/admin/refunds/:id/adjudicate', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { ruling, reason, secondAdminId } = req.body || {};

    try {
      const result = await service.adminAdjudicateOverdueRefund(adminId, refundId, {
        ruling,
        reason,
        secondAdminId,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error adjudicating refund:', err);
      return res.status(500).json({ error: 'Lỗi đưa ra phán quyết xử lý hoàn tiền' });
    }
  });

  // 2.8 Admin: Chi trả bồi hoàn cho khách hàng từ tài khoản Escrow sàn (GAP-FIN-02)
  app.post('/api/admin/refunds/:id/disburse-customer', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { payoutTxId, notes } = req.body || {};

    try {
      const result = await service.adminDisburseToCustomer(adminId, refundId, {
        payoutTxId,
        notes,
        adminSupabase
      });

      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error disbursing to customer:', err);
      return res.status(500).json({ error: 'Lỗi thực hiện chi trả cho khách hàng' });
    }
  });

  // 2.9 Admin: Giải quyết tranh chấp hoàn tiền legacy (Backward compatibility)
  app.post('/api/admin/refunds/:id/resolve', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { resolution, notes } = req.body || {};

    try {
      const result = await service.adminResolveRefundDispute(adminId, refundId, { resolution, notes });
      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error resolving refund dispute:', err);
      return res.status(500).json({ error: 'Lỗi xử lý tranh chấp hoàn tiền' });
    }
  });

  // 2.10 Admin: Phán quyết phúc khảo (ĐẢO QUYẾT ĐỊNH / XÁC NHẬN KHẤU TRỪ CHÍNH THỨC)
  app.post('/api/admin/refunds/:id/adjudicate-appeal', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { ruling, reason, secondAdminId } = req.body || {};

    try {
      const result = await service.adminAdjudicateAppeal(adminId, refundId, {
        ruling,
        reason,
        secondAdminId,
        adminSupabase
      });
      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error adjudicating appeal:', err);
      return res.status(500).json({ error: 'Lỗi phán quyết phúc khảo' });
    }
  });

  // 2.11 Admin: Chuyển khấu trừ chính thức khi hết 48h phúc khảo không khiếu nại
  app.post('/api/admin/refunds/:id/finalize-hold', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const adminId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    const refundId = Number(req.params.id);
    const { reason, secondAdminId } = req.body || {};

    try {
      const result = await service.adminFinalizeOverdueHold(adminId, refundId, {
        reason,
        secondAdminId,
        adminSupabase
      });
      if (!result.success) return res.status(result.status || 400).json(result);
      return res.json(result);
    } catch (err) {
      console.error('Error finalizing overdue hold:', err);
      return res.status(500).json({ error: 'Lỗi chuyển khấu trừ dứt điểm' });
    }
  });

  // 2.12 Chủ sân: Báo cáo & Kiểm toán Tính Nhất Quán Tài Chính Cá Nhân
  app.get('/api/owner/financial-summary', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN')) {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Chủ sân' });
    }

    const ownerId = authData.profile?.manguoidung || authData.profile?.MaNguoiDung;
    try {
      const result = await service.calculateOwnerFinancialSummary(ownerId);
      return res.json(result);
    } catch (err) {
      console.error('Error calculating owner financial summary:', err);
      return res.status(500).json({ error: 'Lỗi tổng hợp dữ liệu tài chính chủ sân' });
    }
  });

  // 2.13 Admin: Kiểm toán Tính Nhất Quán Tài Chính theo Chủ Sân
  app.get('/api/admin/financial-summary/:ownerId', async (req, res) => {
    const authData = await getAuthenticatedProfile(req);
    if (!authData || authData.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Yêu cầu quyền Super Admin' });
    }

    const ownerId = Number(req.params.ownerId);
    try {
      const result = await service.calculateOwnerFinancialSummary(ownerId);
      return res.json(result);
    } catch (err) {
      console.error('Error calculating admin financial summary:', err);
      return res.status(500).json({ error: 'Lỗi tổng hợp dữ liệu tài chính cho Admin' });
    }
  });

}

module.exports = mountDepositAndCancellationRoutes;