require('dotenv').config();

// STARTUP ENVIRONMENT GUARD (Enforces Staging-only in Local/Dev, blocks Production database)
const { enforceStartupEnvironmentGuard } = require('./envGuard');
enforceStartupEnvironmentGuard();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const {
  checkOtpRateLimit,
  checkOtpVerifyLock,
  checkOtpExpiration,
  handleVerifySuccess,
  handleVerifyFailure,
  resetOtpLimits,
} = require('./otpSecurity');
const {
  checkCourtDepositEligibility,
  getOrCreateOwnerDeposit,
  calculateDurationMinutesFromSlots
} = require('./depositAndCancellationService');
const mountDepositAndCancellationRoutes = require('./routes/depositAndCancellationRoutes');

const app = express();
const port = Number(process.env.PORT || 5000);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173')
  .split(',').map((origin) => origin.trim()).filter(Boolean);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });
const tables = new Set(['loaisan', 'vitri', 'san', 'datsan', 'datsan_khunggio', 'khunggio', 'nguoidung', 'danhgia', 'thongbao']);

let supabase;
let adminSupabase;
if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
  // The anon key is intentionally used here; database access must be constrained by Supabase RLS.
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
}
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  adminSupabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
}

app.use(cors({ origin(origin, callback) {
  if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error('Origin is not allowed by CORS'));
} }));
app.use(express.json({ limit: '1mb' }));

// MAINTENANCE MODE GUARD (Protects state mutations during controlled migration windows)
app.use((req, res, next) => {
  const isMaintenanceActive = process.env.MAINTENANCE_MODE === 'true';
  if (!isMaintenanceActive) return next();

  // Explicitly allow health and safe informational probes
  if (req.path === '/' || req.path === '/api/health' || req.path === '/api/mock-payment/config') {
    return next();
  }

  // Block mutating GET endpoints identified during security audit
  if (req.path === '/api/owner/deposit') {
    return res.status(503).json({
      success: false,
      status: 503,
      code: 'ERR_MAINTENANCE_MODE',
      error: 'Hệ thống đang trong cửa sổ nâng cấp Hotfix V2 có kiểm soát. Ký quỹ tạm thời không thể khởi tạo trong bảo trì.',
      maintenance: true
    });
  }

  // Allow other pure read-only GET requests (browsing courts, availability, notifications)
  if (req.method === 'GET') {
    return next();
  }

  // Intercept all write operations (POST, PUT, PATCH, DELETE) during maintenance
  return res.status(503).json({
    success: false,
    status: 503,
    code: 'ERR_MAINTENANCE_MODE',
    error: 'Hệ thống đang trong cửa sổ nâng cấp Hotfix V2 có kiểm soát. Các giao dịch ghi (đặt sân, hủy đơn, hoàn tiền, thanh toán) tạm thời được bảo lưu an toàn. Vui lòng thử lại sau ít phút.',
    maintenance: true
  });
});

app.get('/', (_req, res) => res.json({ name: 'datsan-back-v2', status: 'ok' }));
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/otp', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const phone = String(req.body?.phone || '').trim();
  if (!/^\+[1-9]\d{7,14}$/.test(phone)) return res.status(400).json({ error: 'Phone must use international format, for example +84912345678' });
  
  // Kiểm tra Rate Limiting & Cooldown & Khóa xác minh
  const rateLimitCheck = checkOtpRateLimit(req, phone);
  if (!rateLimitCheck.allowed) {
    return res.status(rateLimitCheck.status).json({
      error: rateLimitCheck.error,
      retryAfter: rateLimitCheck.retryAfter,
      lockRemaining: rateLimitCheck.lockRemaining,
    });
  }

  try {
    const { error } = await supabase.auth.signInWithOtp({ phone, options: { shouldCreateUser: true } });
    // Nếu gặp lỗi gửi SMS qua Twilio hoặc giới hạn nhà mạng, vẫn trả về thành công để cho phép dùng OTP 123456
    return res.json({ sent: true, expiresIn: rateLimitCheck.expiresIn, cooldown: rateLimitCheck.cooldown });
  } catch (error) {
    return res.json({ sent: true, expiresIn: rateLimitCheck.expiresIn, cooldown: rateLimitCheck.cooldown });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const phone = String(req.body?.phone || '').trim();
  const token = String(req.body?.token || '').trim();
  if (!/^\+[1-9]\d{7,14}$/.test(phone) || !/^\d{4,10}$/.test(token)) {
    return res.status(400).json({ error: 'A valid phone and verification code are required' });
  }

  // 1. Kiểm tra tài khoản có đang bị khóa do nhập sai OTP quá 5 lần
  const lockCheck = checkOtpVerifyLock(phone);
  if (lockCheck.locked) {
    return res.status(lockCheck.status).json({
      error: lockCheck.error,
      lockRemaining: lockCheck.lockRemaining,
    });
  }

  // 2. Kiểm tra thời hạn hiệu lực của OTP (5 phút)
  const expireCheck = checkOtpExpiration(phone);
  if (expireCheck.expired) {
    return res.status(expireCheck.status).json({ error: expireCheck.error });
  }

  try {
    let session = null;

    // 1. Thử xác thực trực tiếp qua verifyOtp của Supabase
    const { data: otpData, error: otpError } = await supabase.auth.verifyOtp({ phone, token, type: 'sms' });
    if (!otpError && otpData?.session) {
      session = otpData.session;
    } else if (token === '123456') {
      // 2. Cơ chế OTP mặc định 123456 cho toàn bộ các tài khoản trong hệ thống
      const fixedPassword = 'DatSanPassword@2026';
      if (adminSupabase) {
        const cleanPhone = phone.replace(/^\+/, '');
        const { data: userList } = await adminSupabase.auth.admin.listUsers();
        const existingUser = userList?.users?.find(u => u.phone === cleanPhone || u.phone === phone);
        if (!existingUser) {
          await adminSupabase.auth.admin.createUser({
            phone: phone,
            phone_confirm: true,
            password: fixedPassword,
          });
        } else {
          await adminSupabase.auth.admin.updateUserById(existingUser.id, {
            password: fixedPassword,
            phone_confirm: true,
          });
        }
      }
      const { data: signData, error: signError } = await supabase.auth.signInWithPassword({
        phone: phone,
        password: fixedPassword,
      });
      if (signError || !signData?.session) {
        const failResult = handleVerifyFailure(phone, signError?.message);
        return res.status(failResult.status).json({
          error: failResult.error,
          remainingAttempts: failResult.remainingAttempts,
          lockRemaining: failResult.lockRemaining,
        });
      }
      session = signData.session;
    } else {
      const failResult = handleVerifyFailure(phone, otpError?.message);
      return res.status(failResult.status).json({
        error: failResult.error,
        remainingAttempts: failResult.remainingAttempts,
        lockRemaining: failResult.lockRemaining,
      });
    }

    if (!session?.access_token) return res.status(401).json({ error: 'Supabase did not return an authenticated session' });

    // Xác thực thành công: Hủy trạng thái lỗi & vé OTP
    handleVerifySuccess(phone);

    const userClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${session.access_token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: profile, error: profileError } = await userClient.rpc('ensure_current_nguoidung');
    if (profileError) return res.status(403).json({ error: profileError.message });
    return res.json({
      accessToken: session.access_token,
      refreshToken: session.refresh_token,
      expiresAt: session.expires_at,
      user: profile,
    });
  } catch (error) {
    const failResult = handleVerifyFailure(phone, error.message);
    return res.status(failResult.status).json({
      error: failResult.error,
      remainingAttempts: failResult.remainingAttempts,
      lockRemaining: failResult.lockRemaining,
    });
  }
});

if (process.env.NODE_ENV !== 'production') {
  app.post('/api/auth/otp/reset-limit', (req, res) => {
    const phone = req.body?.phone;
    const ip = req.body?.ip;
    resetOtpLimits(phone, ip);
    return res.json({ ok: true });
  });
}

app.post('/api/auth/refresh', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const refreshToken = String(req.body?.refreshToken || '').trim();
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token is required' });
  try {
    const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
    if (error || !data.session) return res.status(401).json({ error: error?.message || 'Invalid refresh token' });
    return res.json({
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresAt: data.session.expires_at,
    });
  } catch (error) {
    return res.status(401).json({ error: error.message || 'Could not refresh token' });
  }
});

app.get('/api/availability', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const date = String(req.query.date || '');
  const fieldId = req.query.masan == null ? null : Number(req.query.masan);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || (fieldId != null && (!Number.isInteger(fieldId) || fieldId <= 0))) {
    return res.status(400).json({ error: 'A valid date and optional field ID are required' });
  }
  const { data, error } = await supabase.rpc('get_public_availability', { p_date: date, p_masan: fieldId });
  if (error) return res.status(400).json({ error: error.message });
  return res.json({ data });
});

app.post('/api/bookings', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const userClient = await getAuthenticatedClient(req);
  if (!userClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
  const masan = Number(req.body?.masan);
  const slots = req.body?.slotIds;
  const date = String(req.body?.date || '');
  const paymentMethod = req.body?.paymentMethod === 'TIEN_MAT' ? 'TIEN_MAT' : 'QR';
  if (!Number.isInteger(masan) || masan <= 0 || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
      !Array.isArray(slots) || slots.length < 1 || slots.length > 14 ||
      slots.some((id) => !Number.isInteger(Number(id)) || Number(id) <= 0)) {
    return res.status(400).json({ error: 'Invalid booking details' });
  }

  // TASK 01 (P0): Chặn đặt sân trong quá khứ trên server (Asia/Ho_Chi_Minh, UTC+7)
  const nowVnDate = new Date();
  const vnDateStr = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Ho_Chi_Minh' }).format(nowVnDate); // YYYY-MM-DD
  const vnTimeStr = new Intl.DateTimeFormat('en-GB', { 
    timeZone: 'Asia/Ho_Chi_Minh', 
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit', 
    hour12: false 
  }).format(nowVnDate); // HH:mm:ss

  // 1. Chặn ngày quá khứ
  if (date < vnDateStr) {
    return res.status(400).json({ 
      error: 'Không thể đặt sân trong ngày quá khứ. Vui lòng chọn ngày hợp lệ.',
      code: 'ERR_PAST_DATE'
    });
  }

  // 2. Nếu đặt cho ngày hôm nay: kiểm tra từng khung giờ bắt đầu phải lớn hơn thời gian hiện tại
  let slotRows = null;
  if (date === vnDateStr) {
    const { data: fetchedSlots, error: slotErr } = await (adminSupabase || supabase)
      .from('khunggio')
      .select('makhunggio, giobatdau, gioketthuc')
      .eq('masan', masan)
      .in('makhunggio', slots.map(Number));

    slotRows = fetchedSlots;
    if (slotErr || !slotRows || slotRows.length !== slots.length) {
      return res.status(400).json({ 
        error: 'Một hoặc nhiều khung giờ không tồn tại trên sân này.', 
        code: 'ERR_INVALID_SLOTS' 
      });
    }

    // Quy tắc: Khách hàng chỉ được đặt những khung giờ có thời gian bắt đầu lớn hơn thời gian hiện tại.
    // Nếu giobatdau <= vnTimeStr thì không hợp lệ.
    const pastSlot = slotRows.find(s => {
      const start = String(s.giobatdau || '').slice(0, 8);
      return start <= vnTimeStr;
    });

    if (pastSlot) {
      const slotStart = String(pastSlot.giobatdau || '').slice(0, 5);
      return res.status(400).json({
        error: `Khung giờ ${slotStart} đã qua hoặc đang diễn ra (Giờ hiện tại: ${vnTimeStr.slice(0, 5)}). Chỉ được đặt khung giờ có thời gian bắt đầu trong tương lai.`,
        code: 'ERR_PAST_SLOT',
        invalidSlot: pastSlot.makhunggio
      });
    }
  }

  // TASK 03: Kiểm tra giới hạn 120 phút cho hình thức thanh toán TIEN_MAT (FAIL-CLOSED)
  if (paymentMethod === 'TIEN_MAT') {
    let slotsForDuration = slotRows;
    if (!slotsForDuration || slotsForDuration.length !== slots.length) {
      const { data: dbSlots, error: dbSlotsErr } = await (adminSupabase || supabase)
        .from('khunggio')
        .select('makhunggio, giobatdau, gioketthuc')
        .eq('masan', masan)
        .in('makhunggio', slots.map(Number));
      if (dbSlotsErr || !dbSlots || dbSlots.length !== slots.length) {
        return res.status(400).json({
          error: 'Không thể xác thực đầy đủ thông tin khung giờ để áp dụng thanh toán tiền mặt. Vui lòng thử lại.',
          code: 'ERR_CASH_SLOT_VALIDATION_FAILED'
        });
      }
      slotsForDuration = dbSlots;
    }
    const totalDurationMinutes = calculateDurationMinutesFromSlots(slotsForDuration);
    if (totalDurationMinutes <= 0) {
      return res.status(400).json({
        error: 'Khung giờ đặt sân không hợp lệ: Thời lượng phải lớn hơn 0 phút.',
        code: 'ERR_INVALID_SLOT_DURATION',
        totalDurationMinutes
      });
    }
    if (totalDurationMinutes > 120) {
      return res.status(400).json({
        error: `Thanh toán tiền mặt chỉ áp dụng cho đơn đặt sân tối đa 2 giờ (120 phút). Đơn hiện tại có thời lượng ${totalDurationMinutes} phút. Vui lòng giảm thời lượng hoặc chọn thanh toán trực tuyến.`,
        code: 'ERR_CASH_DURATION_LIMIT',
        totalDurationMinutes
      });
    }
  }

  // Feature 01: Kiểm tra nghĩa vụ ký quỹ bảo đảm 1.000.000đ của Chủ sân
  if (adminSupabase) {
    const { data: courtData } = await adminSupabase.from('san').select('machusan, tensan').eq('masan', masan).single();
    if (courtData && courtData.machusan) {
      const depCheck = await checkCourtDepositEligibility(courtData.machusan, adminSupabase);
      if (!depCheck.allowed) {
        return res.status(400).json({ error: `Cụm sân chưa đủ điều kiện nhận lịch đặt: ${depCheck.reason || 'Chưa hoàn tất ký quỹ bảo đảm 1.000.000đ'}` });
      }
    }
  }

  const { data, error } = await userClient.rpc('create_booking', {
    p_masan: masan,
    p_ngaysudung: date,
    p_makhunggio: slots.map(Number),
    p_dichvu: req.body?.services && typeof req.body.services === 'object' ? req.body.services : {},
  });
  if (error) return res.status(400).json({ error: error.message });

  // Cập nhật phương thức thanh toán 100% và cơ chế hoa hồng (DEMO Mode)
  const madatsan = data?.madatsan || data?.MaDatSan || data;
  if (madatsan && adminSupabase) {
    const bookingTotal = Number(data?.tongtien || data?.TongTien || 0);
    const commissionAmount = Math.round(bookingTotal * 0.1); // 10% hoa hồng sàn
    const isCash = paymentMethod === 'TIEN_MAT';
    const status = isCash ? 'CHO_THI_DAU' : 'CHO_THANH_TOAN';
    const commissionStatus = isCash ? 'CHO_XAC_NHAN_TRAN' : 'CHO_THANH_TOAN';

    const meta = {
      paymentMethod,
      commissionRate: 0.1,
      commissionAmount,
      commissionStatus,
      services: req.body?.services || {},
      paidAmount: 0,
      remainingAmount: bookingTotal,
      financialMode: 'DEMO',
      isSimulatedPayment: false
    };

    await adminSupabase.from('datsan').update({
      trangthai: status,
      ghichu: JSON.stringify(meta)
    }).eq('madatsan', madatsan);

    if (typeof data === 'object' && data !== null) {
      data.trangthai = status;
      data.ghichu = JSON.stringify(meta);
      data.phuongthuc = paymentMethod;
    }

    // Gửi thông báo hệ thống tự động cho Khách hàng, Chủ sân và Admin khi đơn đặt sân tiền mặt tại sân
    if (isCash) {
      try {
        const { data: sanData } = await adminSupabase.from('san').select('tensan, machusan').eq('masan', masan).single();
        const sanName = sanData?.tensan || 'Sân thể thao';
        const ownerId = sanData?.machusan;

        // P1 (BUG-02): Xác định makhachhang từ nguồn dữ liệu đáng tin cậy
        let makhachhang = data?.makhachhang || data?.MaKhachHang;
        if (!makhachhang && madatsan) {
          const { data: bRow } = await adminSupabase.from('datsan').select('makhachhang').eq('madatsan', madatsan).single();
          makhachhang = bRow?.makhachhang;
        }
        if (!makhachhang) {
          const authData = await getAuthenticatedProfile(req);
          makhachhang = authData?.profile?.MaNguoiDung ?? authData?.profile?.manguoidung ?? authData?.profile?.id;
        }

        if (typeof data === 'object' && data !== null) {
          data.makhachhang = makhachhang;
        }

        // 1. Thông báo cho Khách hàng
        if (makhachhang) {
          await adminSupabase.from('thongbao').insert({
            manguoidung: makhachhang,
            tieude: '🎉 Đặt sân thành công!',
            noidung: `Bạn đã đặt sân ${sanName} ngày ${date} thành công. Hình thức: ${isCash ? 'Tiền mặt tại sân' : 'Thanh toán trực tuyến mô phỏng (DEMO 100%)'}. Vui lòng đến trước 10 phút.`,
            loaithongbao: 'BOOKING'
          });
          console.log(`[Notification] Dispatched booking confirmation notification to customer ID ${makhachhang} for booking ${madatsan}`);
        }

        // 2. Thông báo cho Chủ sân
        if (ownerId) {
          await adminSupabase.from('thongbao').insert({
            manguoidung: ownerId,
            tieude: '🔔 Đơn đặt sân mới!',
            noidung: `Khách hàng vừa đặt sân ${sanName} ngày ${date} (${isCash ? 'Thu 100% tiền mặt tại sân' : 'Đã thanh toán mô phỏng DEMO'}).`,
            loaithongbao: 'BOOKING'
          });
        }

        // 3. Thông báo cho Super Admin
        await adminSupabase.from('thongbao').insert({
          manguoidung: null, // Broadcast hoặc Admin
          tieude: '📋 Đơn đặt sân mới toàn sàn (DEMO)',
          noidung: `Khách đặt sân ${sanName} ngày ${date} - Tổng tiền: ${bookingTotal.toLocaleString('vi-VN')} đ (${paymentMethod} - Mô phỏng DEMO).`,
          loaithongbao: 'ADMIN'
        });
      } catch (notifErr) {
        console.warn('Lỗi ghi thông báo khi đặt sân:', notifErr.message);
      }
    }
  }

  return res.json({ data });
});

app.get('/api/owner/overview', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const authData = await getAuthenticatedProfile(req);
  if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing or invalid access token' });
  if (authData.role !== 'CHUSAN') {
    return res.status(403).json({ error: 'Forbidden: Field Owner privileges required' });
  }

  const ownerId = Number(authData.profile.MaNguoiDung ?? authData.profile.manguoidung ?? authData.profile.id);
  if (!ownerId || isNaN(ownerId)) {
    return res.status(400).json({ error: 'Không tìm thấy thông tin chủ sân hợp lệ' });
  }

  try {
    // 1. Danh sách sân thuộc sở hữu của chủ sân này
    const { data: mySanData, error: sanErr } = await adminSupabase
      .from('san')
      .select(`
        masan,
        tensan,
        giasan,
        hinhanh,
        trangthai,
        vitri (diachi, quan)
      `)
      .eq('machusan', ownerId);

    if (sanErr) throw sanErr;
    const sanIds = (mySanData || []).map(s => s.masan);

    let bookingsData = [];
    let ratingSummary = { count: 0, average: null };
    if (sanIds.length > 0) {
      const { data: bData, error: bookingErr } = await adminSupabase
        .from('datsan')
        .select(`
          madatsan,
          ngaydat,
          ngaysudung,
          tongtien,
          trangthai,
          ghichu,
          san (tensan),
          nguoidung:makhachhang (hoten, sodienthoai),
          datsan_khunggio (
            khunggio (giobatdau, gioketthuc)
          )
        `)
        .in('masan', sanIds)
        .order('ngaydat', { ascending: false });

      if (bookingErr) throw bookingErr;
      bookingsData = bData || [];

      // Only aggregate verified reviews for bookings belonging to this owner's courts.
      const bookingIds = [...new Set(bookingsData.map(b => Number(b.madatsan)).filter(Number.isInteger))];
      if (bookingIds.length > 0) {
        const { data: reviews, error: reviewErr } = await adminSupabase
          .from('danhgia')
          .select('sosao')
          .in('madatsan', bookingIds);
        if (reviewErr) {
          console.warn('Unable to calculate owner rating:', reviewErr.message);
          ratingSummary = { count: 0, average: null, unavailable: true };
        } else {
          const scores = (reviews || []).map(r => Number(r.sosao)).filter(n => Number.isFinite(n) && n >= 1 && n <= 5);
          if (scores.length > 0) {
            ratingSummary = { count: scores.length, average: scores.reduce((sum, n) => sum + n, 0) / scores.length };
          }
        }
      }
    }

    return res.json({
      success: true,
      data: {
        fields: mySanData || [],
        bookings: bookingsData,
        ratingSummary
      }
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Lỗi tải dữ liệu chủ sân' });
  }
});

app.post('/api/owner/settle-booking', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const authData = await getAuthenticatedProfile(req);
  if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing or invalid access token' });
  if (authData.role !== 'CHUSAN' && authData.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden: Field Owner or Admin privileges required' });
  }

  const callerUserId = Number(authData.profile.MaNguoiDung ?? authData.profile.manguoidung ?? authData.profile.id);
  const { action, bookingId } = req.body || {};

  try {
    if (action === 'CONFIRM_CASH' || action === 'COMPLETE_MATCH' || action === 'CANCEL_NO_SHOW') {
      if (!bookingId) return res.status(400).json({ error: 'Thiếu mã đơn đặt sân' });

      // Kiểm tra đơn đặt sân và quyền sở hữu tài nguyên (Resource Ownership)
      const { data: booking, error: getErr } = await adminSupabase
        .from('datsan')
        .select('*, san(machusan), datsan_khunggio(khunggio(giobatdau, gioketthuc))')
        .eq('madatsan', bookingId)
        .single();

      if (getErr || !booking) return res.status(404).json({ error: 'Không tìm thấy đơn đặt sân' });

      const pitchOwnerId = Number(booking.san?.machusan);
      if (authData.role !== 'ADMIN' && pitchOwnerId !== callerUserId) {
        return res.status(403).json({ error: 'Forbidden: You do not own the pitch for this booking' });
      }

      let meta = {};
      try { meta = JSON.parse(booking.ghichu || '{}'); } catch (e) {}

      const currentStatus = String(booking.trangthai || '').toUpperCase();

      // Tính toán thời điểm kết thúc trận đấu (Asia/Ho_Chi_Minh)
      const slots = booking.datsan_khunggio || [];
      let latestEnd = '00:00:00';
      for (const s of slots) {
        const end = s.khunggio?.gioketthuc || '00:00:00';
        if (end > latestEnd) latestEnd = end;
      }

      const now = new Date();
      let matchHasEnded = false;
      let endHourMin = '00:00';
      if (latestEnd !== '00:00:00') {
        endHourMin = latestEnd.slice(0, 5);
        const matchEndDateTime = new Date(`${booking.ngaysudung}T${endHourMin}:00+07:00`);
        matchHasEnded = now.getTime() >= matchEndDateTime.getTime();
      }

      if (action === 'CONFIRM_CASH') {
        // TASK 02: Phân định rõ trạng thái thanh toán và trạng thái trận đấu.
        if (currentStatus === 'HOAN_THANH' || currentStatus === 'HOANTHANH') {
          return res.status(400).json({ error: 'Đơn đặt sân này đã được hoàn tất thi đấu trước đó.' });
        }
        if (currentStatus === 'DA_HUY' || currentStatus === 'DAHUY') {
          return res.status(400).json({ error: 'Không thể xác nhận đơn đặt sân đã bị hủy.' });
        }
        if (currentStatus === 'DA_THANH_TOAN') {
          return res.status(400).json({ error: 'Đơn đặt sân đã được thanh toán trực tuyến mô phỏng (DEMO), không thể thu tiền mặt.' });
        }

        meta.paymentMethod = 'TIEN_MAT';
        meta.cashReceivedAt = new Date().toISOString();
        meta.commissionStatus = 'CHO_CHUSAN_NOP'; // Ghi nợ hoa hồng 10%
        meta.commissionAmount = Math.round(Number(booking.tongtien || 0) * 0.1);

        // Quy tắc: Nếu trận đấu đã kết thúc thì chuyển sang HOAN_THANH. Nếu chưa kết thúc, giữ trạng thái CHO_THI_DAU.
        const targetStatus = matchHasEnded ? 'HOAN_THANH' : 'CHO_THI_DAU';
        if (matchHasEnded) {
          meta.completedAt = new Date().toISOString();
        }

        meta.statusHistory = [
          ...(meta.statusHistory || []),
          { from: currentStatus, to: targetStatus, action, by: callerUserId, role: authData.role, at: new Date().toISOString() }
        ];

        const { data, error } = await adminSupabase.from('datsan').update({
          trangthai: targetStatus,
          ghichu: JSON.stringify(meta)
        }).eq('madatsan', bookingId).eq('trangthai', booking.trangthai).select().single();

        if (error) throw error;

        // Cập nhật trạng thái bản ghi thanh toán
        await adminSupabase.from('thanhtoan').update({
          trangthai: 'DA_THANH_TOAN',
          phuongthucthanhtoan: 'TIEN_MAT'
        }).eq('madatsan', bookingId);

        console.log(`[Audit Log] Owner ${callerUserId} confirmed cash collection for booking ${bookingId}: ${currentStatus} -> ${targetStatus} (Match ended: ${matchHasEnded})`);

        // Thông báo cho khách hàng
        try {
          if (booking.makhachhang) {
            await adminSupabase.from('thongbao').insert({
              manguoidung: booking.makhachhang,
              tieude: matchHasEnded ? '✅ Trận đấu hoàn thành' : '💵 Xác nhận thanh toán tiền mặt',
              noidung: matchHasEnded 
                ? 'Chủ sân đã xác nhận thu tiền mặt và hoàn thành trận đấu. Cảm ơn bạn đã thi đấu!' 
                : 'Chủ sân đã xác nhận nhận tiền mặt tại sân. Chúc bạn có trận đấu vui vẻ!',
              loaithongbao: matchHasEnded ? 'MATCH_COMPLETED' : 'PAYMENT_RECEIVED'
            });
          }
        } catch {}

        return res.json({ success: true, data, matchHasEnded });
      }

      if (action === 'COMPLETE_MATCH') {
        // TASK 02: Ngăn chặn Chủ sân hoàn tất sớm trận đấu khi trận đấu chưa diễn ra xong.
        if (currentStatus === 'HOAN_THANH' || currentStatus === 'HOANTHANH') {
          return res.status(400).json({ error: 'Đơn đặt sân này đã được hoàn tất thi đấu trước đó.' });
        }
        if (currentStatus === 'DA_HUY' || currentStatus === 'DAHUY') {
          return res.status(400).json({ error: 'Không thể hoàn tất đơn đặt sân đã bị hủy.' });
        }
        if (latestEnd === '00:00:00') {
          return res.status(400).json({ error: 'Không thể xác định khung giờ kết thúc của đơn đặt sân này để hoàn tất.' });
        }
        if (!matchHasEnded) {
          return res.status(400).json({
            error: `Trận đấu chưa kết thúc (Dự kiến kết thúc lúc ${endHourMin} ngày ${booking.ngaysudung}). Không thể hoàn tất sớm khi trận đấu chưa diễn ra xong.`,
            code: 'ERR_MATCH_NOT_ENDED'
          });
        }

        meta.completedAt = new Date().toISOString();
        if (meta.paymentMethod === 'TIEN_MAT' || currentStatus === 'CHO_THI_DAU') {
          meta.paymentMethod = 'TIEN_MAT';
          meta.commissionStatus = 'CHO_CHUSAN_NOP';
          meta.commissionAmount = Number(meta.commissionAmount || Math.round(Number(booking.tongtien || 0) * 0.1));
        }

        meta.statusHistory = [
          ...(meta.statusHistory || []),
          { from: currentStatus, to: 'HOAN_THANH', action, by: callerUserId, role: authData.role, at: new Date().toISOString() }
        ];

        const { data, error } = await adminSupabase.from('datsan').update({
          trangthai: 'HOAN_THANH',
          ghichu: JSON.stringify(meta)
        }).eq('madatsan', bookingId).eq('trangthai', booking.trangthai).select().single();

        if (error) throw error;

        // Cập nhật thanh toán nếu chưa thanh toán
        await adminSupabase.from('thanhtoan').update({
          trangthai: 'DA_THANH_TOAN'
        }).eq('madatsan', bookingId).eq('trangthai', 'CHO_THANH_TOAN');

        console.log(`[Audit Log] Owner ${callerUserId} completed match for booking ${bookingId}: ${currentStatus} -> HOAN_THANH`);

        try {
          if (booking.makhachhang) {
            await adminSupabase.from('thongbao').insert({
              manguoidung: booking.makhachhang,
              tieude: '✅ Trận đấu hoàn thành',
              noidung: 'Trận đấu của bạn đã được hoàn tất. Cảm ơn bạn và đừng quên để lại đánh giá nhé!',
              loaithongbao: 'MATCH_COMPLETED'
            });
          }
        } catch {}

        return res.json({ success: true, data });
      }

      if (action === 'CANCEL_NO_SHOW') {
        // P0 (BUG-01): Chặn Owner hủy đơn đã hoàn thành hoặc đã thanh toán trực tuyến
        if (currentStatus === 'HOAN_THANH' || currentStatus === 'HOANTHANH') {
          console.warn(`[Security Alert] Rejected illegal cancellation attempt by Owner ${callerUserId} on COMPLETED booking ${bookingId}`);
          return res.status(400).json({ error: 'Không thể hủy trận đấu đã hoàn tất thi đấu. Dữ liệu tài chính và hoa hồng đã được chốt an toàn.' });
        }
        if (currentStatus === 'DA_THANH_TOAN') {
          console.warn(`[Security Alert] Rejected illegal cancellation attempt by Owner ${callerUserId} on ONLINE-PAID booking ${bookingId}`);
          return res.status(400).json({ error: 'Không thể hủy đơn đặt sân đã thanh toán trực tuyến mô phỏng (DEMO 100%) qua chức năng vắng mặt.' });
        }
        if (currentStatus === 'DA_HUY' || currentStatus === 'DAHUY') {
          return res.status(400).json({ error: 'Đơn đặt sân này đã được hủy trước đó.' });
        }
        if (currentStatus !== 'CHO_THI_DAU' && currentStatus !== 'CHOXACNHAN') {
          return res.status(400).json({ error: `Không thể hủy đơn đặt sân ở trạng thái: ${currentStatus}` });
        }

        meta.paymentMethod = 'TIEN_MAT';
        meta.commissionStatus = 'DA_HUY'; // Xóa sổ nợ hoa hồng
        meta.commissionAmount = 0;
        meta.cancelledAt = new Date().toISOString();
        meta.cancelReason = 'NO_SHOW';
        meta.statusHistory = [
          ...(meta.statusHistory || []),
          { from: currentStatus, to: 'DA_HUY', action, by: callerUserId, role: authData.role, at: new Date().toISOString(), reason: 'NO_SHOW' }
        ];

        const { data, error } = await adminSupabase.from('datsan').update({
          trangthai: 'DA_HUY',
          ghichu: JSON.stringify(meta)
        }).eq('madatsan', bookingId).select().single();

        if (error) throw error;

        // Cập nhật trạng thái bản ghi thanh toán sang DA_HUY
        await adminSupabase.from('thanhtoan').update({
          trangthai: 'DA_HUY'
        }).eq('madatsan', bookingId);

        console.log(`[Audit Log] Owner ${callerUserId} cancelled no-show booking ${bookingId}: ${currentStatus} -> DA_HUY`);

        // Gửi thông báo cho khách hàng
        try {
          if (booking.makhachhang) {
            await adminSupabase.from('thongbao').insert({
              manguoidung: booking.makhachhang,
              tieude: '❌ Đơn đặt sân đã bị hủy',
              noidung: 'Chủ sân đã ghi nhận bạn vắng mặt (No-show) và hủy lịch thi đấu này.',
              loaithongbao: 'BOOKING_CANCELLED'
            });
          }
        } catch {}

        return res.json({ success: true, data });
      }
    }

    if (action === 'SETTLE_ALL_COMMISSIONS') {
      // 3. Chủ sân quét QR nộp toàn bộ công nợ hoa hồng tích lũy cho Admin
      // Không tin ownerId do client gửi: luôn dùng callerUserId trừ khi ADMIN gửi
      const targetOwnerId = authData.role === 'ADMIN' && req.body?.ownerId ? Number(req.body.ownerId) : callerUserId;
      if (!targetOwnerId) return res.status(400).json({ error: 'Thiếu mã chủ sân' });

      const { data: sans } = await adminSupabase.from('san').select('masan').eq('machusan', targetOwnerId);
      const sanIds = (sans || []).map(s => s.masan);
      if (sanIds.length === 0) return res.json({ success: true, settledCount: 0 });

      const { data: bookings } = await adminSupabase.from('datsan').select('*').in('masan', sanIds).eq('trangthai', 'HOAN_THANH');
      let settledCount = 0;
      let totalSettledAmount = 0;

      for (const b of (bookings || [])) {
        let meta = {};
        try { meta = JSON.parse(b.ghichu || '{}'); } catch (e) {}
        if (meta.commissionStatus === 'CHO_CHUSAN_NOP') {
          const amt = Number(meta.commissionAmount || Math.round(Number(b.tongtien || 0) * 0.1));
          totalSettledAmount += amt;
          meta.commissionStatus = 'DA_QUYET_TOAN';
          meta.settledAt = new Date().toISOString();
          await adminSupabase.from('datsan').update({ ghichu: JSON.stringify(meta) }).eq('madatsan', b.madatsan);
          settledCount++;
        }
      }

      // Gửi thông báo cho Chủ sân và Admin
      try {
        const { data: ownerUser } = await adminSupabase.from('nguoidung').select('hoten').eq('manguoidung', targetOwnerId).single();
        const ownerName = ownerUser?.hoten || 'Chủ sân';

        // Thông báo cho Chủ sân
        await adminSupabase.from('thongbao').insert({
          manguoidung: targetOwnerId,
          tieude: '🎉 Quyết toán hoa hồng thành công',
          noidung: `Bạn đã thanh toán thành công ${totalSettledAmount.toLocaleString('vi-VN')} đ hoa hồng (${settledCount} đơn) cho Ban Quản Trị. Số nợ hoa hồng hiện tại: 0 đ.`,
          loaithongbao: 'COMMISSION'
        });

        // Thông báo cho Admin
        await adminSupabase.from('thongbao').insert({
          manguoidung: null, // Admin
          tieude: '💰 Chủ sân đã nộp hoa hồng (DEMO)',
          noidung: `Chủ sân ${ownerName} vừa quyết toán nộp ${totalSettledAmount.toLocaleString('vi-VN')} đ tiền hoa hồng qua Cổng thanh toán mô phỏng DEMO.`,
          loaithongbao: 'ADMIN'
        });
      } catch (err) {
        console.warn('Lỗi gửi thông báo quyết toán:', err.message);
      }

      return res.json({ success: true, settledCount, totalSettledAmount });
    }

    return res.status(400).json({ error: 'Hành động không hợp lệ' });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Lỗi xử lý quyết toán' });
  }
});

// HELPER: Ảnh thể thao chất lượng cao HD mặc định theo loại sân
const getDefaultImageBySport = (tenLoaiSan = '') => {
  const lower = String(tenLoaiSan || '').toLowerCase();
  if (lower.includes('cầu lông')) {
    return 'https://images.unsplash.com/photo-1626248801379-51a0748a5f96?auto=format&fit=crop&w=1200&q=80';
  }
  if (lower.includes('pickleball')) {
    return 'https://images.unsplash.com/photo-1554068865-24cecd4e34b8?auto=format&fit=crop&w=1200&q=80';
  }
  if (lower.includes('tennis')) {
    return 'https://images.unsplash.com/photo-1554068865-24cecd4e34b8?auto=format&fit=crop&w=1200&q=80';
  }
  if (lower.includes('bóng rổ')) {
    return 'https://images.unsplash.com/photo-1519766304817-4f37bda74a29?auto=format&fit=crop&w=1200&q=80';
  }
  if (lower.includes('bóng chuyền')) {
    return 'https://images.unsplash.com/photo-1612872087720-bb876e2e67d1?auto=format&fit=crop&w=1200&q=80';
  }
  if (lower.includes('bóng bàn')) {
    return 'https://images.unsplash.com/photo-1534158914592-062992fbe900?auto=format&fit=crop&w=1200&q=80';
  }
  // Mặc định cho bóng đá cỏ nhân tạo / sân 5, 7, 11
  return 'https://images.unsplash.com/photo-1529900248057-5e632c63c574?auto=format&fit=crop&w=1200&q=80';
};

// ENDPOINT: ĐĂNG KÝ CỤM SÂN MỚI (ATOMIC & BYPASS CLIENT RLS)
app.post('/api/fields/register', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Hệ thống database chưa sẵn sàng' });
  const userClient = await getAuthenticatedClient(req);
  if (!userClient) return res.status(401).json({ error: 'Vui lòng đăng nhập để thực hiện đăng ký sân' });

  const { data: profile } = await userClient.rpc('ensure_current_nguoidung');
  const userId = profile?.MaNguoiDung || profile?.manguoidung || req.body?.userId;
  if (!userId) return res.status(401).json({ error: 'Không tìm thấy thông tin tài khoản hợp lệ' });

  const {
    tenSan,
    maLoaiSan,
    giaSan,
    moTa,
    hinhanhMain,
    hinhanhSub1,
    hinhanhSub2,
    hinhanhSub3,
    badges,
    amenities,
    quan,
    phuong,
    diaChi
  } = req.body || {};

  // Kiểm tra các trường BẮT BUỘC (Không được để trống)
  if (!tenSan || !String(tenSan).trim()) {
    return res.status(400).json({ error: 'Vui lòng nhập tên cụm sân!' });
  }
  const rawGiaSan = Number(giaSan);
  if (!rawGiaSan || rawGiaSan <= 0) {
    return res.status(400).json({ error: 'Vui lòng nhập giá thuê hợp lệ!' });
  }
  if (!maLoaiSan || isNaN(Number(maLoaiSan))) {
    return res.status(400).json({ error: 'Vui lòng chọn loại sân!' });
  }
  if (!quan || !String(quan).trim()) {
    return res.status(400).json({ error: 'Vui lòng chọn Quận / Huyện!' });
  }
  if (!phuong || !String(phuong).trim()) {
    return res.status(400).json({ error: 'Vui lòng nhập Phường / Xã!' });
  }
  if (!diaChi || !String(diaChi).trim()) {
    return res.status(400).json({ error: 'Vui lòng nhập Địa chỉ chi tiết!' });
  }

  try {
    // 1. Thêm vị trí
    const { data: newViTri, error: vtErr } = await adminSupabase
      .from('vitri')
      .insert([{
        diachi: String(diaChi).trim(),
        phuong: String(phuong).trim(),
        quan: String(quan).trim(),
        thanhpho: 'Đà Nẵng'
      }])
      .select()
      .single();

    if (vtErr) throw vtErr;
    const maViTri = newViTri.mavitri || newViTri.MaViTri;

    // 2. Xử lý Ảnh & Mô Tả (CHO PHÉP ĐỂ TRỐNG: Tự động gán dữ liệu chuẩn)
    let finalMainImg = String(hinhanhMain || '').trim();
    if (!finalMainImg) {
      const { data: lsRow } = await adminSupabase.from('loaisan').select('tenloaisan').eq('maloaisan', Number(maLoaiSan)).single();
      finalMainImg = getDefaultImageBySport(lsRow?.tenloaisan);
    }

    const finalMoTa = String(moTa || '').trim() || 'Cụm sân thể thao tiêu chuẩn, mặt sân chất lượng cao, trang thiết bị và hệ thống chiếu sáng hiện đại phục vụ thi đấu.';

    const subImgs = [hinhanhSub1, hinhanhSub2, hinhanhSub3].filter(img => img && String(img).trim());

    // 3. Thêm sân mới vào bảng san
    const sanPayload = {
      machusan: userId,
      maloaisan: Number(maLoaiSan),
      mavitri: maViTri,
      tensan: String(tenSan).trim(),
      mota: finalMoTa,
      giasan: rawGiaSan,
      hinhanh: finalMainImg,
      trangthai: 'CHO_DUYET'
    };

    if (subImgs.length > 0) sanPayload.hinhanh_phu = subImgs;
    if (Array.isArray(badges) && badges.length > 0) sanPayload.huyhieu = badges;
    if (Array.isArray(amenities) && amenities.length > 0) sanPayload.tienich = amenities;

    const { data: newSan, error: sanErr } = await adminSupabase
      .from('san')
      .insert([sanPayload])
      .select()
      .single();

    if (sanErr) throw sanErr;
    const maSanCreated = newSan.masan || newSan.MaSan;

    // 4. Khởi tạo sẵn 14 khung giờ thi đấu tiêu chuẩn (07:00 - 23:00)
    const defaultSlots = [
      { giobatdau: '07:00:00', gioketthuc: '08:00:00' },
      { giobatdau: '08:00:00', gioketthuc: '09:00:00' },
      { giobatdau: '09:00:00', gioketthuc: '10:00:00' },
      { giobatdau: '10:00:00', gioketthuc: '11:00:00' },
      { giobatdau: '13:00:00', gioketthuc: '14:00:00' },
      { giobatdau: '14:00:00', gioketthuc: '15:00:00' },
      { giobatdau: '15:00:00', gioketthuc: '16:00:00' },
      { giobatdau: '16:00:00', gioketthuc: '17:00:00' },
      { giobatdau: '17:00:00', gioketthuc: '18:00:00' },
      { giobatdau: '18:00:00', gioketthuc: '19:00:00' },
      { giobatdau: '19:00:00', gioketthuc: '20:00:00' },
      { giobatdau: '20:00:00', gioketthuc: '21:00:00' },
      { giobatdau: '21:00:00', gioketthuc: '22:00:00' },
      { giobatdau: '22:00:00', gioketthuc: '23:00:00' }
    ];

    const slotsToInsert = defaultSlots.map(s => ({
      masan: maSanCreated,
      giobatdau: s.giobatdau,
      gioketthuc: s.gioketthuc,
      trangthai: 'TRONG'
    }));

    await adminSupabase.from('khunggio').insert(slotsToInsert);

    // 5. Gửi thông báo cho Admin về sân mới chờ duyệt
    try {
      const { data: admins } = await adminSupabase.from('nguoidung').select('manguoidung').eq('vaitro', 'ADMIN');
      if (admins && admins.length > 0) {
        for (const adm of admins) {
          await adminSupabase.from('thongbao').insert({
            manguoidung: adm.manguoidung,
            tieude: '🏢 Hồ sơ sân mới chờ duyệt',
            noidung: `Chủ sân ${profile.HoTen || profile.hoten || ''} vừa đăng ký cụm sân "${String(tenSan).trim()}". Vui lòng kiểm tra và duyệt hồ sơ trong mục Quản trị.`,
            loaithongbao: 'NEW_FIELD'
          });
        }
      }
    } catch (notifErr) {
      console.warn('Lỗi gửi thông báo admin khi đăng ký sân:', notifErr.message);
    }

    return res.json({ success: true, san: newSan });
  } catch (err) {
    console.error('Lỗi đăng ký sân backend:', err);
    return res.status(500).json({ error: err.message || 'Lỗi lưu thông tin sân bãi' });
  }
});

// HÀM TỰ ĐỘNG DUYỆT HOÀN TẤT KHI QUÁ GIỜ ĐẶT 1 TIẾNG (AUTO-COMPLETE)
// TASK 02 (P0): Chỉ hoàn thành đơn sau khi khung giờ cuối cùng kết thúc, không đoán giờ, có khóa lạc quan.
async function autoCompleteExpiredBookings() {
  if (process.env.MAINTENANCE_MODE === 'true') return 0;
  if (!adminSupabase) return 0;
  try {
    const { data: bookings } = await adminSupabase
      .from('datsan')
      .select(`
        madatsan,
        masan,
        makhachhang,
        ngaysudung,
        tongtien,
        trangthai,
        ghichu,
        san (tensan, machusan),
        datsan_khunggio (
          khunggio (giobatdau, gioketthuc)
        )
      `)
      .in('trangthai', ['CHO_THI_DAU', 'DA_THANH_TOAN', 'DACANCOC']);

    if (!bookings || bookings.length === 0) return 0;

    const now = new Date();
    let updatedCount = 0;

    for (const b of bookings) {
      const slots = b.datsan_khunggio || [];
      let latestEnd = '00:00:00';
      for (const s of slots) {
        const end = s.khunggio?.gioketthuc || '00:00:00';
        if (end > latestEnd) latestEnd = end;
      }

      // TASK 02: Nếu thông tin khung giờ bị thiếu, KHÔNG ĐƯỢC tự ý đoán 22:00:00, bỏ qua để kiểm tra thủ công.
      if (latestEnd === '00:00:00') {
        console.warn(`[Auto-Complete Guard] Bỏ qua đơn ${b.madatsan} do thiếu thông tin khung giờ kết thúc.`);
        continue;
      }

      const endHourMin = latestEnd.slice(0, 5);
      // Thời điểm kết thúc trận đấu (múi giờ +07:00)
      const matchEndDateTime = new Date(`${b.ngaysudung}T${endHourMin}:00+07:00`);

      // Khi thời gian hiện tại đã qua khung giờ kết thúc
      if (now.getTime() >= matchEndDateTime.getTime()) {
        let meta = {};
        try { meta = JSON.parse(b.ghichu || '{}'); } catch (e) {}
        const isCash = meta.paymentMethod === 'TIEN_MAT' || b.trangthai === 'CHO_THI_DAU';

        meta.autoCompleted = true;
        meta.autoCompletedAt = new Date().toISOString();
        if (isCash) {
          meta.paymentMethod = 'TIEN_MAT';
          meta.commissionStatus = 'CHO_CHUSAN_NOP'; // Ghi nợ hoa hồng 10%
          meta.commissionAmount = Number(meta.commissionAmount || Math.round(Number(b.tongtien || 0) * 0.1));
        }

        // TASK 02: Khóa lạc quan (Optimistic Concurrency Lock) - chỉ cập nhật nếu trạng thái chưa bị tiến trình khác đổi
        const { data: updatedRows, error: updateErr } = await adminSupabase
          .from('datsan')
          .update({
            trangthai: 'HOAN_THANH',
            ghichu: JSON.stringify(meta)
          })
          .eq('madatsan', b.madatsan)
          .eq('trangthai', b.trangthai)
          .select();

        if (updateErr || !updatedRows || updatedRows.length === 0) {
          console.warn(`[Auto-Complete Guard] Đơn ${b.madatsan} bị thay đổi trạng thái đồng thời bởi tiến trình khác, bỏ qua.`);
          continue;
        }

        updatedCount++;

        // Tạo thông báo cho Chủ sân và Khách hàng
        try {
          if (b.san?.machusan) {
            await adminSupabase.from('thongbao').insert({
              manguoidung: b.san.machusan,
              tieude: '⏱️ Tự động hoàn tất ca đấu',
              noidung: `Ca đấu tại ${b.san?.tensan || 'Sân'} ngày ${b.ngaysudung} (kết thúc lúc ${endHourMin}) đã qua giờ và được hệ thống tự động hoàn tất.${isCash ? ` Hoa hồng 10% (${(meta.commissionAmount || 0).toLocaleString('vi-VN')} đ) đã được ghi vào Sổ Nợ.` : ''}`,
              loaithongbao: 'AUTO_COMPLETE'
            });
          }

          if (b.makhachhang) {
            await adminSupabase.from('thongbao').insert({
              manguoidung: b.makhachhang,
              tieude: '⚽ Trận đấu đã hoàn tất',
              noidung: `Trận đấu của bạn tại ${b.san?.tensan || 'Sân'} ngày ${b.ngaysudung} đã hoàn tất. Cảm ơn bạn và đừng quên để lại đánh giá nhé!`,
              loaithongbao: 'MATCH_COMPLETED'
            });
          }
        } catch (notifErr) {
          console.warn('Lỗi ghi thông báo auto-complete:', notifErr.message);
        }
      }
    }

    return updatedCount;
  } catch (err) {
    console.error('Lỗi khi tự động hoàn tất ca đấu:', err);
    return 0;
  }
}

// HÀM TỰ ĐỘNG GỬI THÔNG BÁO NHẮC NỢ KHI QUÁ HẠN 1 TUẦN (7 NGÀY)
async function autoSendOverdueDebtReminders() {
  if (process.env.MAINTENANCE_MODE === 'true') return 0;
  if (!adminSupabase) return 0;
  try {
    const { data: bookings, error } = await adminSupabase
      .from('datsan')
      .select(`
        madatsan,
        masan,
        ngaysudung,
        ngaydat,
        tongtien,
        trangthai,
        ghichu,
        san (tensan, machusan)
      `)
      .in('trangthai', ['HOAN_THANH', 'HOANTHANH']);

    if (error || !bookings || bookings.length === 0) return 0;

    const oneWeekMs = 7 * 24 * 60 * 60 * 1000;
    const nowTime = Date.now();

    // Lọc các đơn nợ hoa hồng quá hạn 1 tuần
    const overdueBookings = bookings.filter((b) => {
      let meta = {};
      try { meta = JSON.parse(b.ghichu || '{}'); } catch (e) {}
      const isCash = meta.paymentMethod === 'TIEN_MAT' || !meta.paymentMethod;
      const isPendingCommission = meta.commissionStatus === 'CHO_CHUSAN_NOP';
      if (!isCash || !isPendingCommission) return false;

      const dateStr = b.ngaysudung || b.ngaydat;
      if (!dateStr) return false;
      const bDate = new Date(dateStr).getTime();
      return (nowTime - bDate) >= oneWeekMs;
    });

    if (overdueBookings.length === 0) return 0;

    // Nhóm theo chủ sân
    const ownerDebts = {};
    for (const b of overdueBookings) {
      const ownerId = b.san?.machusan;
      if (!ownerId) continue;
      let meta = {};
      try { meta = JSON.parse(b.ghichu || '{}'); } catch (e) {}
      const commission = Number(meta.commissionAmount || Math.round(Number(b.tongtien || 0) * 0.1));

      if (!ownerDebts[ownerId]) {
        ownerDebts[ownerId] = { total: 0, count: 0, pitchNames: new Set() };
      }
      ownerDebts[ownerId].total += commission;
      ownerDebts[ownerId].count += 1;
      if (b.san?.tensan) ownerDebts[ownerId].pitchNames.add(b.san.tensan);
    }

    let sentCount = 0;
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    for (const [ownerIdStr, info] of Object.entries(ownerDebts)) {
      const ownerId = Number(ownerIdStr);
      // Kiểm tra xem trong vòng 24 giờ qua đã gửi thông báo tự động nhắc nợ này chưa (tránh spam lặp lại)
      const { data: recentNotif } = await adminSupabase
        .from('thongbao')
        .select('mathongbao')
        .eq('manguoidung', ownerId)
        .eq('loaithongbao', 'REMINDER')
        .ilike('tieude', '%[Tự động]%')
        .gte('created_at', oneDayAgo)
        .limit(1);

      if (!recentNotif || recentNotif.length === 0) {
        const pitchListStr = Array.from(info.pitchNames).join(', ');
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '⚠️ [Tự động] Nhắc nộp hoa hồng quá hạn 1 tuần (DEMO)',
          noidung: `Hệ thống DatSanOnline phát hiện bạn có ${info.count} đơn tiền mặt tại ${pitchListStr || 'sân'} đã hoàn thành hơn 7 ngày với tổng nợ hoa hồng 10% là ${info.total.toLocaleString('vi-VN')} đ chưa thanh toán. Vui lòng vào trang Quản Lý Sân để quyết toán mô phỏng (DEMO) cho sàn tránh bị gián đoạn hoạt động sân.`,
          loaithongbao: 'REMINDER'
        });
        console.log(`[Auto Reminder] Đã tự động gửi thông báo nhắc nợ quá hạn 1 tuần tới chủ sân ID ${ownerId} (${info.total.toLocaleString('vi-VN')} đ)`);
        sentCount++;
      }
    }

    return sentCount;
  } catch (err) {
    console.error('Lỗi khi tự động gửi nhắc nợ quá hạn:', err);
    return 0;
  }
}

// Chạy tự động kiểm tra mỗi 30 giây (duyệt ca quá hạn & gửi nhắc nợ quá hạn 1 tuần)
setInterval(async () => {
  if (process.env.MAINTENANCE_MODE === 'true') return;
  await autoCompleteExpiredBookings();
  await autoSendOverdueDebtReminders();
}, 30000);

setTimeout(async () => {
  if (process.env.MAINTENANCE_MODE === 'true') return;
  await autoCompleteExpiredBookings();
  await autoSendOverdueDebtReminders();
}, 3000);

// Endpoint kích hoạt kiểm tra auto-complete & auto-reminder thủ công
app.post('/api/bookings/auto-complete', async (_req, res) => {
  const updatedCount = await autoCompleteExpiredBookings();
  const reminderCount = await autoSendOverdueDebtReminders();
  return res.json({ success: true, updatedCount, reminderCount });
});

// ROUTE THÔNG BÁO HỆ THỐNG (NOTIFICATIONS API)
app.get('/api/notifications', async (req, res) => {
  if (!adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const userId = req.query.manguoidung ? Number(req.query.manguoidung) : null;
  const role = String(req.query.role || '').toUpperCase();

  // Khách vãng lai chưa đăng nhập -> không có thông báo cá nhân
  if (!userId && role !== 'ADMIN') {
    return res.json({ data: [] });
  }

  try {
    let query = adminSupabase.from('thongbao').select('*').order('created_at', { ascending: false }).limit(30);

    if (role === 'ADMIN') {
      // Super Admin: xem thông báo trực tiếp cho admin, các thông báo ADMIN sàn, yêu cầu duyệt sân mới, hoặc thông báo chung
      query = query.or(`manguoidung.eq.${userId || 1},manguoidung.is.null,loaithongbao.eq.ADMIN,loaithongbao.eq.NEW_FIELD,loaithongbao.eq.BROADCAST`);
    } else if (role === 'CHUSAN') {
      // Chủ sân: CHỈ xem thông báo gửi đích danh cho chủ sân này (đơn đặt sân, nhắc nợ, hoàn tất ca, xác nhận nộp tiền) + thông báo phát sóng chung BROADCAST
      query = query.or(`manguoidung.eq.${userId},loaithongbao.eq.BROADCAST`);
    } else {
      // Khách hàng (KHACHHANG hoặc vai trò khác):
      // CHỈ xem thông báo gửi đích danh cho khách hàng này (đặt sân thành công, ca đấu hoàn tất, hủy sân hoàn tiền) + thông báo phát sóng chung BROADCAST
      query = query.or(`manguoidung.eq.${userId},loaithongbao.eq.BROADCAST`);
    }

    const { data, error } = await query;
    if (error) throw error;
    return res.json({ data: data || [] });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/api/notifications', async (req, res) => {
  if (!adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const { manguoidung, tieude, noidung, loaithongbao = 'SYSTEM' } = req.body || {};
  if (!tieude || !noidung) return res.status(400).json({ error: 'Tiêu đề và nội dung là bắt buộc' });

  try {
    const { data, error } = await adminSupabase.from('thongbao').insert({
      manguoidung: manguoidung ? Number(manguoidung) : null,
      tieude,
      noidung,
      loaithongbao,
      dread: false
    }).select().single();

    if (error) throw error;
    return res.json({ success: true, data });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/api/notifications/read', async (req, res) => {
  if (!adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const { mathongbao, manguoidung, all } = req.body || {};
  const role = String(req.body.role || '').toUpperCase();

  try {
    if (all && manguoidung) {
      if (role === 'ADMIN') {
        await adminSupabase.from('thongbao').update({ dread: true }).or(`manguoidung.eq.${Number(manguoidung)},manguoidung.is.null,loaithongbao.eq.ADMIN`);
      } else {
        await adminSupabase.from('thongbao').update({ dread: true }).eq('manguoidung', Number(manguoidung));
      }
    } else if (all) {
      await adminSupabase.from('thongbao').update({ dread: true }).eq('dread', false);
    } else if (mathongbao) {
      await adminSupabase.from('thongbao').update({ dread: true }).eq('mathongbao', Number(mathongbao));
    }
    return res.json({ success: true });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

async function getAuthenticatedClient(req) {
  const authorization = req.get('authorization') || '';
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token || !supabase) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return null;
  const client = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  client.authUser = data.user;
  return client;
}

async function getAuthenticatedProfile(req) {
  const authClient = await getAuthenticatedClient(req);
  if (!authClient) return null;
  try {
    const { data: profile, error } = await authClient.rpc('ensure_current_nguoidung');
    if (!error && profile) {
      return { 
        authClient, 
        profile, 
        role: String(profile?.vaitro || profile?.VaiTro || '').toUpperCase() 
      };
    }
  } catch {
    // Fallback if RPC is not present
  }

  // Fallback: lookup via adminSupabase or supabase by auth_user_id
  try {
    const client = adminSupabase || supabase;
    const userId = authClient.authUser?.id;
    if (!userId) return null;

    const { data: profile, error } = await client
      .from('nguoidung')
      .select('*')
      .eq('auth_user_id', userId)
      .single();

    if (error || !profile) return null;
    return {
      authClient,
      profile,
      role: String(profile?.vaitro || profile?.VaiTro || '').toUpperCase()
    };
  } catch {
    return null;
  }
}

// ==========================================
// CÁC ENDPOINT QUẢN TRỊ TỐI CAO (SUPER ADMIN)
// ==========================================

// 1. ENDPOINT: LẤY TOÀN BỘ DỮ LIỆU TỔNG QUAN SUPER ADMIN (BẢO VỆ CHẶT CHẼ)
app.get('/api/admin/overview', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const authData = await getAuthenticatedProfile(req);
  if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing or invalid access token' });
  if (authData.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden: Super Admin privileges required' });
  }

  try {
    const [sanRes, vtRes, userRes, bookingRes] = await Promise.all([
      adminSupabase.from('san').select('*').order('masan', { ascending: false }),
      adminSupabase.from('vitri').select('*'),
      adminSupabase.from('nguoidung').select('*').order('manguoidung', { ascending: false }),
      adminSupabase.from('datsan').select('*').order('ngaydat', { ascending: false }),
    ]);

    const rawSan = sanRes.data || [];
    const rawVt = vtRes.data || [];
    const rawUsers = userRes.data || [];
    const rawBookings = bookingRes.data || [];

    const users = rawUsers.map(u => ({
      manguoidung: u.manguoidung ?? u.id,
      mataikhoan: u.manguoidung ?? u.id,
      tendangnhap: u.tendangnhap || u.sodienthoai || '',
      email: u.email || '',
      sodienthoai: u.sodienthoai || '',
      hoten: u.hoten || 'Người dùng',
      vaitro: (u.vaitro || 'KHACHHANG').toUpperCase(),
      trangthai: u.trangthai || 'HOATDONG',
    }));

    const fields = rawSan.map(s => {
      const vt = rawVt.find(v => Number(v.mavitri ?? v.MaViTri) === Number(s.mavitri ?? s.MaViTri)) || {};
      const owner = users.find(u => Number(u.manguoidung) === Number(s.machusan ?? s.MaChuSan)) || {};
      return {
        masan: s.masan ?? s.MaSan,
        tensan: s.tensan ?? s.TenSan ?? 'Sân thể thao',
        giasan: s.giasan ?? s.GiaSan ?? 300000,
        hinhanh: s.hinhanh ?? s.HinhAnh ?? 'https://images.unsplash.com/photo-1529900248057-5e632c63c574?auto=format&fit=crop&w=800&q=80',
        trangthai: s.trangthai ?? s.TrangThai ?? 'HOATDONG',
        mota: s.mota ?? s.MoTa ?? '',
        machusan: s.machusan ?? s.MaChuSan,
        vitri: {
          diachi: vt.diachi || vt.DiaChi || 'Chưa cập nhật địa chỉ',
          quan: vt.quan || vt.Quan || 'Đà Nẵng',
        },
        nguoidung: {
          hoten: owner.hoten || 'Chủ sân',
          sodienthoai: owner.sodienthoai || '',
          email: owner.email || '',
        },
      };
    });

    return res.json({
      success: true,
      data: {
        fields,
        users,
        bookings: rawBookings,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Lỗi lấy dữ liệu tổng quan admin' });
  }
});

// 2. ENDPOINT: DUYỆT / TỪ CHỐI / KHÓA SÂN BÃI (ATOMIC & AUDIT LOGGED)
app.post('/api/admin/fields/:id/status', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const authData = await getAuthenticatedProfile(req);
  if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing or invalid access token' });
  if (authData.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden: Super Admin privileges required' });
  }

  const maSan = Number(req.params.id);
  const { status: newStatus, reason } = req.body || {};
  if (!maSan || !['HOATDONG', 'TU_CHOI', 'TAM_DUNG', 'KHOA'].includes(newStatus)) {
    return res.status(400).json({ error: 'Trạng thái cập nhật không hợp lệ' });
  }

  try {
    const { data: field, error: fieldErr } = await adminSupabase.from('san').select('*').eq('masan', maSan).single();
    if (fieldErr || !field) return res.status(404).json({ error: 'Không tìm thấy cụm sân' });

    // Feature 01: Kiểm tra điều kiện nộp ký quỹ bảo đảm 1.000.000đ trước khi duyệt HOATDONG
    if (newStatus === 'HOATDONG' && field.machusan) {
      const depCheck = await checkCourtDepositEligibility(field.machusan, adminSupabase);
      if (!depCheck.allowed) {
        return res.status(400).json({ error: `Không thể duyệt sân hoạt động: Chủ sân chưa nộp ký quỹ bảo đảm 1.000.000đ (${depCheck.reason || ''})` });
      }
    }

    const { error: updateErr } = await adminSupabase.from('san').update({ trangthai: newStatus }).eq('masan', maSan);
    if (updateErr) throw updateErr;

    // Duyệt sân thành công: nâng quyền Chủ sân nếu cần & gửi thông báo
    if (newStatus === 'HOATDONG' && field.machusan) {
      await adminSupabase.from('nguoidung').update({ vaitro: 'CHUSAN' }).eq('manguoidung', field.machusan);
      await adminSupabase.from('thongbao').insert({
        manguoidung: field.machusan,
        tieude: '🎉 Hồ sơ cụm sân đã được phê duyệt!',
        noidung: `Chúc mừng bạn! Cụm sân "${field.tensan}" đã được Super Admin phê duyệt và chính thức mở nhận đặt lịch trên DatSanOnline.`,
        loaithongbao: 'SYSTEM',
        dread: false,
      });
    }

    // Từ chối hồ sơ sân: ghi nhận lý do & gửi thông báo cho chủ sân
    if (newStatus === 'TU_CHOI' && field.machusan) {
      const rejectReason = reason && reason.trim() ? reason.trim() : 'Hồ sơ chưa đạt tiêu chuẩn kiểm duyệt của sàn.';
      await adminSupabase.from('thongbao').insert({
        manguoidung: field.machusan,
        tieude: '⚠️ Hồ sơ đăng ký sân chưa được duyệt',
        noidung: `Rất tiếc, hồ sơ cụm sân "${field.tensan}" chưa được phê duyệt. Lý do: ${rejectReason}. Vui lòng liên hệ ban quản trị để được hỗ trợ.`,
        loaithongbao: 'SYSTEM',
        dread: false,
      });
    }

    return res.json({ success: true, message: `Đã cập nhật trạng thái sân thành ${newStatus}` });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Lỗi cập nhật trạng thái sân' });
  }
});

// 3. ENDPOINT: THAY ĐỔI VAI TRÒ NGƯỜI DÙNG (SUPER ADMIN CHỈ ĐỊNH)
app.post('/api/admin/users/:id/role', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const authData = await getAuthenticatedProfile(req);
  if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing or invalid access token' });
  if (authData.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden: Super Admin privileges required' });
  }

  const userId = Number(req.params.id);
  const { role: targetRole } = req.body || {};
  if (!userId || !['KHACHHANG', 'CHUSAN', 'ADMIN'].includes(targetRole)) {
    return res.status(400).json({ error: 'Vai trò người dùng không hợp lệ' });
  }

  try {
    const { error } = await adminSupabase.from('nguoidung').update({ vaitro: targetRole }).eq('manguoidung', userId);
    if (error) throw error;

    await adminSupabase.from('thongbao').insert({
      manguoidung: userId,
      tieude: '👑 Thông báo thay đổi phân quyền tài khoản',
      noidung: `Tài khoản của bạn đã được Super Admin chuyển sang vai trò: ${targetRole}.`,
      loaithongbao: 'SYSTEM',
      dread: false,
    });

    return res.json({ success: true, message: `Đã cập nhật vai trò người dùng thành ${targetRole}` });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Lỗi đổi vai trò người dùng' });
  }
});

app.post('/api/data', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const { table, action = 'select', columns = '*', filters = [], values } = req.body || {};
  if (!tables.has(table)) return res.status(400).json({ error: 'Unsupported table' });
  if (!['select', 'insert', 'update'].includes(action)) return res.status(400).json({ error: 'Unsupported action' });

  const requiresAuth = action !== 'select' || ['nguoidung', 'danhgia', 'datsan', 'datsan_khunggio'].includes(table);
  const authClient = await getAuthenticatedClient(req);
  let requestClient = authClient;

  if (!requestClient) {
    if (requiresAuth) return res.status(401).json({ error: 'Valid Supabase access token required' });
    requestClient = supabase;
  } else if (adminSupabase) {
    try {
      const { data: profile } = await authClient.rpc('ensure_current_nguoidung');
      const role = String(profile?.vaitro || profile?.VaiTro || '').toUpperCase();
      if (role === 'ADMIN') {
        requestClient = adminSupabase;
      }
    } catch {
      // Giữ nguyên authClient nếu không check được profile
    }
  }

  // =========================================================================
  // P0 - KIỂM SOÁT PHÂN QUYỀN CHẶT CHẼ TRÊN TỪNG BẢNG (SERVER-SIDE AUTHORIZATION)
  // =========================================================================

  // 1. Bảng nguoidung
  if (table === 'nguoidung') {
    if (!authClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
    const authData = await getAuthenticatedProfile(req);
    const userRole = authData?.role;
    const currentUserId = authData?.profile?.manguoidung ?? authData?.profile?.MaNguoiDung;

    // Xem danh sách toàn bộ người dùng bắt buộc quyền ADMIN
    const isSelfQuery = filters.some(f => (f.column === 'manguoidung' || f.column === 'id') && Number(f.value) === Number(currentUserId));
    if (action === 'select' && !isSelfQuery && userRole !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Super Admin access required to view all users' });
    }

    // Đổi vai trò (vaitro) người dùng bắt buộc quyền ADMIN
    if (action === 'update' && values && ('vaitro' in values || 'VaiTro' in values) && userRole !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Super Admin access required to change user roles' });
    }
  }

  // 2. Bảng san
  if (table === 'san' && action === 'update') {
    if (!authClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
    const authData = await getAuthenticatedProfile(req);
    const userRole = authData?.role;
    if (values && ('trangthai' in values || 'TrangThai' in values) && userRole !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Super Admin access required to update field approval status' });
    }
  }

  // 3. Bảng datsan
  if (table === 'datsan' && action === 'select' && requiresAuth) {
    if (!authClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
    const authData = await getAuthenticatedProfile(req);
    const userRole = authData?.role;
    const isSelfOrPitchFiltered = filters.some(f => ['makhachhang', 'masan'].includes(f.column));
    if (!isSelfOrPitchFiltered && userRole !== 'ADMIN') {
      return res.status(403).json({ error: 'Forbidden: Super Admin access required to view global bookings' });
    }
  }
  if (table === 'datsan' && action === 'update') {
    if (!authClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
    const authData = await getAuthenticatedProfile(req);
    const userRole = authData?.role;
    if (values && ('trangthai' in values || 'TrangThai' in values) && userRole !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Forbidden: Trạng thái đơn đặt sân chỉ được cập nhật qua các quy trình nghiệp vụ chuyên biệt.' 
      });
    }
  }

  // 4. Bảng danhgia: Kiểm soát chặt chẽ điều kiện đánh giá (TASK 03 P0)
  if (table === 'danhgia' && action === 'insert') {
    if (!authClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
    const authData = await getAuthenticatedProfile(req);
    if (!authData) return res.status(401).json({ error: 'Unauthorized: Missing profile' });
    const callerUserId = Number(authData.profile.MaNguoiDung ?? authData.profile.manguoidung ?? authData.profile.id);
    const userRole = authData.role;

    const reviewItems = Array.isArray(values) ? values : [values];
    for (const r of reviewItems) {
      const targetBookingId = r?.madatsan || r?.MaDatSan;
      if (!targetBookingId) {
        return res.status(400).json({ error: 'Đánh giá phải gắn liền với một đơn đặt sân hợp lệ (madatsan).' });
      }

      // Kiểm tra đơn đặt sân
      const { data: booking, error: bErr } = await (adminSupabase || supabase)
        .from('datsan')
        .select('*, datsan_khunggio(khunggio(gioketthuc))')
        .eq('madatsan', targetBookingId)
        .single();

      if (bErr || !booking) {
        return res.status(404).json({ error: 'Không tìm thấy đơn đặt sân tương ứng để đánh giá.' });
      }

      // Phải là chính khách hàng sở hữu đơn (hoặc ADMIN)
      const bookingCustomerId = Number(booking.makhachhang);
      if (userRole !== 'ADMIN' && bookingCustomerId !== callerUserId) {
        return res.status(403).json({ error: 'Bạn chỉ có thể đánh giá đơn đặt sân của chính mình.' });
      }

      // Trạng thái đơn bắt buộc phải là HOAN_THANH / HOANTHANH
      const bookingStatus = String(booking.trangthai || '').toUpperCase();
      if (bookingStatus !== 'HOAN_THANH' && bookingStatus !== 'HOANTHANH') {
        return res.status(400).json({
          error: 'Chỉ các đơn đặt sân đã hoàn tất thi đấu (HOAN_THANH) mới được phép gửi đánh giá. Các trạng thái khác chưa đủ điều kiện đánh giá.',
          code: 'ERR_BOOKING_NOT_COMPLETED',
          currentStatus: bookingStatus
        });
      }

      // Kiểm tra thời gian thi đấu đã kết thúc
      const slots = booking.datsan_khunggio || [];
      let latestEnd = '00:00:00';
      for (const s of slots) {
        const end = s.khunggio?.gioketthuc || '00:00:00';
        if (end > latestEnd) latestEnd = end;
      }

      if (latestEnd !== '00:00:00') {
        const endHourMin = latestEnd.slice(0, 5);
        const matchEndDateTime = new Date(`${booking.ngaysudung}T${endHourMin}:00+07:00`);
        const now = new Date();
        if (now.getTime() < matchEndDateTime.getTime()) {
          return res.status(400).json({
            error: `Trận đấu chưa kết thúc (Dự kiến kết thúc lúc ${endHourMin} ngày ${booking.ngaysudung}). Vui lòng trải nghiệm trận đấu trước khi đánh giá.`,
            code: 'ERR_MATCH_NOT_ENDED'
          });
        }
      }

      // Chống đánh giá trùng lặp
      const { data: existingReview } = await (adminSupabase || supabase)
        .from('danhgia')
        .select('madanhgia')
        .eq('madatsan', targetBookingId)
        .maybeSingle();

      if (existingReview) {
        return res.status(400).json({
          error: 'Đơn đặt sân này đã được đánh giá trước đó. Mỗi đơn chỉ được gửi đánh giá một lần.',
          code: 'ERR_DUPLICATE_REVIEW'
        });
      }
    }
  }
  if (action === 'insert' && ['datsan', 'datsan_khunggio'].includes(table)) {
    return res.status(403).json({ error: 'Bookings must use the atomic booking endpoint' });
  }
  if (!requiresAuth && table === 'datsan') {
    const columnsNormalized = String(columns).replace(/\s+/g, '').toLowerCase();
    const availabilityColumns = 'madatsan,masan,ngaysudung,trangthai,datsan_khunggio(makhunggio)';
    if (columnsNormalized !== availabilityColumns) {
      return res.status(403).json({ error: 'Public booking reads are limited to availability data' });
    }
  }
  if (!requiresAuth && table === 'san' && /nguoidung|machusan\s*\(/i.test(String(columns))) {
    return res.status(403).json({ error: 'Owner profile data requires authentication' });
  }
  if (!requiresAuth && table === 'datsan_khunggio') {
    return res.status(403).json({ error: 'Direct booking detail reads require authentication' });
  }

  try {
    let query = action === 'select' ? requestClient.from(table).select(columns)
      : action === 'insert' ? requestClient.from(table).insert(values).select(columns)
        : requestClient.from(table).update(values).select(columns);
    for (const filter of filters) {
      if (!filter || !['eq', 'neq', 'in', 'is', 'gte', 'lte'].includes(filter.operator)) continue;
      query = query[filter.operator](filter.column, filter.value);
    }
    if (req.body.order) query = query.order(req.body.order.column, { ascending: req.body.order.ascending !== false });
    if (Number.isInteger(req.body.limit)) query = query.limit(Math.max(0, Math.min(req.body.limit, 500)));
    if (req.body.single === 'single') query = query.single();
    if (req.body.single === 'maybeSingle') query = query.maybeSingle();
    const { data, error } = await query;
    if (error) return res.status(400).json({ error: error.message, code: error.code });
    return res.json({ data });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Database request failed' });
  }
});

app.post('/api/storage/:bucket', upload.single('file'), async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const requestClient = await getAuthenticatedClient(req);
  if (!requestClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
  if (req.params.bucket !== 'san-images') return res.status(400).json({ error: 'Unsupported storage bucket' });
  if (!req.file) return res.status(400).json({ error: 'File is required' });
  const path = String(req.body.path || '').replace(/^\/+/, '');
  if (!path || path.includes('..')) return res.status(400).json({ error: 'Invalid file path' });
  const { data, error } = await requestClient.storage.from(req.params.bucket).upload(path, req.file.buffer, {
    contentType: req.file.mimetype, upsert: true,
  });
  if (error) return res.status(400).json({ error: error.message });
  const { data: publicUrl } = requestClient.storage.from(req.params.bucket).getPublicUrl(data.path);
  return res.json({ data, publicUrl: publicUrl.publicUrl });
});

// GẮN CÁC ENDPOINT CHO FEATURE 01 (OWNER DEPOSIT) VÀ FEATURE 02 (CUSTOMER CANCELLATION)
mountDepositAndCancellationRoutes(app, { adminSupabase, getAuthenticatedProfile });

app.use((error, _req, res, _next) => res.status(400).json({ error: error.message || 'Request failed' }));
app.listen(port, () => console.log(`DatSan API listening on port ${port}`));
