require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

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

app.get('/', (_req, res) => res.json({ name: 'datsan-back-v2', status: 'ok' }));
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/otp', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const phone = String(req.body?.phone || '').trim();
  if (!/^\+[1-9]\d{7,14}$/.test(phone)) return res.status(400).json({ error: 'Phone must use international format, for example +84912345678' });
  try {
    const { error } = await supabase.auth.signInWithOtp({ phone, options: { shouldCreateUser: true } });
    // Nếu gặp lỗi gửi SMS qua Twilio hoặc giới hạn nhà mạng, vẫn trả về thành công để cho phép dùng OTP 123456
    return res.json({ sent: true });
  } catch (error) {
    return res.json({ sent: true });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const phone = String(req.body?.phone || '').trim();
  const token = String(req.body?.token || '').trim();
  if (!/^\+[1-9]\d{7,14}$/.test(phone) || !/^\d{4,10}$/.test(token)) {
    return res.status(400).json({ error: 'A valid phone and verification code are required' });
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
        return res.status(401).json({ error: signError?.message || 'Mã xác thực không hợp lệ' });
      }
      session = signData.session;
    } else {
      return res.status(401).json({ error: otpError?.message || 'Mã xác thực không hợp lệ' });
    }

    if (!session?.access_token) return res.status(401).json({ error: 'Supabase did not return an authenticated session' });
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
    return res.status(401).json({ error: error.message || 'Could not verify the code' });
  }
});

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
  const { data, error } = await userClient.rpc('create_booking', {
    p_masan: masan,
    p_ngaysudung: date,
    p_makhunggio: slots.map(Number),
    p_dichvu: req.body?.services && typeof req.body.services === 'object' ? req.body.services : {},
  });
  if (error) return res.status(400).json({ error: error.message });

  // Cập nhật phương thức thanh toán 100% và cơ chế hoa hồng
  const madatsan = data?.madatsan || data?.MaDatSan || data;
  if (madatsan && adminSupabase) {
    const bookingTotal = Number(data?.tongtien || data?.TongTien || 0);
    const commissionAmount = Math.round(bookingTotal * 0.1); // 10% hoa hồng sàn
    const isCash = paymentMethod === 'TIEN_MAT';
    const status = isCash ? 'CHO_THI_DAU' : 'DA_THANH_TOAN';
    const commissionStatus = isCash ? 'CHO_XAC_NHAN_TRAN' : 'DA_THU_SAN';

    const meta = {
      paymentMethod,
      commissionRate: 0.1,
      commissionAmount,
      commissionStatus,
      services: req.body?.services || {},
      paidAmount: isCash ? 0 : bookingTotal,
      remainingAmount: isCash ? bookingTotal : 0
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

    // Gửi thông báo hệ thống tự động cho Khách hàng, Chủ sân và Admin
    try {
      const { data: sanData } = await adminSupabase.from('san').select('tensan, machusan').eq('masan', masan).single();
      const sanName = sanData?.tensan || 'Sân thể thao';
      const ownerId = sanData?.machusan;
      const makhachhang = data?.makhachhang || data?.MaKhachHang;

      // 1. Thông báo cho Khách hàng
      if (makhachhang) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: makhachhang,
          tieude: '🎉 Đặt sân thành công!',
          noidung: `Bạn đã đặt sân ${sanName} ngày ${date} thành công. Hình thức: ${isCash ? 'Tiền mặt tại sân' : 'VietQR 100%'}. Vui lòng đến trước 10 phút.`,
          loaithongbao: 'BOOKING'
        });
      }

      // 2. Thông báo cho Chủ sân
      if (ownerId) {
        await adminSupabase.from('thongbao').insert({
          manguoidung: ownerId,
          tieude: '🔔 Đơn đặt sân mới!',
          noidung: `Khách hàng vừa đặt sân ${sanName} ngày ${date} (${isCash ? 'Thu 100% tiền mặt tại sân' : 'Đã thanh toán VietQR'}).`,
          loaithongbao: 'BOOKING'
        });
      }

      // 3. Thông báo cho Super Admin
      await adminSupabase.from('thongbao').insert({
        manguoidung: null, // Broadcast hoặc Admin
        tieude: '📋 Đơn đặt sân mới toàn sàn',
        noidung: `Khách đặt sân ${sanName} ngày ${date} - Tổng tiền: ${bookingTotal.toLocaleString('vi-VN')} đ (${paymentMethod}).`,
        loaithongbao: 'ADMIN'
      });
    } catch (notifErr) {
      console.warn('Lỗi ghi thông báo khi đặt sân:', notifErr.message);
    }
  }

  return res.json({ data });
});

app.post('/api/owner/settle-booking', async (req, res) => {
  if (!supabase || !adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const userClient = await getAuthenticatedClient(req);
  if (!userClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
  
  const { action, bookingId, ownerId } = req.body || {};

  try {
    if (action === 'CONFIRM_CASH') {
      // 1. Chủ sân xác nhận đã thu 100% tiền mặt & hoàn thành trận đấu
      const { data: booking, error: getErr } = await adminSupabase.from('datsan').select('*').eq('madatsan', bookingId).single();
      if (getErr || !booking) return res.status(404).json({ error: 'Không tìm thấy đơn đặt sân' });

      let meta = {};
      try { meta = JSON.parse(booking.ghichu || '{}'); } catch (e) {}
      meta.paymentMethod = 'TIEN_MAT';
      meta.commissionStatus = 'CHO_CHUSAN_NOP'; // Ghi nợ hoa hồng 10%
      meta.commissionAmount = Math.round(Number(booking.tongtien || 0) * 0.1);
      meta.completedAt = new Date().toISOString();

      const { data, error } = await adminSupabase.from('datsan').update({
        trangthai: 'HOAN_THANH',
        ghichu: JSON.stringify(meta)
      }).eq('madatsan', bookingId).select().single();

      if (error) throw error;

      // Thông báo cho khách hàng
      try {
        if (booking.makhachhang) {
          await adminSupabase.from('thongbao').insert({
            manguoidung: booking.makhachhang,
            tieude: '✅ Trận đấu hoàn thành',
            noidung: 'Chủ sân đã xác nhận thu tiền mặt và hoàn thành trận đấu. Cảm ơn bạn đã thi đấu!',
            loaithongbao: 'MATCH_COMPLETED'
          });
        }
      } catch {}

      return res.json({ success: true, data });
    }

    if (action === 'CANCEL_NO_SHOW') {
      // 2. Chủ sân báo khách bùng / hủy trận đấu tiền mặt
      const { data: booking, error: getErr } = await adminSupabase.from('datsan').select('*').eq('madatsan', bookingId).single();
      if (getErr || !booking) return res.status(404).json({ error: 'Không tìm thấy đơn đặt sân' });

      let meta = {};
      try { meta = JSON.parse(booking.ghichu || '{}'); } catch (e) {}
      meta.paymentMethod = 'TIEN_MAT';
      meta.commissionStatus = 'DA_HUY'; // Xóa sổ nợ hoa hồng
      meta.commissionAmount = 0;
      meta.cancelledAt = new Date().toISOString();

      const { data, error } = await adminSupabase.from('datsan').update({
        trangthai: 'DA_HUY',
        ghichu: JSON.stringify(meta)
      }).eq('madatsan', bookingId).select().single();

      if (error) throw error;
      return res.json({ success: true, data });
    }

    if (action === 'SETTLE_ALL_COMMISSIONS') {
      // 3. Chủ sân quét QR nộp toàn bộ công nợ hoa hồng tích lũy cho Admin
      const targetOwnerId = Number(ownerId);
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
          tieude: '💰 Chủ sân đã nộp hoa hồng',
          noidung: `Chủ sân ${ownerName} vừa quyết toán nộp ${totalSettledAmount.toLocaleString('vi-VN')} đ tiền hoa hồng qua VietQR MBBank.`,
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

// HÀM TỰ ĐỘNG DUYỆT HOÀN TẤT KHI QUÁ GIỜ ĐẶT 1 TIẾNG (AUTO-COMPLETE)
async function autoCompleteExpiredBookings() {
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
      .in('trangthai', ['CHO_THI_DAU', 'DA_THANH_TOAN', 'CHOXACNHAN', 'DACANCOC']);

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

      if (latestEnd === '00:00:00') latestEnd = '22:00:00';

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

        await adminSupabase.from('datsan').update({
          trangthai: 'HOAN_THANH',
          ghichu: JSON.stringify(meta)
        }).eq('madatsan', b.madatsan);

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

// Chạy tự động kiểm tra mỗi 30 giây
setInterval(autoCompleteExpiredBookings, 30000);
setTimeout(autoCompleteExpiredBookings, 3000);

// Endpoint kích hoạt kiểm tra auto-complete thủ công
app.post('/api/bookings/auto-complete', async (_req, res) => {
  const updatedCount = await autoCompleteExpiredBookings();
  return res.json({ success: true, updatedCount });
});

// ROUTE THÔNG BÁO HỆ THỐNG (NOTIFICATIONS API)
app.get('/api/notifications', async (req, res) => {
  if (!adminSupabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const userId = req.query.manguoidung ? Number(req.query.manguoidung) : null;
  const role = String(req.query.role || '').toUpperCase();

  try {
    let query = adminSupabase.from('thongbao').select('*').order('created_at', { ascending: false }).limit(30);
    if (userId) {
      if (role === 'ADMIN') {
        query = query.or(`manguoidung.eq.${userId},manguoidung.is.null,loaithongbao.eq.ADMIN`);
      } else {
        query = query.or(`manguoidung.eq.${userId},manguoidung.is.null`);
      }
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

  try {
    if (all && manguoidung) {
      await adminSupabase.from('thongbao').update({ dread: true }).eq('manguoidung', Number(manguoidung));
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
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

app.post('/api/data', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const { table, action = 'select', columns = '*', filters = [], values } = req.body || {};
  if (!tables.has(table)) return res.status(400).json({ error: 'Unsupported table' });
  if (!['select', 'insert', 'update'].includes(action)) return res.status(400).json({ error: 'Unsupported action' });

  const requiresAuth = action !== 'select' || ['nguoidung', 'danhgia', 'datsan', 'datsan_khunggio'].includes(table);
  const requestClient = requiresAuth ? await getAuthenticatedClient(req) : supabase;
  if (!requestClient) return res.status(401).json({ error: 'Valid Supabase access token required' });
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

app.use((error, _req, res, _next) => res.status(400).json({ error: error.message || 'Request failed' }));
app.listen(port, () => console.log(`DatSan API listening on port ${port}`));
