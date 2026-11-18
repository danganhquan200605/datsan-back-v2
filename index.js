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
const tables = new Set(['loaisan', 'vitri', 'san', 'datsan', 'datsan_khunggio', 'khunggio', 'nguoidung', 'danhgia']);

let supabase;
if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
  // The anon key is intentionally used here; database access must be constrained by Supabase RLS.
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
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
    if (error) {
      if (error.message && error.message.toLowerCase().includes('twilio')) {
        return res.status(400).json({
          error: 'Số điện thoại này chưa thể nhận mã SMS trực tiếp. Vui lòng kiểm tra lại số điện thoại hoặc liên hệ quản trị viên để được hỗ trợ.'
        });
      }
      return res.status(400).json({ error: error.message });
    }
    return res.json({ sent: true });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Could not send the verification code' });
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
    const { data, error } = await supabase.auth.verifyOtp({ phone, token, type: 'sms' });
    if (error) return res.status(401).json({ error: error.message });
    if (!data.session?.access_token) return res.status(401).json({ error: 'Supabase did not return an authenticated session' });
    const userClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${data.session.access_token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: profile, error: profileError } = await userClient.rpc('ensure_current_nguoidung');
    if (profileError) return res.status(403).json({ error: profileError.message });
    return res.json({
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      expiresAt: data.session.expires_at,
      user: profile,
    });
  } catch (error) {
    return res.status(401).json({ error: error.message || 'Could not verify the code' });
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
  return res.json({ data });
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
