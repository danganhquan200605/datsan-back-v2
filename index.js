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

app.post('/api/data', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured' });
  const { table, action = 'select', columns = '*', filters = [], values } = req.body || {};
  if (!tables.has(table)) return res.status(400).json({ error: 'Unsupported table' });
  if (!['select', 'insert', 'update'].includes(action)) return res.status(400).json({ error: 'Unsupported action' });

  try {
    let query = action === 'select' ? supabase.from(table).select(columns)
      : action === 'insert' ? supabase.from(table).insert(values).select(columns)
        : supabase.from(table).update(values).select(columns);
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
  if (req.params.bucket !== 'san-images') return res.status(400).json({ error: 'Unsupported storage bucket' });
  if (!req.file) return res.status(400).json({ error: 'File is required' });
  const path = String(req.body.path || '').replace(/^\/+/, '');
  if (!path || path.includes('..')) return res.status(400).json({ error: 'Invalid file path' });
  const { data, error } = await supabase.storage.from(req.params.bucket).upload(path, req.file.buffer, {
    contentType: req.file.mimetype, upsert: true,
  });
  if (error) return res.status(400).json({ error: error.message });
  const { data: publicUrl } = supabase.storage.from(req.params.bucket).getPublicUrl(data.path);
  return res.json({ data, publicUrl: publicUrl.publicUrl });
});

app.use((error, _req, res, _next) => res.status(400).json({ error: error.message || 'Request failed' }));
app.listen(port, () => console.log(`DatSan API listening on port ${port}`));
