const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const STATIC_DIR = path.join(__dirname, 'static');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS objectives (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      freq TEXT NOT NULL DEFAULT 'daily',
      days TEXT DEFAULT '[]',
      dates TEXT DEFAULT '[]',
      months TEXT DEFAULT '[]',
      year_dates TEXT DEFAULT '[]',
      custom_freq TEXT DEFAULT '',
      color TEXT DEFAULT 'rust',
      start_date TEXT,
      end_date TEXT,
      notif BOOLEAN DEFAULT FALSE,
      notif_time TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  // Add new columns if upgrading existing DB
  const cols = ['months','year_dates','custom_freq','notif','notif_time'];
  for (const col of cols) {
    await pool.query(`ALTER TABLE objectives ADD COLUMN IF NOT EXISTS ${col} ${
      col==='notif'?'BOOLEAN DEFAULT FALSE':col==='months'||col==='year_dates'?'TEXT DEFAULT \'[]\'':'TEXT DEFAULT \'\''
    }`).catch(()=>{});
  }
  console.log('Database ready');
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + pw).digest('hex');
  return `${salt}:${h}`;
}
function verifyPassword(pw, stored) {
  const [salt, h] = stored.split(':');
  return crypto.createHash('sha256').update(salt + pw).digest('hex') === h;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function makeToken(userId, username) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const exp = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const payload = b64url(JSON.stringify({ user_id: userId, username, exp }));
  const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${sig}`;
}
function verifyToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Bad token');
  const [header, payload, sig] = parts;
  const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest());
  if (sig !== expected) throw new Error('Bad signature');
  const data = JSON.parse(Buffer.from(payload, 'base64').toString());
  if (data.exp < Math.floor(Date.now() / 1000)) throw new Error('Expired');
  return data;
}

function readBody(req) {
  return new Promise((res, rej) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { res(body ? JSON.parse(body) : {}); } catch { rej(new Error('Bad JSON')); } });
    req.on('error', rej);
  });
}
function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=');
  });
  return cookies;
}
function json(res, data, status = 200, setCookie = null) {
  const body = JSON.stringify(data);
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
  if (setCookie) headers['Set-Cookie'] = setCookie;
  res.writeHead(status, headers);
  res.end(body);
}
function getAuth(req) {
  const cookies = parseCookies(req);
  const token = cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) throw new Error('Not authenticated');
  return verifyToken(token);
}
function serveStatic(req, res) {
  const urlPath = req.url.split('?')[0];
  let filePath = path.join(STATIC_DIR, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(STATIC_DIR)) { res.writeHead(403); res.end(); return; }
  if (!fs.existsSync(filePath)) filePath = path.join(STATIC_DIR, 'index.html');
  const ext = path.extname(filePath);
  const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' }[ext] || 'text/plain';
  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(filePath).pipe(res);
}
function fmtObj(row) {
  return {
    id: row.id, title: row.title, desc: row.description,
    freq: row.freq,
    days: JSON.parse(row.days || '[]'),
    dates: JSON.parse(row.dates || '[]'),
    months: JSON.parse(row.months || '[]'),
    year_dates: JSON.parse(row.year_dates || '[]'),
    custom_freq: row.custom_freq || '',
    color: row.color,
    start: row.start_date, end: row.end_date,
    notif: row.notif || false,
    notif_time: row.notif_time || null,
    created: row.created_at
  };
}

async function router(req, res) {
  const url = req.url.split('?')[0];
  const method = req.method;
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    if (method === 'POST' && url === '/api/register') {
      const { username, email, password } = await readBody(req);
      if (!username || !email || !password) return json(res, { error: 'All fields required' }, 400);
      if (username.length < 2) return json(res, { error: 'Username too short' }, 400);
      if (password.length < 6) return json(res, { error: 'Password must be at least 6 characters' }, 400);
      try {
        const result = await pool.query(
          'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username',
          [username.trim(), email.trim().toLowerCase(), hashPassword(password)]
        );
        const user = result.rows[0];
        const token = makeToken(user.id, user.username);
        return json(res, { ok: true, username: user.username }, 200, `token=${token}; HttpOnly; Path=/; Max-Age=${30*24*3600}; SameSite=Lax`);
      } catch (e) {
        if (e.code === '23505') return json(res, { error: 'Username or email already taken' }, 409);
        throw e;
      }
    }

    if (method === 'POST' && url === '/api/login') {
      const { identifier, password } = await readBody(req);
      const result = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$2', [identifier, (identifier||'').toLowerCase()]);
      const user = result.rows[0];
      if (!user || !verifyPassword(password, user.password_hash)) return json(res, { error: 'Invalid credentials' }, 401);
      const token = makeToken(user.id, user.username);
      return json(res, { ok: true, username: user.username }, 200, `token=${token}; HttpOnly; Path=/; Max-Age=${30*24*3600}; SameSite=Lax`);
    }

    if (method === 'POST' && url === '/api/logout') {
      return json(res, { ok: true }, 200, 'token=; HttpOnly; Path=/; Max-Age=0');
    }

    if (method === 'GET' && url === '/api/me') {
      const user = getAuth(req);
      return json(res, { username: user.username, user_id: user.user_id });
    }

    if (method === 'GET' && url === '/api/objectives') {
      const user = getAuth(req);
      const result = await pool.query('SELECT * FROM objectives WHERE user_id=$1 ORDER BY created_at DESC', [user.user_id]);
      return json(res, result.rows.map(fmtObj));
    }

    if (method === 'POST' && url === '/api/objectives') {
      const user = getAuth(req);
      const d = await readBody(req);
      if (!d.title) return json(res, { error: 'Title required' }, 400);
      const result = await pool.query(
        `INSERT INTO objectives (user_id,title,description,freq,days,dates,months,year_dates,custom_freq,color,start_date,end_date,notif,notif_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
        [user.user_id, d.title, d.desc||'', d.freq||'daily',
         JSON.stringify(d.days||[]), JSON.stringify(d.dates||[]),
         JSON.stringify(d.months||[]), JSON.stringify(d.year_dates||[]),
         d.custom_freq||'', d.color||'rust',
         d.start||null, d.end||null,
         d.notif||false, d.notif_time||null]
      );
      return json(res, fmtObj(result.rows[0]), 201);
    }

    const putMatch = url.match(/^\/api\/objectives\/(\d+)$/);
    if (method === 'PUT' && putMatch) {
      const user = getAuth(req);
      const id = parseInt(putMatch[1]);
      const check = await pool.query('SELECT * FROM objectives WHERE id=$1 AND user_id=$2', [id, user.user_id]);
      if (!check.rows[0]) return json(res, { error: 'Not found' }, 404);
      const d = await readBody(req);
      await pool.query(
        `UPDATE objectives SET title=$1,description=$2,freq=$3,days=$4,dates=$5,months=$6,year_dates=$7,custom_freq=$8,color=$9,start_date=$10,end_date=$11,notif=$12,notif_time=$13
         WHERE id=$14 AND user_id=$15`,
        [d.title, d.desc!=null?d.desc:'', d.freq,
         JSON.stringify(d.days||[]), JSON.stringify(d.dates||[]),
         JSON.stringify(d.months||[]), JSON.stringify(d.year_dates||[]),
         d.custom_freq||'', d.color,
         d.start||null, d.end||null,
         d.notif||false, d.notif_time||null,
         id, user.user_id]
      );
      return json(res, { ok: true });
    }

    const delMatch = url.match(/^\/api\/objectives\/(\d+)$/);
    if (method === 'DELETE' && delMatch) {
      const user = getAuth(req);
      const id = parseInt(delMatch[1]);
      const check = await pool.query('SELECT id FROM objectives WHERE id=$1 AND user_id=$2', [id, user.user_id]);
      if (!check.rows[0]) return json(res, { error: 'Not found' }, 404);
      await pool.query('DELETE FROM objectives WHERE id=$1 AND user_id=$2', [id, user.user_id]);
      return json(res, { ok: true });
    }

    serveStatic(req, res);

  } catch (e) {
    if (['Not authenticated','Expired','Bad signature','Bad token'].includes(e.message)) {
      return json(res, { error: 'Not authenticated' }, 401);
    }
    console.error(e);
    json(res, { error: 'Server error' }, 500);
  }
}

process.on('uncaughtException', err => console.error('Uncaught:', err.message));
process.on('unhandledRejection', err => console.error('Unhandled:', err));

initDB().then(() => {
  const server = http.createServer(router);
  server.on('error', err => { console.error('Server error:', err.message); process.exit(1); });
  server.listen(PORT, '0.0.0.0', () => console.log(`Objectives running → http://localhost:${PORT}`));
}).catch(err => {
  console.error('Failed to connect to database:', err.message);
  process.exit(1);
});
