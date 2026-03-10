const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

// ── Config ──────────────────────────────────────────────
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const STATIC_DIR = path.join(__dirname, 'static');

// ── DB ───────────────────────────────────────────────────
const db = new DatabaseSync(path.join(__dirname, 'intentions.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    freq TEXT NOT NULL DEFAULT 'daily',
    days TEXT DEFAULT '[]',
    dates TEXT DEFAULT '[]',
    color TEXT DEFAULT 'rust',
    start_date TEXT,
    end_date TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Crypto helpers ───────────────────────────────────────
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + pw).digest('hex');
  return `${salt}:${h}`;
}

function verifyPassword(pw, stored) {
  const [salt, h] = stored.split(':');
  return crypto.createHash('sha256').update(salt + pw).digest('hex') === h;
}

// ── JWT (manual, no deps) ────────────────────────────────
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

// ── HTTP helpers ─────────────────────────────────────────
function readBody(req) {
  return new Promise((res, rej) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try { res(body ? JSON.parse(body) : {}); } catch { rej(new Error('Bad JSON')); }
    });
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
  const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' }[ext] || 'text/plain';
  res.writeHead(200, { 'Content-Type': mime });
  fs.createReadStream(filePath).pipe(res);
}

function fmtObj(row) {
  return {
    id: row.id, title: row.title, desc: row.description,
    freq: row.freq, days: JSON.parse(row.days || '[]'),
    dates: JSON.parse(row.dates || '[]'), color: row.color,
    start: row.start_date, end: row.end_date, created: row.created_at
  };
}

// ── Router ───────────────────────────────────────────────
async function router(req, res) {
  const url = req.url.split('?')[0];
  const method = req.method;

  // CORS for dev
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    // POST /api/register
    if (method === 'POST' && url === '/api/register') {
      const { username, email, password } = await readBody(req);
      if (!username || !email || !password) return json(res, { error: 'All fields required' }, 400);
      if (username.length < 2) return json(res, { error: 'Username too short' }, 400);
      if (password.length < 6) return json(res, { error: 'Password must be at least 6 characters' }, 400);
      try {
        const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
        const result = stmt.run(username.trim(), email.trim().toLowerCase(), hashPassword(password));
        const token = makeToken(result.lastInsertRowid, username.trim());
        const cookie = `token=${token}; HttpOnly; Path=/; Max-Age=${30*24*3600}; SameSite=Lax`;
        return json(res, { ok: true, username: username.trim() }, 200, cookie);
      } catch (e) {
        if (e.message.includes('UNIQUE')) return json(res, { error: 'Username or email already taken' }, 409);
        throw e;
      }
    }

    // POST /api/login
    if (method === 'POST' && url === '/api/login') {
      const { identifier, password } = await readBody(req);
      const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(identifier, (identifier||'').toLowerCase());
      if (!user || !verifyPassword(password, user.password_hash)) return json(res, { error: 'Invalid credentials' }, 401);
      const token = makeToken(user.id, user.username);
      const cookie = `token=${token}; HttpOnly; Path=/; Max-Age=${30*24*3600}; SameSite=Lax`;
      return json(res, { ok: true, username: user.username }, 200, cookie);
    }

    // POST /api/logout
    if (method === 'POST' && url === '/api/logout') {
      return json(res, { ok: true }, 200, 'token=; HttpOnly; Path=/; Max-Age=0');
    }

    // GET /api/me
    if (method === 'GET' && url === '/api/me') {
      const user = getAuth(req);
      return json(res, { username: user.username, user_id: user.user_id });
    }

    // GET /api/objectives
    if (method === 'GET' && url === '/api/objectives') {
      const user = getAuth(req);
      const rows = db.prepare('SELECT * FROM objectives WHERE user_id=? ORDER BY created_at DESC').all(user.user_id);
      return json(res, rows.map(fmtObj));
    }

    // POST /api/objectives
    if (method === 'POST' && url === '/api/objectives') {
      const user = getAuth(req);
      const d = await readBody(req);
      if (!d.title) return json(res, { error: 'Title required' }, 400);
      const stmt = db.prepare(`INSERT INTO objectives (user_id,title,description,freq,days,dates,color,start_date,end_date)
        VALUES (?,?,?,?,?,?,?,?,?)`);
      const result = stmt.run(user.user_id, d.title, d.desc||'', d.freq||'daily',
        JSON.stringify(d.days||[]), JSON.stringify(d.dates||[]),
        d.color||'rust', d.start||null, d.end||null);
      const row = db.prepare('SELECT * FROM objectives WHERE id=?').get(result.lastInsertRowid);
      return json(res, fmtObj(row), 201);
    }

    // PUT /api/objectives/:id
    const putMatch = url.match(/^\/api\/objectives\/(\d+)$/);
    if (method === 'PUT' && putMatch) {
      const user = getAuth(req);
      const id = parseInt(putMatch[1]);
      const row = db.prepare('SELECT * FROM objectives WHERE id=? AND user_id=?').get(id, user.user_id);
      if (!row) return json(res, { error: 'Not found' }, 404);
      const d = await readBody(req);
      db.prepare(`UPDATE objectives SET title=?,description=?,freq=?,days=?,dates=?,color=?,start_date=?,end_date=?
        WHERE id=? AND user_id=?`).run(
        d.title||row.title, d.desc!=null?d.desc:row.description, d.freq||row.freq,
        JSON.stringify(d.days||[]), JSON.stringify(d.dates||[]),
        d.color||row.color, d.start||null, d.end||null, id, user.user_id
      );
      return json(res, { ok: true });
    }

    // DELETE /api/objectives/:id
    const delMatch = url.match(/^\/api\/objectives\/(\d+)$/);
    if (method === 'DELETE' && delMatch) {
      const user = getAuth(req);
      const id = parseInt(delMatch[1]);
      const row = db.prepare('SELECT id FROM objectives WHERE id=? AND user_id=?').get(id, user.user_id);
      if (!row) return json(res, { error: 'Not found' }, 404);
      db.prepare('DELETE FROM objectives WHERE id=? AND user_id=?').run(id, user.user_id);
      return json(res, { ok: true });
    }

    // Static files
    serveStatic(req, res);

  } catch (e) {
    if (e.message === 'Not authenticated' || e.message === 'Expired' || e.message === 'Bad signature' || e.message === 'Bad token') {
      return json(res, { error: 'Not authenticated' }, 401);
    }
    console.error(e);
    json(res, { error: 'Server error' }, 500);
  }
}

// ── Start ────────────────────────────────────────────────
process.on('uncaughtException', err => { console.error('Uncaught:', err.message); });
process.on('unhandledRejection', err => { console.error('Unhandled:', err); });

const server = http.createServer(router);
server.on('error', err => {
  if (err.code === 'EADDRINUSE') { console.error(`Port ${PORT} in use. Try: kill $(lsof -t -i:${PORT})`); process.exit(1); }
  console.error('Server error:', err);
});
server.listen(PORT, '0.0.0.0', () => console.log(`Intentions running → http://localhost:${PORT}`));
