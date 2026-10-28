'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const { createHash, randomBytes, scrypt, timingSafeEqual } = require('node:crypto');

const ROOT = __dirname;
const DATA_DIR = process.env.MZ_DATA_DIR || path.join(ROOT, 'data');
const DB_PATH = path.join(DATA_DIR, 'mz-life-os.sqlite');
const HOST = process.env.HOST || '127.0.0.1';
const PORT = process.env.PORT === undefined ? 4173 : Number(process.env.PORT);
const SESSION_DAYS = 30;
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || '';
const ALLOW_REGISTRATION = process.env.ALLOW_REGISTRATION === '1';
const scryptAsync = promisify(scrypt);
const KINDS = ['tasks', 'events', 'notes', 'transactions', 'habits', 'study', 'studio', 'goals'];
const DEFAULT_DATA = { tasks: [], events: [], notes: [], transactions: [], habits: [], habitLogs: {}, study: [], studio: [], goals: [], settings: { theme: 'light', city: '' } };
const STATIC_FILES = new Set(['index.html', 'app.js', 'style.css', 'manifest.json', 'icon.svg', 'sw.js']);
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
const loginAttempts = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

function tableExists(name) {
  return Boolean(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(name));
}

// Preserve records from the first local prototype for one-time migration after signup.
if (tableExists('app_items')) {
  const columns = db.prepare('PRAGMA table_info(app_items)').all().map((row) => row.name);
  if (!columns.includes('user_id') && !tableExists('legacy_items')) db.exec('ALTER TABLE app_items RENAME TO legacy_items');
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    recovery_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
  CREATE TABLE IF NOT EXISTS app_items (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    item_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (user_id, kind, item_id)
  );
  CREATE TABLE IF NOT EXISTS user_state (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );
`);

const userByEmail = db.prepare('SELECT * FROM users WHERE email=?');
const userById = db.prepare('SELECT id,email,display_name,created_at FROM users WHERE id=?');
const sessionByHash = db.prepare('SELECT user_id,expires_at FROM sessions WHERE token_hash=?');
const insertSession = db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)');
const removeSession = db.prepare('DELETE FROM sessions WHERE token_hash=?');
const readItems = db.prepare('SELECT kind,payload FROM app_items WHERE user_id=?');
const deleteItems = db.prepare('DELETE FROM app_items WHERE user_id=?');
const insertItem = db.prepare('INSERT INTO app_items(user_id,kind,item_id,payload) VALUES(?,?,?,?)');
const getRevision = db.prepare('SELECT revision,updated_at FROM user_state WHERE user_id=?');
const setRevision = db.prepare(`INSERT INTO user_state(user_id,revision,updated_at) VALUES(?,?,?)
  ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at`);

function securityHeaders(res, type = 'application/json; charset=utf-8') {
  res.setHeader('Content-Type', type);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(self)');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
}

function send(res, status, body, type) {
  securityHeaders(res, type || 'application/json; charset=utf-8');
  res.statusCode = status;
  if (type && !type.startsWith('application/json')) res.setHeader('Cache-Control', 'no-cache');
  else res.setHeader('Cache-Control', 'no-store');
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function json(res, status, body, extraHeaders = {}) {
  for (const [key, value] of Object.entries(extraHeaders)) res.setHeader(key, value);
  send(res, status, body);
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    try { out[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch { /* Ignore malformed cookie. */ }
  }
  return out;
}

function digest(value) { return createHash('sha256').update(value).digest('hex'); }

function cookieHeader(token, maxAge) {
  const parts = [`mz_session=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAge}`];
  if (COOKIE_SECURE) parts.push('Secure');
  return parts.join('; ');
}

function validOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  const activePort = server.address()?.port || PORT;
  const allowed = new Set([PUBLIC_ORIGIN, `http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].filter(Boolean));
  return allowed.has(origin);
}

function rateKey(req) { return req.socket.remoteAddress || 'unknown'; }
function checkRate(req, res) {
  const key = rateKey(req), now = Date.now();
  let state = loginAttempts.get(key);
  if (!state || state.resetAt <= now) state = { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (state.count >= 8) {
    json(res, 429, { error: 'محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا.' }, { 'Retry-After': String(Math.max(1, Math.ceil((state.resetAt - now) / 1000))) });
    loginAttempts.set(key, state);
    return false;
  }
  loginAttempts.set(key, state);
  return true;
}
function failedAttempt(req) { const state = loginAttempts.get(rateKey(req)); if (state) state.count += 1; }
function clearAttempts(req) { loginAttempts.delete(rateKey(req)); }

function registrationAvailable() {
  const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  return count === 0 || ALLOW_REGISTRATION;
}

function getSession(req) {
  const token = parseCookies(req).mz_session;
  if (!token || token.length > 256) return null;
  const hash = digest(token), found = sessionByHash.get(hash);
  if (!found) return null;
  if (found.expires_at <= Date.now()) { removeSession.run(hash); return null; }
  const user = userById.get(found.user_id);
  return user ? { user, tokenHash: hash } : null;
}

function createSession(userId) {
  const token = randomBytes(32).toString('base64url');
  const now = Date.now();
  insertSession.run(digest(token), userId, now + SESSION_DAYS * 86400000, now);
  return token;
}

async function passwordDigest(password, salt = randomBytes(16).toString('hex')) {
  const key = await scryptAsync(password, salt, 64, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  return { salt, hash: Buffer.from(key).toString('hex') };
}

function equalHex(a, b) {
  try {
    const left = Buffer.from(a, 'hex'), right = Buffer.from(b, 'hex');
    return left.length === right.length && left.length > 0 && timingSafeEqual(left, right);
  } catch { return false; }
}

function validateCredentials(email, password) {
  const normalized = String(email || '').trim().toLowerCase();
  if (normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) return { error: 'أدخل بريدًا إلكترونيًا بصيغة صحيحة.' };
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) return { error: 'كلمة المرور يجب أن تكون من 12 إلى 128 حرفًا.' };
  return { email: normalized };
}

function newRecoveryCode() {
  return randomBytes(16).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
}
function recoveryDigest(code) { return digest(String(code || '').replace(/[^a-f0-9]/gi, '').toUpperCase()); }

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 3_000_000) throw Object.assign(new Error('الطلب أكبر من الحد المسموح.'), { status: 413 });
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(text || '{}'); }
  catch { throw Object.assign(new Error('صيغة البيانات غير صحيحة.'), { status: 400 }); }
}

function transferLegacyItems(userId) {
  if (!tableExists('legacy_items')) return;
  const old = db.prepare('SELECT kind,item_id,payload FROM legacy_items').all();
  const put = db.prepare('INSERT OR IGNORE INTO app_items(user_id,kind,item_id,payload) VALUES(?,?,?,?)');
  for (const row of old) if (KINDS.includes(row.kind) || ['settings', 'habitLogs'].includes(row.kind)) put.run(userId, row.kind, row.item_id, row.payload);
  db.exec('DELETE FROM legacy_items');
}

function readData(userId) {
  const data = structuredClone(DEFAULT_DATA);
  for (const row of readItems.all(userId)) {
    let value;
    try { value = JSON.parse(row.payload); } catch { continue; }
    if (row.kind === 'settings') data.settings = value;
    else if (row.kind === 'habitLogs') data.habitLogs = value;
    else if (KINDS.includes(row.kind)) data[row.kind].push(value);
  }
  const state = getRevision.get(userId);
  return { data, revision: state?.revision || 0, updatedAt: state?.updated_at || null };
}

function validateData(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw Error('Invalid data document');
  for (const kind of KINDS) {
    if (input[kind] !== undefined && !Array.isArray(input[kind])) throw Error('Invalid collection');
    if ((input[kind] || []).length > 3000) throw Error('Too many records');
  }
  const rows = [];
  for (const kind of KINDS) for (const item of input[kind] || []) {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string' || item.id.length < 1 || item.id.length > 128) throw Error('Invalid record');
    rows.push([kind, item.id, JSON.stringify(item)]);
  }
  rows.push(['settings', 'main', JSON.stringify(input.settings && typeof input.settings === 'object' ? input.settings : DEFAULT_DATA.settings)]);
  rows.push(['habitLogs', 'main', JSON.stringify(input.habitLogs && typeof input.habitLogs === 'object' ? input.habitLogs : {})]);
  if (Buffer.byteLength(JSON.stringify(rows), 'utf8') > 2_500_000) throw Object.assign(new Error('البيانات أكبر من الحد المسموح.'), { status: 413 });
  return rows;
}

function saveData(userId, input, expectedRevision) {
  const rows = validateData(input);
  const state = getRevision.get(userId);
  const currentRevision = state?.revision || 0;
  if (!Number.isInteger(expectedRevision) || expectedRevision !== currentRevision) return { conflict: true, revision: currentRevision, updatedAt: state?.updated_at || null };
  const nextRevision = currentRevision + 1, updatedAt = new Date().toISOString();
  db.exec('BEGIN IMMEDIATE');
  try {
    deleteItems.run(userId);
    for (const [kind, itemId, payload] of rows) insertItem.run(userId, kind, itemId, payload);
    setRevision.run(userId, nextRevision, updatedAt);
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
  return { conflict: false, revision: nextRevision, updatedAt };
}

function countUsers() { return db.prepare('SELECT COUNT(*) AS count FROM users').get().count; }

async function routeApi(req, res, url) {
  const pathname = url.pathname;
  if (req.method === 'GET' && pathname === '/api/session') {
    const current = getSession(req);
    json(res, 200, { user: current ? { id: current.user.id, email: current.user.email, name: current.user.display_name } : null, registrationAvailable: registrationAvailable(), offlineSupported: true });
    return;
  }
  if (['POST', 'PUT', 'DELETE'].includes(req.method) && !validOrigin(req)) { json(res, 403, { error: 'رُفض الطلب بسبب مصدر غير معروف.' }); return; }

  if (req.method === 'POST' && pathname === '/api/auth/register') {
    if (!checkRate(req, res)) return;
    const body = await readBody(req), credentials = validateCredentials(body.email, body.password);
    if (credentials.error) { json(res, 400, { error: credentials.error }); return; }
    if (typeof body.name !== 'string' || body.name.trim().length < 2 || body.name.trim().length > 80) { json(res, 400, { error: 'اكتب اسمًا من حرفين إلى 80 حرفًا.' }); return; }
    if (!registrationAvailable()) { json(res, 403, { error: 'إنشاء الحسابات الجديدة مغلق. اطلب من مسؤول الخادم تفعيله.' }); return; }
    if (userByEmail.get(credentials.email)) { failedAttempt(req); json(res, 409, { error: 'تعذر إنشاء الحساب بهذه البيانات.' }); return; }
    const pass = await passwordDigest(body.password), recoveryCode = newRecoveryCode(), userId = randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    db.exec('BEGIN IMMEDIATE');
    try {
      if (!ALLOW_REGISTRATION && countUsers() > 0) throw Error('Registration is closed');
      if (userByEmail.get(credentials.email)) throw Error('Email already exists');
      db.prepare('INSERT INTO users(id,email,display_name,password_salt,password_hash,recovery_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(userId, credentials.email, body.name.trim(), pass.salt, pass.hash, recoveryDigest(recoveryCode), now);
      setRevision.run(userId, 0, now);
      transferLegacyItems(userId);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); json(res, 409, { error: 'تعذر إنشاء الحساب. ربما استُخدم البريد من قبل.' }); return; }
    clearAttempts(req);
    const token = createSession(userId);
    json(res, 201, { user: { id: userId, email: credentials.email, name: body.name.trim() }, recoveryCode, migratedPreviousData: tableExists('legacy_items') ? false : undefined }, { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/login') {
    if (!checkRate(req, res)) return;
    const body = await readBody(req), email = String(body.email || '').trim().toLowerCase();
    const user = userByEmail.get(email);
    let valid = false;
    if (user && typeof body.password === 'string' && body.password.length <= 128) {
      const attempted = await passwordDigest(body.password, user.password_salt);
      valid = equalHex(attempted.hash, user.password_hash);
    }
    if (!valid) { failedAttempt(req); json(res, 401, { error: 'البريد أو كلمة المرور غير صحيحين.' }); return; }
    clearAttempts(req);
    const token = createSession(user.id);
    json(res, 200, { user: { id: user.id, email: user.email, name: user.display_name } }, { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/recover') {
    if (!checkRate(req, res)) return;
    const body = await readBody(req), credentials = validateCredentials(body.email, body.newPassword);
    if (credentials.error) { json(res, 400, { error: credentials.error }); return; }
    const user = userByEmail.get(credentials.email), supplied = recoveryDigest(body.recoveryCode);
    if (!user || !equalHex(supplied, user.recovery_hash)) { failedAttempt(req); json(res, 401, { error: 'تعذر التحقق من رمز الاستعادة.' }); return; }
    const pass = await passwordDigest(body.newPassword), nextCode = newRecoveryCode();
    db.prepare('UPDATE users SET password_salt=?,password_hash=?,recovery_hash=? WHERE id=?').run(pass.salt, pass.hash, recoveryDigest(nextCode), user.id);
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id);
    clearAttempts(req);
    const token = createSession(user.id);
    json(res, 200, { user: { id: user.id, email: user.email, name: user.display_name }, recoveryCode: nextCode }, { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    const current = getSession(req);
    if (current) removeSession.run(current.tokenHash);
    json(res, 200, { loggedOut: true }, { 'Set-Cookie': cookieHeader('', 0) });
    return;
  }

  const current = getSession(req);
  if (!current) { json(res, 401, { error: 'سجّل الدخول للمتابعة.' }); return; }
  if (req.method === 'GET' && pathname === '/api/data') { json(res, 200, readData(current.user.id)); return; }
  if (req.method === 'PUT' && pathname === '/api/data') {
    const expected = Number(req.headers['if-match']);
    const body = await readBody(req);
    const result = saveData(current.user.id, body, expected);
    if (result.conflict) { json(res, 409, { conflict: true, revision: result.revision, updatedAt: result.updatedAt, error: 'هناك تحديث أحدث على جهاز آخر. احتُفظ بنسختك المحلية.' }); return; }
    json(res, 200, { saved: true, revision: result.revision, updatedAt: result.updatedAt });
    return;
  }
  if (req.method === 'DELETE' && pathname === '/api/account') {
    const body = await readBody(req), user = db.prepare('SELECT * FROM users WHERE id=?').get(current.user.id);
    const attempt = await passwordDigest(String(body.password || ''), user.password_salt);
    if (!equalHex(attempt.hash, user.password_hash)) { json(res, 403, { error: 'كلمة المرور غير صحيحة.' }); return; }
    db.prepare('DELETE FROM users WHERE id=?').run(current.user.id);
    json(res, 200, { deleted: true }, { 'Set-Cookie': cookieHeader('', 0) });
    return;
  }
  json(res, 404, { error: 'المسار غير موجود.' });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    if (url.pathname.startsWith('/api/')) { await routeApi(req, res, url); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') { send(res, 405, 'الطريقة غير مدعومة.', 'text/plain; charset=utf-8'); return; }
    const requested = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1));
    if (!STATIC_FILES.has(requested)) { send(res, 404, 'الملف غير موجود.', 'text/plain; charset=utf-8'); return; }
    fs.readFile(path.join(ROOT, requested), (error, content) => {
      if (error) { send(res, 404, 'الملف غير موجود.', 'text/plain; charset=utf-8'); return; }
      send(res, 200, req.method === 'HEAD' ? '' : content, MIME[path.extname(requested)] || 'application/octet-stream');
    });
  } catch (error) {
    if (!res.headersSent) send(res, error.status || 500, { error: error.status ? error.message : 'حدث خطأ داخلي.' });
    else res.destroy();
  }
});

server.listen(PORT, HOST, () => console.log(`MZ Life OS يعمل محليًا على http://${HOST}:${server.address().port}`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => { db.close(); process.exit(0); }));
