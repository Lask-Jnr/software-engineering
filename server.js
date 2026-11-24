'use strict';
/*
 * Student Results Portal: backend.
 * Node.js built-ins only (http, crypto, fs, node:sqlite). No npm install needed.
 * Needs Node 22.13 or newer.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const util = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.db');
const PUBLIC = path.join(__dirname, 'public');
const SESSION_HOURS = 8;
const SECURE_COOKIE = process.env.COOKIE_SECURE === 'true';
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const args = process.argv.slice(2);

if (args.includes('--reset')) for (const ext of ['', '-wal', '-shm']) fs.rmSync(DB_FILE + ext, { force: true });

/* ---------------- Database ---------------- */
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
CREATE TABLE IF NOT EXISTS staff (
  username TEXT PRIMARY KEY COLLATE NOCASE, name TEXT NOT NULL, pw TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, programme TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', dob TEXT NOT NULL DEFAULT '', gender TEXT NOT NULL DEFAULT '',
  pw TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS courses (
  code TEXT PRIMARY KEY, title TEXT NOT NULL, credits INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS registrations (
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  code TEXT NOT NULL REFERENCES courses(code) ON DELETE CASCADE,
  PRIMARY KEY (student_id, code));
CREATE TABLE IF NOT EXISTS results (
  student_id TEXT NOT NULL, code TEXT NOT NULL,
  score REAL NOT NULL CHECK (score BETWEEN 0 AND 100), grade TEXT NOT NULL,
  PRIMARY KEY (student_id, code),
  FOREIGN KEY (student_id, code) REFERENCES registrations(student_id, code) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS exams (
  code TEXT PRIMARY KEY REFERENCES courses(code) ON DELETE CASCADE,
  exam_date TEXT NOT NULL, time_start TEXT NOT NULL, time_end TEXT NOT NULL, venue TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, role TEXT NOT NULL, user_id TEXT NOT NULL, expires INTEGER NOT NULL);
`);
const q = sql => db.prepare(sql);
function tx(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
}

/* ---------------- Passwords and sessions ---------------- */
const scrypt = util.promisify(crypto.scrypt);
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
async function checkPw(pw, stored) {
  const [alg, s, h] = stored.split('$');
  if (alg !== 'scrypt') return false;
  const got = await scrypt(pw, Buffer.from(s, 'hex'), 64), want = Buffer.from(h, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
let DUMMY_HASH;
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
const tempPassword = () => Array.from({ length: 10 }, () => ALPHA[crypto.randomInt(ALPHA.length)]).join('');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

function cookie(token, seconds) {
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${seconds}${SECURE_COOKIE ? '; Secure' : ''}`;
}
function createSession(res, role, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  q('INSERT INTO sessions (token, role, user_id, expires) VALUES (?,?,?,?)').run(sha(token), role, userId, Date.now() + SESSION_HOURS * 3600e3);
  res.setHeader('Set-Cookie', cookie(token, SESSION_HOURS * 3600));
}
function getSession(req) {
  const m = /(?:^|;\s*)sid=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const row = q('SELECT token, role, user_id FROM sessions WHERE token = ? AND expires > ?').get(sha(m[1]), Date.now());
  if (!row) return null;
  const user = row.role === 'staff'
    ? q('SELECT username AS id, name, must_change FROM staff WHERE username = ?').get(row.user_id)
    : q('SELECT id, name, must_change FROM students WHERE id = ?').get(row.user_id);
  if (!user) return null;
  return { tokenHash: row.token, role: row.role, id: user.id, name: user.name, mustChange: !!user.must_change };
}

/* Login throttling: 5 wrong tries lock that ID from that address for 60 seconds. */
const attempts = new Map();
const lockedFor = key => { const a = attempts.get(key); return a && a.until > Date.now() ? Math.ceil((a.until - Date.now()) / 1000) : 0; };
function recordFail(key) {
  if (attempts.size > 5000) attempts.clear();
  const a = attempts.get(key) || { n: 0, until: 0 };
  if (++a.n >= 5) { a.until = Date.now() + 60_000; a.n = 0; }
  attempts.set(key, a);
}

/* ---------------- Validation ---------------- */
class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}
const bad = msg => new HttpError(400, msg);
function text(v, label, { max = 100, required = true } = {}) {
  if (v === undefined || v === null || v === '') { if (required) throw bad(`${label} is required.`); return ''; }
  if (typeof v !== 'string') throw bad(`${label} is not valid.`);
  v = v.trim();
  if (required && !v) throw bad(`${label} is required.`);
  if (v.length > max) throw bad(`${label} must be ${max} characters or fewer.`);
  if (/[\u0000-\u001f]/.test(v)) throw bad(`${label} contains characters that are not allowed.`);
  return v;
}
const idOf = (v, label) => {
  const s = text(v, label, { max: 20 }).toUpperCase();
  if (!/^[A-Z0-9_-]{2,20}$/.test(s)) throw bad(`${label} can use letters, numbers, dashes and underscores only (2 to 20 characters).`);
  return s;
};
const dateOk = s => { if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false; const d = new Date(s + 'T00:00:00Z'); return !isNaN(d) && d.toISOString().slice(0, 10) === s; };
const timeOk = s => /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
function scoreOf(v) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 100) throw bad('Score must be a number from 0 to 100.');
  return v;
}
const gradeOf = s => s >= 80 ? 'A' : s >= 70 ? 'B' : s >= 60 ? 'C' : s >= 50 ? 'D' : s >= 40 ? 'E' : 'F';

/* ---------------- Routing ---------------- */
const routes = [];
function route(method, pattern, auth, fn, opts = {}) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, auth, fn, opts });
}
function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}
async function readJson(req) {
  const chunks = []; let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 100_000) throw new HttpError(413, 'That request is too large.');
    chunks.push(c);
  }
  if (!size) return {};
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw 0;
    return v;
  } catch { throw bad('The request body is not valid JSON.'); }
}
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

async function handleApi(req, res, url) {
  const matches = routes.filter(r => r.re.test(url.pathname));
  if (!matches.length) throw new HttpError(404, 'Not found.');
  const r = matches.find(x => x.method === req.method);
  if (!r) throw new HttpError(405, 'Method not allowed.');

  if (req.method !== 'GET') {            // block cross-site requests
    const origin = req.headers.origin;
    if (origin) {
      let host; try { host = new URL(origin).host; } catch { host = ''; }
      if (host !== req.headers.host) throw new HttpError(403, 'Cross-site requests are not allowed.');
    }
  }
  const session = getSession(req);
  if (r.auth !== 'none') {
    if (!session) throw new HttpError(401, 'Please sign in.', 'AUTH');
    if (session.mustChange && !r.opts.allowMustChange) throw new HttpError(403, 'Choose a new password before continuing.', 'MUST_CHANGE');
    if (r.auth === 'staff' && session.role !== 'staff') throw new HttpError(403, 'Only staff can do that.');
  }
  const m = r.re.exec(url.pathname);
  const params = {};
  r.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(m[i + 1]); } catch { throw bad('Bad address.'); } });
  const body = ['POST', 'PUT'].includes(req.method) ? await readJson(req) : {};
  const out = await r.fn({ req, res, params, body, session, ip: clientIp(req) });
  send(res, 200, out ?? { ok: true });
}

/* ---------------- API: accounts ---------------- */
route('POST', '/api/login', 'none', async ({ body, res, ip }) => {
  const role = body.role === 'staff' ? 'staff' : body.role === 'student' ? 'student' : null;
  const username = typeof body.username === 'string' ? body.username.trim().slice(0, 64) : '';
  const password = typeof body.password === 'string' ? body.password.slice(0, 128) : '';
  if (!role || !username || !password) throw bad('Enter your ID and password.');
  const key = `${ip}|${role}|${username.toLowerCase()}`;
  const wait = lockedFor(key);
  if (wait) throw new HttpError(429, `Too many attempts. Try again in ${wait} seconds.`);
  const user = role === 'staff'
    ? q('SELECT username AS id, name, pw, must_change FROM staff WHERE username = ?').get(username)
    : q('SELECT id, name, pw, must_change FROM students WHERE id = ?').get(username.toUpperCase());
  const match = await checkPw(password, user ? user.pw : DUMMY_HASH);   // same work whether or not the ID exists
  if (!user || !match) { recordFail(key); throw new HttpError(401, 'The ID or password is wrong. Check both and try again.'); }
  attempts.delete(key);
  createSession(res, role, user.id);
  return { role, id: user.id, name: user.name, mustChange: !!user.must_change };
});

route('POST', '/api/logout', 'any', ({ res, session }) => {
  q('DELETE FROM sessions WHERE token = ?').run(session.tokenHash);
  res.setHeader('Set-Cookie', cookie('', 0));
}, { allowMustChange: true });

route('GET', '/api/me', 'any', ({ session }) => (
  { role: session.role, id: session.id, name: session.name, mustChange: session.mustChange }
), { allowMustChange: true });

route('POST', '/api/change-password', 'any', async ({ body, session }) => {
  const cur = typeof body.current === 'string' ? body.current.slice(0, 128) : '';
  const next = typeof body.next === 'string' ? body.next : '';
  const [table, col] = session.role === 'staff' ? ['staff', 'username'] : ['students', 'id'];
  const row = q(`SELECT pw FROM ${table} WHERE ${col} = ?`).get(session.id);
  if (!(await checkPw(cur, row.pw))) throw bad('The current password is wrong.');
  if (next.length < 8) throw bad('Use at least 8 characters.');
  if (next.length > 128) throw bad('Use 128 characters or fewer.');
  if (next === cur) throw bad('The new password must be different from the current one.');
  if (next.toLowerCase() === session.id.toLowerCase()) throw bad('The password cannot be your ID.');
  const pw = await hashPw(next);
  tx(() => {
    q(`UPDATE ${table} SET pw = ?, must_change = 0 WHERE ${col} = ?`).run(pw, session.id);
    q('DELETE FROM sessions WHERE role = ? AND user_id = ? AND token <> ?').run(session.role, session.id, session.tokenHash);
  });
}, { allowMustChange: true });

/* ---------------- API: data ---------------- */
route('GET', '/api/data', 'any', ({ session }) => {
  const staff = session.role === 'staff', id = session.id;
  const cols = 'id, name, programme, email, phone, dob, gender';
  const examSql = 'SELECT code, exam_date AS date, time_start AS start, time_end AS end, venue FROM exams';
  if (staff) return {
    students: q(`SELECT ${cols} FROM students ORDER BY id`).all(),
    courses: q('SELECT code, title, credits FROM courses ORDER BY code').all(),
    registrations: q('SELECT student_id AS studentId, code FROM registrations ORDER BY student_id, code').all(),
    results: q('SELECT student_id AS studentId, code, score, grade FROM results ORDER BY student_id, code').all(),
    exams: q(`${examSql} ORDER BY exam_date, time_start`).all()
  };
  return {
    students: q(`SELECT ${cols} FROM students WHERE id = ?`).all(id),
    courses: q('SELECT code, title, credits FROM courses ORDER BY code').all(),
    registrations: q('SELECT student_id AS studentId, code FROM registrations WHERE student_id = ? ORDER BY code').all(id),
    results: q('SELECT student_id AS studentId, code, score, grade FROM results WHERE student_id = ? ORDER BY code').all(id),
    exams: q(`${examSql} WHERE code IN (SELECT code FROM registrations WHERE student_id = ?) ORDER BY exam_date, time_start`).all(id)
  };
});

/* ---------------- API: students (staff) ---------------- */
route('POST', '/api/students', 'staff', async ({ body }) => {
  const id = idOf(body.id, 'Student ID');
  const name = text(body.name, 'Name'), programme = text(body.programme, 'Programme');
  const email = text(body.email, 'Email', { required: false, max: 120 });
  const phone = text(body.phone, 'Phone', { required: false, max: 30 });
  const dob = text(body.dob, 'Date of birth', { required: false, max: 10 });
  const gender = text(body.gender, 'Gender', { required: false, max: 20 });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw bad('Enter a valid email address.');
  if (dob && !dateOk(dob)) throw bad('Enter a valid date of birth.');
  if (q('SELECT 1 FROM students WHERE id = ?').get(id)) throw new HttpError(409, `Student ID ${id} already exists.`);
  const temp = tempPassword();
  q('INSERT INTO students (id, name, programme, email, phone, dob, gender, pw, must_change) VALUES (?,?,?,?,?,?,?,?,1)')
    .run(id, name, programme, email, phone, dob, gender, await hashPw(temp));
  return { ok: true, id, tempPassword: temp };
});

route('POST', '/api/students/:id/reset-password', 'staff', async ({ params }) => {
  const id = idOf(params.id, 'Student ID');
  if (!q('SELECT 1 FROM students WHERE id = ?').get(id)) throw new HttpError(404, 'Student not found.');
  const temp = tempPassword(), pw = await hashPw(temp);
  tx(() => {
    q('UPDATE students SET pw = ?, must_change = 1 WHERE id = ?').run(pw, id);
    q("DELETE FROM sessions WHERE role = 'student' AND user_id = ?").run(id);
  });
  return { ok: true, id, tempPassword: temp };
});

route('DELETE', '/api/students/:id', 'staff', ({ params }) => {
  const id = idOf(params.id, 'Student ID');
  tx(() => {
    q("DELETE FROM sessions WHERE role = 'student' AND user_id = ?").run(id);
    if (!q('DELETE FROM students WHERE id = ?').run(id).changes) throw new HttpError(404, 'Student not found.');
  });
});

/* ---------------- API: courses and registration ---------------- */
route('POST', '/api/courses', 'staff', ({ body }) => {
  const code = idOf(body.code, 'Course code'), title = text(body.title, 'Course title');
  const credits = body.credits;
  if (!Number.isInteger(credits) || credits < 1 || credits > 6) throw bad('Credit hours must be a whole number from 1 to 6.');
  if (q('SELECT 1 FROM courses WHERE code = ?').get(code)) throw new HttpError(409, `Course ${code} already exists.`);
  q('INSERT INTO courses (code, title, credits) VALUES (?,?,?)').run(code, title, credits);
});

route('POST', '/api/registrations', 'any', ({ body, session }) => {
  const code = idOf(body.code, 'Course');
  let studentId;
  if (session.role === 'student') {
    if (body.studentId && String(body.studentId).toUpperCase() !== session.id) throw new HttpError(403, 'You can only register yourself.');
    studentId = session.id;
  } else studentId = idOf(body.studentId, 'Student');
  if (!q('SELECT 1 FROM students WHERE id = ?').get(studentId)) throw new HttpError(404, 'Student not found.');
  if (!q('SELECT 1 FROM courses WHERE code = ?').get(code)) throw new HttpError(404, 'Course not found.');
  if (q('SELECT 1 FROM registrations WHERE student_id = ? AND code = ?').get(studentId, code))
    throw new HttpError(409, `${studentId} is already registered for ${code}.`);
  q('INSERT INTO registrations (student_id, code) VALUES (?,?)').run(studentId, code);
});

route('DELETE', '/api/registrations/:studentId/:code', 'any', ({ params, session }) => {
  const studentId = idOf(params.studentId, 'Student'), code = idOf(params.code, 'Course');
  if (session.role === 'student') {
    if (studentId !== session.id) throw new HttpError(403, 'You can only drop your own courses.');
    if (q('SELECT 1 FROM results WHERE student_id = ? AND code = ?').get(studentId, code))
      throw new HttpError(403, 'This course already has a result. Ask the examination office.');
  }
  if (!q('DELETE FROM registrations WHERE student_id = ? AND code = ?').run(studentId, code).changes)
    throw new HttpError(404, 'Registration not found.');
});

/* ---------------- API: results (staff) ---------------- */
route('POST', '/api/results', 'staff', ({ body }) => {
  const studentId = idOf(body.studentId, 'Student'), code = idOf(body.code, 'Course'), score = scoreOf(body.score);
  if (!q('SELECT 1 FROM registrations WHERE student_id = ? AND code = ?').get(studentId, code))
    throw bad('That student is not registered for this course.');
  if (q('SELECT 1 FROM results WHERE student_id = ? AND code = ?').get(studentId, code))
    throw new HttpError(409, 'A result already exists for this course. Use Update score.');
  q('INSERT INTO results (student_id, code, score, grade) VALUES (?,?,?,?)').run(studentId, code, score, gradeOf(score));
});

route('PUT', '/api/results/:studentId/:code', 'staff', ({ params, body }) => {
  const studentId = idOf(params.studentId, 'Student'), code = idOf(params.code, 'Course'), score = scoreOf(body.score);
  if (!q('UPDATE results SET score = ?, grade = ? WHERE student_id = ? AND code = ?').run(score, gradeOf(score), studentId, code).changes)
    throw new HttpError(404, 'Result not found.');
});

route('DELETE', '/api/results/:studentId/:code', 'staff', ({ params }) => {
  const studentId = idOf(params.studentId, 'Student'), code = idOf(params.code, 'Course');
  if (!q('DELETE FROM results WHERE student_id = ? AND code = ?').run(studentId, code).changes)
    throw new HttpError(404, 'Result not found.');
});

/* ---------------- API: exam timetable (staff) ---------------- */
route('POST', '/api/exams', 'staff', ({ body }) => {
  const code = idOf(body.code, 'Course'), venue = text(body.venue, 'Venue', { max: 60 });
  const date = text(body.date, 'Date', { max: 10 }), start = text(body.start, 'Start time', { max: 5 }), end = text(body.end, 'End time', { max: 5 });
  if (!dateOk(date)) throw bad('Enter a valid date.');
  if (!timeOk(start) || !timeOk(end)) throw bad('Enter valid start and end times.');
  if (end <= start) throw bad('The exam must end after it starts.');
  if (!q('SELECT 1 FROM courses WHERE code = ?').get(code)) throw new HttpError(404, 'Course not found.');
  if (q('SELECT 1 FROM exams WHERE code = ?').get(code)) throw new HttpError(409, `${code} is already on the timetable. Remove it first to reschedule.`);
  const overlaps = q('SELECT code, venue FROM exams WHERE exam_date = ? AND ? < time_end AND time_start < ?').all(date, start, end);
  const clash = overlaps.find(o => o.venue.toLowerCase() === venue.toLowerCase());
  if (clash) throw new HttpError(409, `${venue} is already used by ${clash.code} at that time.`);
  for (const o of overlaps) {
    const shared = q('SELECT COUNT(*) AS n FROM registrations a JOIN registrations b ON a.student_id = b.student_id WHERE a.code = ? AND b.code = ?').get(code, o.code).n;
    if (shared) throw new HttpError(409, `${shared} student(s) are registered for both ${code} and ${o.code}, which overlap.`);
  }
  q('INSERT INTO exams (code, exam_date, time_start, time_end, venue) VALUES (?,?,?,?,?)').run(code, date, start, end, venue);
});

route('DELETE', '/api/exams/:code', 'staff', ({ params }) => {
  if (!q('DELETE FROM exams WHERE code = ?').run(idOf(params.code, 'Course')).changes) throw new HttpError(404, 'Exam not found.');
});

/* ---------------- Static files and server ---------------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png' };
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let p;
  try { p = decodeURIComponent(url.pathname); } catch { res.writeHead(400); return res.end(); }
  if (p.includes('\0')) { res.writeHead(400); return res.end(); }
  if (p === '/') p = '/index.html';
  const file = path.resolve(PUBLIC, '.' + p);
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (SECURE_COOKIE) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else serveStatic(req, res, url);
  } catch (e) {
    if (res.headersSent) return res.end();
    if (e instanceof HttpError) return send(res, e.status, { error: e.message, code: e.code });
    console.error(e);
    send(res, 500, { error: 'Something went wrong on the server.' });
  }
});

/* ---------------- First-run setup ---------------- */
async function seedSample() {
  const day = n => { const d = new Date(); d.setDate(d.getDate() + n); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
  const students = [
    ['STU001', 'Ama Mensah', 'Computer Science', 'ama.mensah@example.com', '024 000 0101', '2005-03-14', 'Female'],
    ['STU002', 'Kofi Boateng', 'Computer Science', 'kofi.boateng@example.com', '024 000 0102', '2004-11-02', 'Male'],
    ['STU003', 'Esi Owusu', 'Information Technology', 'esi.owusu@example.com', '024 000 0103', '2005-07-21', 'Female'],
    ['STU004', 'Yaw Asante', 'Engineering', 'yaw.asante@example.com', '024 000 0104', '2004-01-30', 'Male'],
    ['STU005', 'Abena Darko', 'Business Administration', 'abena.darko@example.com', '024 000 0105', '2005-09-09', 'Female'],
    ['STU006', 'Kwame Adjei', 'Mathematics', 'kwame.adjei@example.com', '024 000 0106', '2004-05-17', 'Male']
  ];
  const temps = {}, hashes = {};
  for (const s of students) { temps[s[0]] = tempPassword(); hashes[s[0]] = await hashPw(temps[s[0]]); }
  const courses = [['CSC101', 'Introduction to Programming', 3], ['CSC202', 'Data Structures', 3], ['MTH102', 'Calculus I', 4], ['PHY101', 'General Physics', 3], ['ENG103', 'Communication Skills', 2], ['STA201', 'Statistics', 3]];
  const regs = [['STU001', 'CSC101'], ['STU001', 'MTH102'], ['STU001', 'STA201'], ['STU002', 'CSC101'], ['STU002', 'CSC202'], ['STU002', 'MTH102'], ['STU003', 'CSC101'], ['STU003', 'ENG103'], ['STU003', 'STA201'], ['STU004', 'PHY101'], ['STU004', 'MTH102'], ['STU004', 'ENG103'], ['STU005', 'ENG103'], ['STU005', 'STA201'], ['STU006', 'MTH102'], ['STU006', 'STA201'], ['STU006', 'CSC202']];
  const results = [['STU001', 'CSC101', 86], ['STU001', 'MTH102', 74], ['STU002', 'CSC101', 62], ['STU002', 'MTH102', 48], ['STU002', 'CSC202', 91], ['STU003', 'CSC101', 71], ['STU003', 'ENG103', 83], ['STU004', 'PHY101', 55], ['STU004', 'MTH102', 38], ['STU005', 'ENG103', 67], ['STU005', 'STA201', 79], ['STU006', 'MTH102', 92], ['STU006', 'STA201', 88]];
  const exams = [['CSC101', day(3), '09:00', '11:00', 'Hall A'], ['MTH102', day(4), '14:00', '16:00', 'Hall B'], ['PHY101', day(6), '09:00', '11:00', 'Lab 2'], ['ENG103', day(7), '10:00', '12:00', 'Hall A'], ['STA201', day(9), '14:00', '16:00', 'Hall B'], ['CSC202', day(10), '09:00', '12:00', 'Lab 1']];
  tx(() => {
    for (const s of students) q('INSERT INTO students (id, name, programme, email, phone, dob, gender, pw, must_change) VALUES (?,?,?,?,?,?,?,?,1)').run(...s, hashes[s[0]]);
    for (const c of courses) q('INSERT INTO courses (code, title, credits) VALUES (?,?,?)').run(...c);
    for (const r of regs) q('INSERT INTO registrations (student_id, code) VALUES (?,?)').run(...r);
    for (const [s, c, sc] of results) q('INSERT INTO results (student_id, code, score, grade) VALUES (?,?,?,?)').run(s, c, sc, gradeOf(sc));
    for (const e of exams) q('INSERT INTO exams (code, exam_date, time_start, time_end, venue) VALUES (?,?,?,?,?)').run(...e);
  });
  console.log('\nSample students (temporary passwords, each must be changed at first sign-in):');
  for (const s of students) console.log(`  ${s[0]}  ${s[1].padEnd(14)} ${temps[s[0]]}`);
}

async function setup() {
  DUMMY_HASH = await hashPw('not-a-real-password');
  if (!q('SELECT COUNT(*) AS n FROM staff').get().n) {
    const pass = process.env.ADMIN_PASSWORD || tempPassword();
    q('INSERT INTO staff (username, name, pw, must_change) VALUES (?,?,?,1)').run('admin', 'Examination Officer', await hashPw(pass));
    console.log('\nFirst run: staff account created.');
    console.log(`  Username: admin\n  Temporary password: ${pass}\n  (You must choose a new password at first sign-in. This is shown once.)`);
    if (!args.includes('--no-sample')) await seedSample();
  }
  setInterval(() => q('DELETE FROM sessions WHERE expires < ?').run(Date.now()), 10 * 60_000).unref();
  q('DELETE FROM sessions WHERE expires < ?').run(Date.now());
  server.listen(PORT, HOST, () => {
    console.log(`\nStudent Results Portal running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    if (HOST === '0.0.0.0' && !SECURE_COOKIE) console.log('Warning: exposed to the network without HTTPS. Put it behind an HTTPS proxy and set COOKIE_SECURE=true.');
  });
}
setup().catch(e => { console.error(e); process.exit(1); });
