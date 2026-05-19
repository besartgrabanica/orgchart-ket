const express = require('express');
const path    = require('path');
const session = require('express-session');
const bcrypt  = require('bcrypt');
const crypto  = require('crypto');
const db      = require('./database');
const mailer  = require('./mailer');

const app  = express();
const PORT = process.env.PORT || 3000;

const ROLES = ['viewer','editor','admin','developer','superadmin'];

// ── Session ───────────────────────────────────────────────────────────────────
let sessionStore;
try {
  const SQLiteStore = require('connect-sqlite3')(session);
  sessionStore = new SQLiteStore({ db: 'sessions.db', dir: __dirname });
  console.log('  ✅  Session store: SQLite');
} catch (e) {
  console.warn('  ⚠️   connect-sqlite3 failed, using memory store:', e.message);
  sessionStore = new session.MemoryStore();
}

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'evrotarget-change-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 8 * 60 * 60 * 1000 }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Helpers ───────────────────────────────────────────────────────────────────
function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function genToken(prefix='') {
  const raw = crypto.randomBytes(32).toString('base64url');
  return prefix ? `${prefix}_${raw}` : raw;
}
function getSetting(key) {
  const r = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return r ? r.value : null;
}
function setSetting(key, value, userId) {
  db.prepare(`INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, CURRENT_TIMESTAMP, ?)
              ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`)
    .run(key, value, userId || null);
}
function ensureOperationsDept() {
  const exists = db.prepare(`SELECT id FROM departments WHERE name = 'Operations' COLLATE NOCASE`).get();
  if (!exists) {
    db.prepare(`INSERT INTO departments (name, color, description, sort_order) VALUES ('Operations', '#0f766e', 'Structural department that client projects branch off.', 999)`).run();
  }
}

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.xhr || req.headers.accept?.includes('application/json'))
    return res.status(401).json({ error: 'Not authenticated' });
  res.redirect('/login.html');
}
function hasRole(req, ...roles) {
  return roles.includes(req.session?.user?.role);
}
function requireEditor(req, res, next) {
  if (hasRole(req,'editor','admin','superadmin')) return next();
  return res.status(403).json({ error: 'Editor access required' });
}
function requireAdmin(req, res, next) {
  if (hasRole(req,'admin','superadmin')) return next();
  return res.status(403).json({ error: 'Admin access required' });
}
function requireDeveloper(req, res, next) {
  if (hasRole(req,'developer','superadmin')) return next();
  return res.status(403).json({ error: 'Developer access required' });
}
function requireSuperadmin(req, res, next) {
  if (hasRole(req,'superadmin')) return next();
  return res.status(403).json({ error: 'Superadmin access required' });
}
function countAdmins(excludeId) {
  const sql = excludeId
    ? `SELECT COUNT(*) AS c FROM users WHERE role IN ('admin','superadmin') AND id != ?`
    : `SELECT COUNT(*) AS c FROM users WHERE role IN ('admin','superadmin')`;
  return excludeId ? db.prepare(sql).get(excludeId).c : db.prepare(sql).get().c;
}
function countSuperadmins(excludeId) {
  const sql = excludeId
    ? `SELECT COUNT(*) AS c FROM users WHERE role='superadmin' AND id != ?`
    : `SELECT COUNT(*) AS c FROM users WHERE role='superadmin'`;
  return excludeId ? db.prepare(sql).get(excludeId).c : db.prepare(sql).get().c;
}

// ── Bearer-token (API key) middleware ─────────────────────────────────────────
// COMMENTED OUT — sync/API import capability disabled for now.
// To re-enable, uncomment the bearer-token lookup block below.
function bearerOrSession(req, res, next) {
  if (req.session && req.session.user) return next();
  // const auth = req.headers.authorization || '';
  // const m = auth.match(/^Bearer\s+(.+)$/i);
  // if (!m) return next();
  // const token = m[1].trim();
  // const hash  = sha256(token);
  // const row = db.prepare(`SELECT * FROM api_keys WHERE token_hash = ? AND revoked_at IS NULL`).get(hash);
  // if (!row) return res.status(401).json({ error: 'Invalid API token' });
  // req.apiKey = { id: row.id, label: row.label, scopes: row.scopes };
  // req.session = req.session || {};
  // req.session.user = { id: 0, username: `apikey:${row.label}`, role: 'viewer', via: 'apikey' };
  // try { db.prepare('UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.id); } catch(e) {}
  next();
}
app.use('/api', bearerOrSession);

// ── Sync-mode lock middleware ──────────────────────────────────────────────────
// COMMENTED OUT — sync mode disabled for now. To re-enable, uncomment below.
// function syncLock(req, res, next) {
//   if (req.method === 'GET') return next();
//   if (getSetting('sync_mode') !== 'on') return next();
//   const allowed = [
//     /^\/api\/users(\/|$)/,
//     /^\/api\/api-keys(\/|$)/,
//     /^\/api\/webhooks(\/|$)/,
//     /^\/api\/me(\/|$)/,
//     /^\/api\/settings(\/|$)/,
//     /^\/api\/invitations(\/|$)/,
//     /^\/api\/sync(\/|$)/,
//     /^\/api\/divisions(\/|$)/,
//   ];
//   if (allowed.some(rx => rx.test(req.path))) return next();
//   return res.status(423).json({ error: 'Sync mode is on.' });
// }
// app.use('/api', syncLock);

// ── Public auth routes ────────────────────────────────────────────────────────
app.get('/login.html', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/accept-invite.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'accept-invite.html')));
app.get('/reset-password.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user) { console.log(`  🔒  Login failed: username "${username.trim()}" not found`); return res.status(401).json({ error: 'Invalid username or password' }); }
  const match = await bcrypt.compare(password, user.password);
  if (!match) { console.log(`  🔒  Login failed: wrong password for "${user.username}" (id=${user.id})`); return res.status(401).json({ error: 'Invalid username or password' }); }
  console.log(`  🔒  Login OK: "${user.username}" (id=${user.id}, role=${user.role})`);
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ role: user.role });
});

app.post('/auth/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/auth/me', (req, res) => {
  if (req.session && req.session.user) return res.json({ user: req.session.user });
  res.status(401).json({ error: 'Not authenticated' });
});

// ── Forgot / reset password (public) ─────────────────────────────────────────
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.trim()) return res.status(400).json({ error: 'Email required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());
  if (user) {
    const token = genToken();
    const hash  = sha256(token);
    const expires = new Date(Date.now() + 60*60*1000).toISOString();
    db.prepare(`INSERT INTO password_resets (user_id, token_hash, expires_at, request_ip) VALUES (?, ?, ?, ?)`)
      .run(user.id, hash, expires, req.ip || null);
    try { await mailer.sendPasswordResetEmail({ to: user.email, token, username: user.username }); }
    catch (e) { console.error('Mailer error (forgot-password):', e.message); }
  }
  res.json({ success: true });
});

app.get('/auth/reset-token/:token', (req, res) => {
  const hash = sha256(req.params.token);
  const row = db.prepare(`SELECT pr.*, u.username FROM password_resets pr JOIN users u ON u.id = pr.user_id WHERE pr.token_hash = ?`).get(hash);
  if (!row) return res.status(404).json({ error: 'Invalid or unknown token' });
  if (row.used_at) return res.status(410).json({ error: 'Token already used' });
  if (new Date(row.expires_at) < new Date()) return res.status(410).json({ error: 'Token expired' });
  res.json({ username: row.username });
});

app.post('/auth/reset-password', async (req, res) => {
  const { token, new_password } = req.body;
  if (!token || !new_password) return res.status(400).json({ error: 'Token and new password required' });
  if (new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = sha256(token);
  const row = db.prepare(`SELECT * FROM password_resets WHERE token_hash = ?`).get(hash);
  if (!row) return res.status(404).json({ error: 'Invalid token' });
  if (row.used_at) return res.status(410).json({ error: 'Token already used' });
  if (new Date(row.expires_at) < new Date()) return res.status(410).json({ error: 'Token expired' });
  const pwHash = await bcrypt.hash(new_password, 10);
  // Get the user first to log who we're updating
  const targetUser = db.prepare('SELECT id, username FROM users WHERE id = ?').get(row.user_id);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  // Update password and mark token used
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(pwHash, targetUser.id);
  db.prepare('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.id);
  // Force WAL checkpoint to ensure the write is fully persisted
  db.pragma('wal_checkpoint(TRUNCATE)');
  // Verify
  const verify = db.prepare('SELECT password FROM users WHERE id = ?').get(targetUser.id);
  const ok = verify && await bcrypt.compare(new_password, verify.password);
  console.log(`  🔑  Password reset for "${targetUser.username}" (id=${targetUser.id}): ${ok ? '✅ verified' : '❌ FAILED'}`);
  res.json({ success: true });
});

// ── Invitation acceptance (public) ────────────────────────────────────────────
app.get('/auth/invite/:token', (req, res) => {
  const hash = sha256(req.params.token);
  const row = db.prepare(`SELECT * FROM invitations WHERE token_hash = ?`).get(hash);
  if (!row) return res.status(404).json({ error: 'Invalid or unknown invite' });
  if (row.accepted_at) return res.status(410).json({ error: 'Invite already used' });
  if (row.revoked_at)  return res.status(410).json({ error: 'Invite revoked' });
  if (new Date(row.expires_at) < new Date()) return res.status(410).json({ error: 'Invite expired' });
  res.json({ email: row.email, role: row.role });
});

app.post('/auth/accept-invite', async (req, res) => {
  const { token, username, password } = req.body;
  if (!token || !username || !password) return res.status(400).json({ error: 'token, username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = sha256(token);
  const inv = db.prepare(`SELECT * FROM invitations WHERE token_hash = ?`).get(hash);
  if (!inv) return res.status(404).json({ error: 'Invalid invite' });
  if (inv.accepted_at) return res.status(410).json({ error: 'Invite already used' });
  if (inv.revoked_at)  return res.status(410).json({ error: 'Invite revoked' });
  if (new Date(inv.expires_at) < new Date()) return res.status(410).json({ error: 'Invite expired' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (existing) return res.status(400).json({ error: 'Username already taken' });
  const existingEmail = db.prepare('SELECT id, username FROM users WHERE email = ? COLLATE NOCASE').get(inv.email);
  if (existingEmail) return res.status(400).json({ error: `Email already in use by user "${existingEmail.username}".` });
  try {
    const pwHash = await bcrypt.hash(password, 10);
    const newUserId = db.transaction(() => {
      const r = db.prepare('INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)')
        .run(username.trim(), pwHash, inv.role, inv.email);
      db.prepare('UPDATE invitations SET accepted_at = CURRENT_TIMESTAMP, accepted_by = ? WHERE id = ?').run(r.lastInsertRowid, inv.id);
      return r.lastInsertRowid;
    })();
    req.session.user = { id: newUserId, username: username.trim(), role: inv.role };
    res.json({ success: true, role: inv.role });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── Static-file gate ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path === '/login.html' || req.path === '/accept-invite.html' || req.path === '/reset-password.html' || req.path.startsWith('/auth/')) return next();
  if (req.path === '/admin.html') {
    if (!req.session?.user) return res.redirect('/login.html');
    if (!hasRole(req,'editor','admin','developer','superadmin')) return res.redirect('/?error=noaccess');
    return next();
  }
  if (!req.session?.user) return res.redirect('/login.html');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ── Current user / password change ───────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.session.user }));

app.post('/api/me/password', requireAuth, async (req, res) => {
  if (req.session.user.via === 'apikey') return res.status(403).json({ error: 'Not allowed via API token' });
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'Both current and new password required' });
  if (new_password.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!await bcrypt.compare(current_password, user.password)) return res.status(401).json({ error: 'Current password is incorrect' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(await bcrypt.hash(new_password, 10), user.id);
  res.json({ success: true });
});

// ── Pessimistic record locks ─────────────────────────────────────────────────
// Only one user can edit a given entity at a time. Locks expire after 5 min
// unless refreshed by a heartbeat. The frontend acquires a lock before opening
// an edit form and releases it on Save / Cancel / tab close.
const LOCK_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

// Check if a record is currently locked (returns lock info or null)
app.get('/api/locks/:entity_type/:entity_id', requireAuth, (req, res) => {
  const { entity_type, entity_id } = req.params;
  const lock = db.prepare('SELECT rl.*, u.username AS locked_by_username FROM record_locks rl JOIN users u ON rl.locked_by = u.id WHERE rl.entity_type = ? AND rl.entity_id = ?').get(entity_type, entity_id);
  if (!lock) return res.json({ locked: false });
  const age = Date.now() - new Date(lock.locked_at + 'Z').getTime();
  if (age > LOCK_EXPIRY_MS) {
    db.prepare('DELETE FROM record_locks WHERE entity_type = ? AND entity_id = ?').run(entity_type, entity_id);
    return res.json({ locked: false });
  }
  res.json({ locked: true, locked_by: lock.locked_by, locked_by_username: lock.locked_by_username, locked_at: lock.locked_at, own: lock.locked_by === req.session.user.id });
});

// Acquire a lock — fails if already locked by someone else
app.post('/api/locks', requireAuth, requireEditor, (req, res) => {
  const { entity_type, entity_id } = req.body;
  if (!entity_type || !entity_id) return res.status(400).json({ error: 'entity_type and entity_id required' });
  // Clean up expired locks first
  db.prepare(`DELETE FROM record_locks WHERE locked_at < datetime('now', '-5 minutes')`).run();
  // Check for existing lock
  const existing = db.prepare('SELECT rl.*, u.username AS locked_by_username FROM record_locks rl JOIN users u ON rl.locked_by = u.id WHERE rl.entity_type = ? AND rl.entity_id = ?').get(entity_type, entity_id);
  if (existing && existing.locked_by !== req.session.user.id) {
    return res.status(423).json({ error: `Currently being edited by ${existing.locked_by_username}. Try again later.`, locked_by: existing.locked_by_username });
  }
  // Acquire or refresh own lock
  db.prepare(`INSERT INTO record_locks (entity_type, entity_id, locked_by, locked_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(entity_type, entity_id) DO UPDATE SET locked_by = excluded.locked_by, locked_at = CURRENT_TIMESTAMP`).run(entity_type, entity_id, req.session.user.id);
  res.json({ success: true });
});

// Heartbeat — refreshes the lock timestamp so it doesn't expire while editing
app.put('/api/locks/:entity_type/:entity_id', requireAuth, (req, res) => {
  const { entity_type, entity_id } = req.params;
  const lock = db.prepare('SELECT * FROM record_locks WHERE entity_type = ? AND entity_id = ? AND locked_by = ?').get(entity_type, entity_id, req.session.user.id);
  if (!lock) return res.status(404).json({ error: 'No active lock found' });
  db.prepare('UPDATE record_locks SET locked_at = CURRENT_TIMESTAMP WHERE entity_type = ? AND entity_id = ?').run(entity_type, entity_id);
  res.json({ success: true });
});

// Release a lock
app.delete('/api/locks/:entity_type/:entity_id', requireAuth, (req, res) => {
  // Only the lock owner can release (or admin/superadmin can force-release)
  const lock = db.prepare('SELECT * FROM record_locks WHERE entity_type = ? AND entity_id = ?').get(req.params.entity_type, req.params.entity_id);
  if (!lock) return res.json({ success: true }); // already unlocked
  if (lock.locked_by !== req.session.user.id && !hasRole(req, 'admin', 'superadmin')) {
    return res.status(403).json({ error: 'Not your lock' });
  }
  db.prepare('DELETE FROM record_locks WHERE entity_type = ? AND entity_id = ?').run(req.params.entity_type, req.params.entity_id);
  res.json({ success: true });
});

// Release all locks held by the current user (called on page unload)
app.delete('/api/locks', requireAuth, (req, res) => {
  db.prepare('DELETE FROM record_locks WHERE locked_by = ?').run(req.session.user.id);
  res.json({ success: true });
});

// ── App settings ──────────────────────────────────────────────────────────────
app.get('/api/settings', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value, updated_at FROM app_settings').all();
  const obj = {};
  rows.forEach(r => { obj[r.key] = r.value; });
  res.json(obj);
});

// COMMENTED OUT — sync mode disabled for now. To re-enable, uncomment below.
// app.post('/api/settings/sync-mode', requireAuth, (req, res) => {
//   if (!hasRole(req,'admin','developer','superadmin')) return res.status(403).json({ error: 'Access denied' });
//   const { value } = req.body;
//   if (value !== 'on' && value !== 'off') return res.status(400).json({ error: 'value must be "on" or "off"' });
//   setSetting('sync_mode', value, req.session.user.id);
//   res.json({ success: true, sync_mode: value });
// });

// ── User management ───────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  if (!hasRole(req,'editor','admin','developer','superadmin')) return res.status(403).json({ error: 'Access denied' });
  res.json(db.prepare('SELECT id, username, email, role, created_at FROM users ORDER BY role, username COLLATE NOCASE').all());
});

app.post('/api/users', requireAuth, async (req, res) => {
  const callerRole = req.session.user.role;
  const { username, password, role, email } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'username, password and role required' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (callerRole === 'editor' && role !== 'viewer') return res.status(403).json({ error: 'Editors can only create viewers.' });
  if (!hasRole(req,'editor','admin','developer','superadmin')) return res.status(403).json({ error: 'Access denied' });
  if (db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(username.trim())) return res.status(400).json({ error: 'Username already exists' });
  if (email) {
    const dupEmail = db.prepare('SELECT id, username FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());
    if (dupEmail) return res.status(400).json({ error: `Email already in use by user "${dupEmail.username}".` });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = db.prepare('INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)').run(username.trim(), hash, role, email||null);
    res.json({ id: r.lastInsertRowid, username: username.trim(), role });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const { username, email, role } = req.body;
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (role && !ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  // Nobody can demote a superadmin via the app
  if (role && target.role === 'superadmin' && role !== 'superadmin') return res.status(403).json({ error: 'Superadmin role cannot be changed from the app.' });
  // Only superadmin can set role to superadmin or developer
  const callerRole = req.session.user.role;
  if (role && callerRole === 'admin' && ['developer','superadmin'].includes(role)) return res.status(403).json({ error: 'Only superadmins can assign developer or superadmin roles.' });
  if (role && ['admin','superadmin'].includes(target.role) && !['admin','superadmin'].includes(role) && countAdmins(id) === 0) return res.status(400).json({ error: 'Cannot demote the last admin-level user.' });
  try {
    if (username) {
      const dup = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE AND id != ?').get(username.trim(), id);
      if (dup) return res.status(400).json({ error: 'Username already taken.' });
      db.prepare('UPDATE users SET username = ? WHERE id = ?').run(username.trim(), id);
    }
    if (email !== undefined) {
      if (email) {
        const dup = db.prepare('SELECT id, username FROM users WHERE email = ? COLLATE NOCASE AND id != ?').get(email.trim(), id);
        if (dup) return res.status(400).json({ error: `Email already in use by user "${dup.username}".` });
      }
      db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email ? email.trim() : null, id);
    }
    if (role) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
    if (req.session.user.id === id && role) req.session.user.role = role;
    res.json(db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(id));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const callerRole = req.session.user.role;
  const id = parseInt(req.params.id);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (callerRole === 'editor' && target.role !== 'viewer') return res.status(403).json({ error: 'Editors can only delete viewers.' });
  if (!hasRole(req,'editor','admin','superadmin')) return res.status(403).json({ error: 'Access denied' });
  if (target.role === 'superadmin' && countSuperadmins(id) === 0) return res.status(400).json({ error: 'Cannot delete the last superadmin.' });
  if (['admin','superadmin'].includes(target.role) && countAdmins(id) === 0) return res.status(400).json({ error: 'Cannot delete the last admin-level user.' });
  if (req.session.user.id === id) return res.status(400).json({ error: 'You cannot delete yourself.' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ success: true });
});

// ── Invitations ───────────────────────────────────────────────────────────────
app.get('/api/invitations', requireAuth, requireEditor, (req, res) => {
  const rows = db.prepare(`SELECT i.id, i.email, i.role, i.created_at, i.expires_at, i.accepted_at, i.revoked_at, u.username AS invited_by_name FROM invitations i LEFT JOIN users u ON u.id = i.invited_by ORDER BY i.created_at DESC`).all();
  rows.forEach(r => {
    if (r.accepted_at) r.status = 'accepted';
    else if (r.revoked_at) r.status = 'revoked';
    else if (new Date(r.expires_at) < new Date()) r.status = 'expired';
    else r.status = 'pending';
  });
  res.json(rows);
});

app.post('/api/invitations', requireAuth, requireEditor, async (req, res) => {
  const { email, role } = req.body;
  if (!email || !role) return res.status(400).json({ error: 'email and role required' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  // Editors can only invite viewers
  const callerRole = req.session.user.role;
  if (callerRole === 'editor' && role !== 'viewer') return res.status(403).json({ error: 'Editors can only invite viewers.' });
  // Developers can invite viewer, editor, developer — not admin/superadmin
  if (callerRole === 'developer' && ['admin','superadmin'].includes(role)) return res.status(403).json({ error: 'Developers cannot invite admins or superadmins.' });
  // Admins can invite viewer, editor, admin — not developer/superadmin
  if (callerRole === 'admin' && ['developer','superadmin'].includes(role)) return res.status(403).json({ error: 'Only superadmins can invite developers and superadmins.' });
  const trimmed = email.trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(trimmed)) return res.status(400).json({ error: 'Invalid email address' });
  // Prevent duplicate email across existing users
  const existingUser = db.prepare('SELECT id, username FROM users WHERE email = ? COLLATE NOCASE').get(trimmed);
  if (existingUser) return res.status(400).json({ error: `Email already in use by user "${existingUser.username}".` });
  const token = genToken();
  const hash  = sha256(token);
  const expires = new Date(Date.now() + 30*24*60*60*1000).toISOString();
  try {
    const r = db.prepare(`INSERT INTO invitations (email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?)`)
      .run(trimmed, role, hash, req.session.user.id, expires);
    try { await mailer.sendInviteEmail({ to: trimmed, role, token, invitedByName: req.session.user.username }); }
    catch (e) { console.error('Mailer error (invite):', e.message); }
    res.json({ id: r.lastInsertRowid, email: trimmed, role, expires_at: expires, dryRun: mailer.dryRun });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/invitations/:id/resend', requireAuth, requireAdmin, async (req, res) => {
  const inv = db.prepare(`SELECT * FROM invitations WHERE id = ?`).get(req.params.id);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.accepted_at) return res.status(400).json({ error: 'Already accepted' });
  if (inv.revoked_at) return res.status(400).json({ error: 'Revoked' });
  const token = genToken();
  const hash  = sha256(token);
  const expires = new Date(Date.now() + 30*24*60*60*1000).toISOString();
  db.prepare(`UPDATE invitations SET token_hash = ?, expires_at = ? WHERE id = ?`).run(hash, expires, inv.id);
  try { await mailer.sendInviteEmail({ to: inv.email, role: inv.role, token, invitedByName: req.session.user.username }); }
  catch (e) { console.error('Mailer error (resend):', e.message); }
  res.json({ success: true, dryRun: mailer.dryRun });
});

app.delete('/api/invitations/:id', requireAuth, requireAdmin, (req, res) => {
  const inv = db.prepare(`SELECT * FROM invitations WHERE id = ?`).get(req.params.id);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.accepted_at) return res.status(400).json({ error: 'Cannot revoke an accepted invite' });
  db.prepare(`UPDATE invitations SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?`).run(inv.id);
  res.json({ success: true });
});

// ── API Keys, Webhooks, fireEvent ────────────────────────────────────────────
// COMMENTED OUT — sync/API import capability disabled for now.
// To re-enable, uncomment the full API keys, webhooks, and fireEvent blocks
// that were here. The database tables (api_keys, webhooks) are still in the
// schema so no migration is needed.
function fireEvent() {} // no-op stub so existing calls don't crash


// ── Departments ───────────────────────────────────────────────────────────────
app.get('/api/departments', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT d.*, e.first_name AS head_first_name, e.last_name AS head_last_name FROM departments d LEFT JOIN employees e ON d.head_employee_id = e.id ORDER BY d.sort_order, d.name`).all();
  res.json(rows);
});
app.get('/api/departments/:id', requireAuth, (req, res) => {
  const dept = db.prepare(`SELECT d.*, e.first_name AS head_first_name, e.last_name AS head_last_name FROM departments d LEFT JOIN employees e ON d.head_employee_id = e.id WHERE d.id=?`).get(req.params.id);
  if (!dept) return res.status(404).json({ error: 'Not found' });
  const standards = db.prepare(`SELECT s.*, ds.scope FROM standards s JOIN department_standards ds ON ds.standard_id = s.id WHERE ds.department_id = ? ORDER BY s.code`).all(req.params.id);
  const positions = db.prepare(`SELECT p.*, COUNT(e.id) as headcount FROM positions p LEFT JOIN employees e ON e.position_id = p.id WHERE p.department_id = ? GROUP BY p.id ORDER BY p.sort_order, p.title`).all(req.params.id);
  const fwd = db.prepare(`SELECT dr.*, d.name AS other_name, d.color AS other_color, d.id AS other_id FROM department_relations dr JOIN departments d ON d.id = dr.dept_b_id WHERE dr.dept_a_id = ? ORDER BY d.name`).all(req.params.id);
  const rev = db.prepare(`SELECT dr.*, d.name AS other_name, d.color AS other_color, d.id AS other_id FROM department_relations dr JOIN departments d ON d.id = dr.dept_a_id WHERE dr.dept_b_id = ? ORDER BY d.name`).all(req.params.id);
  const seen = new Set();
  const relations = [...fwd, ...rev.map(r => ({ ...r, input_from_b: r.output_to_b, output_to_b: r.input_from_b }))].filter(r => seen.has(r.other_id) ? false : (seen.add(r.other_id), true));
  // Divisions of this dept (with head + members)
  const divs = db.prepare(`SELECT d.*, h.first_name AS head_first_name, h.last_name AS head_last_name FROM divisions d LEFT JOIN employees h ON d.head_employee_id = h.id WHERE d.department_id = ? ORDER BY d.sort_order, d.name`).all(req.params.id);
  divs.forEach(div => {
    div.members = db.prepare(`SELECT de.employee_id, e.first_name, e.last_name FROM division_employees de JOIN employees e ON de.employee_id = e.id WHERE de.division_id = ? ORDER BY e.last_name`).all(div.id);
  });
  const deptClauses = db.prepare(`SELECT dc.*, sc.clause_code, sc.title, sc.description AS clause_desc, sc.standard_id, s.code AS standard_code, s.full_name AS standard_name
    FROM department_clauses dc
    JOIN standard_clauses sc ON sc.id = dc.clause_id
    JOIN standards s ON s.id = sc.standard_id
    WHERE dc.department_id = ? ORDER BY s.code, sc.sort_order, sc.clause_code`).all(req.params.id);
  const deptEntries = db.prepare(`SELECT e.*, s.code AS standard_code, s.full_name AS standard_name
    FROM department_standard_entries e
    JOIN standards s ON s.id = e.standard_id
    WHERE e.department_id = ? ORDER BY s.code, e.sort_order, e.id`).all(req.params.id);
  res.json({ ...dept, standards, positions, relations, divisions: divs, clauses: deptClauses, entries: deptEntries });
});
app.post('/api/departments', requireAuth, requireEditor, (req, res) => {
  const { name, color, description, sort_order, head_employee_id } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const r = db.prepare('INSERT INTO departments (name, color, description, sort_order, head_employee_id) VALUES (?, ?, ?, ?, ?)').run(name, color||'#2563eb', description||null, sort_order||0, head_employee_id||null);
    res.json(db.prepare('SELECT * FROM departments WHERE id=?').get(r.lastInsertRowid));
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/departments/:id', requireAuth, requireEditor, (req, res) => {
  const { name, color, description, sort_order, head_employee_id } = req.body;
  db.prepare('UPDATE departments SET name=?, color=?, description=?, sort_order=?, head_employee_id=? WHERE id=?').run(name, color||'#2563eb', description||null, sort_order||0, head_employee_id||null, req.params.id);
  res.json(db.prepare('SELECT * FROM departments WHERE id=?').get(req.params.id));
});
app.delete('/api/departments/:id', requireAuth, requireEditor, (req, res) => {
  const dept = db.prepare('SELECT * FROM departments WHERE id=?').get(req.params.id);
  if (!dept) return res.status(404).json({ error: 'Not found' });
  if (dept.name.toLowerCase() === 'operations') return res.status(400).json({ error: 'The Operations department cannot be deleted.' });
  db.prepare('DELETE FROM departments WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Department Relations ──────────────────────────────────────────────────────
app.get('/api/relations', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT dr.*, a.name AS dept_a_name, a.color AS dept_a_color, b.name AS dept_b_name, b.color AS dept_b_color FROM department_relations dr JOIN departments a ON a.id = dr.dept_a_id JOIN departments b ON b.id = dr.dept_b_id ORDER BY a.name, b.name`).all());
});
app.post('/api/relations', requireAuth, requireEditor, (req, res) => {
  const { dept_a_id, dept_b_id, relation, input_from_b, output_to_b } = req.body;
  if (!dept_a_id || !dept_b_id) return res.status(400).json({ error: 'Both departments required' });
  if (dept_a_id === dept_b_id) return res.status(400).json({ error: 'Cannot relate a dept to itself' });
  try {
    const r = db.prepare(`INSERT INTO department_relations (dept_a_id, dept_b_id, relation, input_from_b, output_to_b) VALUES (?, ?, ?, ?, ?)`).run(dept_a_id, dept_b_id, relation||null, input_from_b||null, output_to_b||null);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/relations/:id', requireAuth, requireEditor, (req, res) => {
  const { relation, input_from_b, output_to_b } = req.body;
  db.prepare('UPDATE department_relations SET relation=?, input_from_b=?, output_to_b=? WHERE id=?').run(relation||null, input_from_b||null, output_to_b||null, req.params.id);
  res.json({ success: true });
});
app.delete('/api/relations/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM department_relations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Standards ─────────────────────────────────────────────────────────────────
app.get('/api/standards', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM standards ORDER BY code').all());
});
app.get('/api/standards/:id', requireAuth, (req, res) => {
  const s = db.prepare('SELECT * FROM standards WHERE id=?').get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Not found' });
  s.departments = db.prepare(`SELECT ds.scope, d.id, d.name, d.color FROM department_standards ds JOIN departments d ON d.id = ds.department_id WHERE ds.standard_id = ? ORDER BY d.name`).all(s.id);
  s.projects = db.prepare(`SELECT ps.scope, cp.id, cp.name, cp.color FROM project_standards ps JOIN client_projects cp ON cp.id = ps.project_id WHERE ps.standard_id = ? ORDER BY cp.name`).all(s.id);
  s.clauses = db.prepare('SELECT * FROM standard_clauses WHERE standard_id = ? ORDER BY sort_order, clause_code').all(s.id);
  res.json(s);
});
app.post('/api/standards', requireAuth, requireEditor, (req, res) => {
  const { code, full_name, url, description } = req.body;
  if (!code || !full_name) return res.status(400).json({ error: 'code and full_name required' });
  try {
    const r = db.prepare('INSERT INTO standards (code, full_name, url, description) VALUES (?, ?, ?, ?)').run(code, full_name, url||null, description||null);
    res.json({ id: r.lastInsertRowid, code, full_name, url, description });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/standards/:id', requireAuth, requireEditor, (req, res) => {
  const { code, full_name, url, description } = req.body;
  if (!code || !full_name) return res.status(400).json({ error: 'code and full_name required' });
  try {
    db.prepare('UPDATE standards SET code=?, full_name=?, url=?, description=? WHERE id=?').run(code, full_name, url||null, description||null, req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/standards/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM standards WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Standard Clauses ────────────────────────────────────────────────────────
app.get('/api/standards/:id/clauses', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM standard_clauses WHERE standard_id = ? ORDER BY sort_order, clause_code').all(req.params.id));
});
app.post('/api/standards/:id/clauses', requireAuth, requireEditor, (req, res) => {
  const { parent_id, clause_code, title, description, sort_order } = req.body;
  if (!clause_code || !title) return res.status(400).json({ error: 'clause_code and title required' });
  try {
    const r = db.prepare('INSERT INTO standard_clauses (standard_id, parent_id, clause_code, title, description, sort_order) VALUES (?, ?, ?, ?, ?, ?)')
      .run(req.params.id, parent_id||null, clause_code, title, description||null, sort_order||0);
    res.json({ id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/clauses/:id', requireAuth, requireEditor, (req, res) => {
  const { clause_code, title, description, sort_order } = req.body;
  if (!clause_code || !title) return res.status(400).json({ error: 'clause_code and title required' });
  db.prepare('UPDATE standard_clauses SET clause_code=?, title=?, description=?, sort_order=? WHERE id=?')
    .run(clause_code, title, description||null, sort_order||0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/clauses/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM standard_clauses WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Department ↔ Clause links ───────────────────────────────────────────────
app.get('/api/departments/:id/clauses', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT dc.*, sc.clause_code, sc.title, sc.description AS clause_desc, sc.standard_id, s.code AS standard_code
    FROM department_clauses dc
    JOIN standard_clauses sc ON sc.id = dc.clause_id
    JOIN standards s ON s.id = sc.standard_id
    WHERE dc.department_id = ? ORDER BY s.code, sc.sort_order, sc.clause_code`).all(req.params.id));
});
app.post('/api/departments/:id/clauses', requireAuth, requireEditor, (req, res) => {
  const { clause_id, compliance, notes } = req.body;
  if (!clause_id) return res.status(400).json({ error: 'clause_id required' });
  try {
    db.prepare('INSERT OR REPLACE INTO department_clauses (department_id, clause_id, compliance, notes) VALUES (?, ?, ?, ?)')
      .run(req.params.id, clause_id, compliance||'applicable', notes||null);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/departments/:deptId/clauses/:clauseId', requireAuth, requireEditor, (req, res) => {
  const { compliance, notes } = req.body;
  db.prepare('UPDATE department_clauses SET compliance=?, notes=? WHERE department_id=? AND clause_id=?')
    .run(compliance||'applicable', notes||null, req.params.deptId, req.params.clauseId);
  res.json({ success: true });
});
app.delete('/api/departments/:deptId/clauses/:clauseId', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM department_clauses WHERE department_id=? AND clause_id=?').run(req.params.deptId, req.params.clauseId);
  res.json({ success: true });
});

app.post('/api/departments/:id/standards', requireAuth, requireEditor, (req, res) => {
  const { standard_id, scope } = req.body;
  try { db.prepare('INSERT OR REPLACE INTO department_standards (department_id, standard_id, scope) VALUES (?, ?, ?)').run(req.params.id, standard_id, scope||null); res.json({ success: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/departments/:id/standards/:sid', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM department_standards WHERE department_id=? AND standard_id=?').run(req.params.id, req.params.sid);
  // Also delete free-text entries for this dept+standard
  db.prepare('DELETE FROM department_standard_entries WHERE department_id=? AND standard_id=?').run(req.params.id, req.params.sid);
  res.json({ success: true });
});

// ── Department Standard Entries (free-text clause + comment per dept per standard) ─
app.get('/api/departments/:deptId/standards/:stdId/entries', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM department_standard_entries WHERE department_id=? AND standard_id=? ORDER BY sort_order, id').all(req.params.deptId, req.params.stdId));
});
app.post('/api/departments/:deptId/standards/:stdId/entries', requireAuth, requireEditor, (req, res) => {
  const { clause_text, comment, sort_order } = req.body;
  if (!clause_text) return res.status(400).json({ error: 'clause_text required' });
  const r = db.prepare('INSERT INTO department_standard_entries (department_id, standard_id, clause_text, comment, sort_order) VALUES (?, ?, ?, ?, ?)')
    .run(req.params.deptId, req.params.stdId, clause_text, comment||null, sort_order||0);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/dept-std-entries/:id', requireAuth, requireEditor, (req, res) => {
  const { clause_text, comment, sort_order } = req.body;
  if (!clause_text) return res.status(400).json({ error: 'clause_text required' });
  db.prepare('UPDATE department_standard_entries SET clause_text=?, comment=?, sort_order=? WHERE id=?')
    .run(clause_text, comment||null, sort_order||0, req.params.id);
  res.json({ success: true });
});
app.delete('/api/dept-std-entries/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM department_standard_entries WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Positions ─────────────────────────────────────────────────────────────────
app.get('/api/positions', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT p.*, d.name AS dept_name, d.color AS dept_color, cp.name AS project_name, cp.color AS project_color, COUNT(e.id) as headcount FROM positions p LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN client_projects cp ON p.project_id = cp.id LEFT JOIN employees e ON e.position_id = p.id GROUP BY p.id ORDER BY COALESCE(d.name, cp.name), p.sort_order, p.title`).all());
});
app.get('/api/positions/:id', requireAuth, (req, res) => {
  const pos = db.prepare(`SELECT p.*, d.name AS dept_name, d.color AS dept_color, cp.name AS project_name, cp.color AS project_color FROM positions p LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN client_projects cp ON p.project_id = cp.id WHERE p.id=?`).get(req.params.id);
  if (!pos) return res.status(404).json({ error: 'Not found' });
  // Holders of this position with their department and primary client project (if any)
  const holders = db.prepare(`
    SELECT
      e.id, e.first_name, e.last_name, e.is_virtual,
      d.id AS dept_id, d.name AS dept_name, d.color AS dept_color,
      cp.id AS project_id, cp.name AS project_name, cp.color AS project_color, cp.status AS project_status
    FROM employees e
    LEFT JOIN positions p2     ON e.position_id = p2.id
    LEFT JOIN departments d    ON p2.department_id = d.id
    LEFT JOIN project_assignments pa ON pa.employee_id = e.id AND pa.is_primary = 1
    LEFT JOIN client_projects cp ON pa.project_id = cp.id
    WHERE e.position_id = ?
    ORDER BY e.last_name, e.first_name
  `).all(req.params.id);
  res.json({ ...pos, holders });
});
app.post('/api/positions', requireAuth, requireEditor, (req, res) => {
  let { title, department_id, project_id, description, sort_order } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  // A position can have department XOR project, not both
  if (department_id && project_id) project_id = null;
  try {
    const r = db.prepare('INSERT INTO positions (title, department_id, project_id, description, sort_order) VALUES (?, ?, ?, ?, ?)').run(title, department_id||null, project_id||null, description||null, sort_order||0);
    res.json(db.prepare('SELECT * FROM positions WHERE id=?').get(r.lastInsertRowid));
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/positions/:id', requireAuth, requireEditor, (req, res) => {
  let { title, department_id, project_id, description, sort_order } = req.body;
  if (department_id && project_id) project_id = null;
  db.prepare('UPDATE positions SET title=?, department_id=?, project_id=?, description=?, sort_order=? WHERE id=?').run(title, department_id||null, project_id||null, description||null, sort_order||0, req.params.id);
  res.json(db.prepare('SELECT * FROM positions WHERE id=?').get(req.params.id));
});
app.delete('/api/positions/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM positions WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Locations ─────────────────────────────────────────────────────────────────
app.get('/api/locations', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM locations ORDER BY name').all());
});
app.post('/api/locations', requireAuth, requireEditor, (req, res) => {
  const { name, country } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const r = db.prepare('INSERT INTO locations (name, country) VALUES (?, ?)').run(name, country||null);
    res.json(db.prepare('SELECT * FROM locations WHERE id=?').get(r.lastInsertRowid));
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/locations/:id', requireAuth, requireEditor, (req, res) => {
  const { name, country } = req.body;
  db.prepare('UPDATE locations SET name=?, country=? WHERE id=?').run(name, country||null, req.params.id);
  res.json(db.prepare('SELECT * FROM locations WHERE id=?').get(req.params.id));
});
app.delete('/api/locations/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM locations WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Employees ─────────────────────────────────────────────────────────────────
function fetchEmployeeEmails(empId) {
  return db.prepare(`SELECT id, email, label, is_primary FROM employee_emails WHERE employee_id=? ORDER BY is_primary DESC, id ASC`).all(empId);
}
function fullEmployee(empId) {
  const out = db.prepare('SELECT * FROM employees WHERE id=?').get(empId);
  if (!out) return null;
  out.emails = fetchEmployeeEmails(empId);
  out.projects = db.prepare(`SELECT pa.project_id AS id, pa.role_on_project, pa.is_primary, cp.name, cp.color FROM project_assignments pa JOIN client_projects cp ON cp.id = pa.project_id WHERE pa.employee_id = ?`).all(empId);
  out.divisions = db.prepare(`SELECT de.*, d.name AS division_name, d.color AS division_color FROM division_employees de JOIN divisions d ON d.id = de.division_id WHERE de.employee_id = ?`).all(empId);
  return out;
}

app.get('/api/employees', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT e.*, p.title AS position_title, d.name AS dept_name, d.color AS dept_color, d.id AS dept_id, m.first_name || ' ' || m.last_name AS manager_name, l.name AS location_name, l.country AS location_country, l.id AS location_id FROM employees e LEFT JOIN positions p ON e.position_id = p.id LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN employees m ON e.manager_id = m.id LEFT JOIN locations l ON e.location_id = l.id ORDER BY e.last_name, e.first_name`).all();
  // Bulk-load project & division memberships so the admin UI can filter pickers locally
  const allAssign = db.prepare(`SELECT employee_id, project_id FROM project_assignments`).all();
  const projMap = {};
  allAssign.forEach(r => { (projMap[r.employee_id] = projMap[r.employee_id] || []).push(r.project_id); });
  const allDiv = db.prepare(`SELECT employee_id, division_id FROM division_employees`).all();
  const divMap = {};
  allDiv.forEach(r => { (divMap[r.employee_id] = divMap[r.employee_id] || []).push(r.division_id); });
  rows.forEach(r => {
    r.emails = fetchEmployeeEmails(r.id);
    r.project_ids = projMap[r.id] || [];
    r.division_ids = divMap[r.id] || [];
  });
  res.json(rows);
});

app.get('/api/employees/:id', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT e.*, p.title AS position_title, d.name AS dept_name, d.color AS dept_color, d.id AS dept_id, m.first_name || ' ' || m.last_name AS manager_name, l.name AS location_name, l.country AS location_country, l.id AS location_id FROM employees e LEFT JOIN positions p ON e.position_id = p.id LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN employees m ON e.manager_id = m.id LEFT JOIN locations l ON e.location_id = l.id WHERE e.id=?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  row.emails = fetchEmployeeEmails(row.id);
  row.projects = db.prepare(`SELECT pa.project_id AS id, pa.role_on_project, pa.is_primary, cp.name, cp.color, cp.status FROM project_assignments pa JOIN client_projects cp ON cp.id = pa.project_id WHERE pa.employee_id = ? ORDER BY pa.is_primary DESC, cp.name`).all(row.id);
  row.divisions = db.prepare(`SELECT de.*, d.name AS division_name, d.color AS division_color, d.project_id, d.department_id FROM division_employees de JOIN divisions d ON d.id = de.division_id WHERE de.employee_id = ? ORDER BY de.is_primary DESC, d.name`).all(row.id);
  res.json(row);
});

app.post('/api/employees', requireAuth, requireEditor, (req, res) => {
  const { first_name, last_name, position_id, phone, location_id, hire_date, bio, education, experience, manager_id, emails } = req.body;
  if (!first_name || !last_name) return res.status(400).json({ error: 'first_name and last_name required' });
  try {
    const tx = db.transaction(() => {
      let primary = null;
      if (Array.isArray(emails) && emails.length > 0) {
        const p = emails.filter(e => e.is_primary && e.email);
        primary = (p[0] || emails.find(e => e.email) || {}).email || null;
      }
      const r = db.prepare(`INSERT INTO employees (first_name, last_name, position_id, email, phone, location_id, hire_date, bio, education, experience, manager_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(first_name, last_name, position_id||null, primary, phone||null, location_id||null, hire_date||null, bio||null, education||null, experience||null, manager_id||null);
      const empId = r.lastInsertRowid;
      if (Array.isArray(emails)) {
        const ins = db.prepare(`INSERT INTO employee_emails (employee_id, email, label, is_primary) VALUES (?, ?, ?, ?)`);
        emails.filter(e => e.email && e.email.trim()).forEach(e => ins.run(empId, e.email.trim(), e.label||null, e.is_primary?1:0));
      }
      return empId;
    });
    const id = tx();
    fireEvent('employee.created', fullEmployee(id));
    res.json(fullEmployee(id));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/api/employees/:id', requireAuth, requireEditor, (req, res) => {
  const { first_name, last_name, phone, location_id, hire_date, bio, education, experience, manager_id, emails } = req.body;
  const existing = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Not found' });
  const position_id = ('position_id' in req.body) ? (req.body.position_id||null) : existing.position_id;
  const mgr_id = ('manager_id' in req.body) ? (req.body.manager_id||null) : existing.manager_id;
  const loc_id = ('location_id' in req.body) ? (req.body.location_id||null) : existing.location_id;
  const edu = ('education' in req.body) ? (education||null) : existing.education;
  const exp = ('experience' in req.body) ? (experience||null) : existing.experience;
  try {
    db.transaction(() => {
      let primary = null;
      if (Array.isArray(emails) && emails.length > 0) {
        const p = emails.filter(e => e.is_primary && e.email);
        primary = (p[0] || emails.find(e => e.email) || {}).email || null;
      }
      db.prepare(`UPDATE employees SET first_name=?, last_name=?, position_id=?, email=?, phone=?, location_id=?, hire_date=?, bio=?, education=?, experience=?, manager_id=? WHERE id=?`)
        .run(first_name, last_name, position_id, primary, phone||null, loc_id, hire_date||null, bio||null, edu, exp, mgr_id, req.params.id);
      if (Array.isArray(emails)) {
        db.prepare('DELETE FROM employee_emails WHERE employee_id = ?').run(req.params.id);
        const ins = db.prepare(`INSERT INTO employee_emails (employee_id, email, label, is_primary) VALUES (?, ?, ?, ?)`);
        emails.filter(e => e.email && e.email.trim()).forEach(e => ins.run(req.params.id, e.email.trim(), e.label||null, e.is_primary?1:0));
      }
    })();
    const out = fullEmployee(req.params.id);
    fireEvent('employee.updated', out);
    res.json(out);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/employees/:id', requireAuth, requireEditor, (req, res) => {
  const emp = db.prepare('SELECT * FROM employees WHERE id=?').get(req.params.id);
  if (!emp) return res.status(404).json({ error: 'Not found' });
  if (emp.is_virtual) return res.status(400).json({ error: 'Cannot delete a virtual node directly.' });
  db.prepare('UPDATE employees SET manager_id=? WHERE manager_id=?').run(emp.manager_id, emp.id);
  db.prepare('DELETE FROM employees WHERE id=?').run(req.params.id);
  fireEvent('employee.deleted', { id: emp.id, first_name: emp.first_name, last_name: emp.last_name });
  res.json({ success: true });
});

// ── Client Projects ───────────────────────────────────────────────────────────
app.get('/api/client-projects', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT cp.*, e.first_name AS head_first_name, e.last_name AS head_last_name FROM client_projects cp LEFT JOIN employees e ON cp.head_employee_id = e.id ORDER BY cp.name`).all();
  rows.forEach(p => { p.headcount = db.prepare('SELECT COUNT(*) AS c FROM project_assignments WHERE project_id = ?').get(p.id).c; });
  res.json(rows);
});
app.get('/api/client-projects/:id', requireAuth, (req, res) => {
  const p = db.prepare(`SELECT cp.*, e.first_name AS head_first_name, e.last_name AS head_last_name FROM client_projects cp LEFT JOIN employees e ON cp.head_employee_id = e.id WHERE cp.id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  p.standards = db.prepare(`SELECT s.*, ps.scope FROM standards s JOIN project_standards ps ON ps.standard_id = s.id WHERE ps.project_id = ? ORDER BY s.code`).all(p.id);
  p.members = db.prepare(`SELECT e.id, e.first_name, e.last_name, pos.title AS position_title, pa.role_on_project, pa.is_primary, d.color AS dept_color FROM project_assignments pa JOIN employees e ON e.id = pa.employee_id LEFT JOIN positions pos ON pos.id = e.position_id LEFT JOIN departments d ON d.id = pos.department_id WHERE pa.project_id = ? ORDER BY pa.is_primary DESC, e.last_name, e.first_name`).all(p.id);
  // Divisions of this project
  p.divisions = db.prepare(`SELECT d.*, h.first_name AS head_first_name, h.last_name AS head_last_name FROM divisions d LEFT JOIN employees h ON d.head_employee_id = h.id WHERE d.project_id = ? ORDER BY d.sort_order, d.name`).all(p.id);
  p.divisions.forEach(div => {
    div.members = db.prepare(`SELECT de.employee_id, e.first_name, e.last_name FROM division_employees de JOIN employees e ON de.employee_id = e.id WHERE de.division_id = ? ORDER BY e.last_name`).all(div.id);
  });
  res.json(p);
});
app.post('/api/client-projects', requireAuth, requireEditor, (req, res) => {
  const { name, client_company, description, color, status, start_date, end_date, languages, client_contact, notes, head_employee_id } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  ensureOperationsDept(); // auto-create Operations if it doesn't exist
  try {
    const r = db.prepare(`INSERT INTO client_projects (name, client_company, description, color, status, start_date, end_date, languages, client_contact, notes, head_employee_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(name, client_company||null, description||null, color||'#0f766e', status||'active', start_date||null, end_date||null, languages||null, client_contact||null, notes||null, head_employee_id||null);
    res.json(db.prepare('SELECT * FROM client_projects WHERE id=?').get(r.lastInsertRowid));
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/client-projects/:id', requireAuth, requireEditor, (req, res) => {
  const { name, client_company, description, color, status, start_date, end_date, languages, client_contact, notes, head_employee_id } = req.body;
  try {
    db.prepare(`UPDATE client_projects SET name=?, client_company=?, description=?, color=?, status=?, start_date=?, end_date=?, languages=?, client_contact=?, notes=?, head_employee_id=? WHERE id=?`)
      .run(name, client_company||null, description||null, color||'#0f766e', status||'active', start_date||null, end_date||null, languages||null, client_contact||null, notes||null, head_employee_id||null, req.params.id);
    res.json(db.prepare('SELECT * FROM client_projects WHERE id=?').get(req.params.id));
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/client-projects/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM client_projects WHERE id=?').run(req.params.id);
  res.json({ success: true });
});
app.post('/api/client-projects/:id/assignments', requireAuth, requireEditor, (req, res) => {
  const { employee_id, role_on_project, is_primary } = req.body;
  if (!employee_id) return res.status(400).json({ error: 'employee_id required' });
  try {
    db.prepare(`INSERT OR REPLACE INTO project_assignments (employee_id, project_id, role_on_project, is_primary) VALUES (?, ?, ?, ?)`)
      .run(employee_id, req.params.id, role_on_project||null, is_primary?1:0);
    fireEvent('project.assignment.changed', { project_id: parseInt(req.params.id), employee_id, action: 'set' });
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/client-projects/:id/assignments/:eid', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM project_assignments WHERE project_id=? AND employee_id=?').run(req.params.id, req.params.eid);
  fireEvent('project.assignment.changed', { project_id: parseInt(req.params.id), employee_id: parseInt(req.params.eid), action: 'removed' });
  res.json({ success: true });
});
app.post('/api/client-projects/:id/standards', requireAuth, requireEditor, (req, res) => {
  const { standard_id, scope } = req.body;
  if (!standard_id) return res.status(400).json({ error: 'standard_id required' });
  try { db.prepare('INSERT OR REPLACE INTO project_standards (project_id, standard_id, scope) VALUES (?, ?, ?)').run(req.params.id, standard_id, scope||null); res.json({ success: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/client-projects/:id/standards/:sid', requireAuth, requireEditor, (req, res) => {
  db.prepare('DELETE FROM project_standards WHERE project_id=? AND standard_id=?').run(req.params.id, req.params.sid);
  res.json({ success: true });
});

// ── Divisions (simplified: belongs to dept OR project, optional head) ─────────
app.get('/api/divisions', requireAuth, (req, res) => {
  const { project_id, department_id } = req.query;
  let sql = `SELECT d.*, h.first_name AS head_first_name, h.last_name AS head_last_name, COUNT(de.employee_id) AS member_count FROM divisions d LEFT JOIN employees h ON d.head_employee_id = h.id LEFT JOIN division_employees de ON de.division_id = d.id`;
  let params = [];
  if (project_id) { sql += ` WHERE d.project_id = ?`; params = [project_id]; }
  else if (department_id) { sql += ` WHERE d.department_id = ?`; params = [department_id]; }
  sql += ` GROUP BY d.id ORDER BY d.sort_order, d.name`;
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/divisions/:id', requireAuth, (req, res) => {
  const div = db.prepare(`SELECT d.*, h.first_name AS head_first_name, h.last_name AS head_last_name FROM divisions d LEFT JOIN employees h ON d.head_employee_id = h.id WHERE d.id = ?`).get(req.params.id);
  if (!div) return res.status(404).json({ error: 'Not found' });
  div.members = db.prepare(`SELECT de.employee_id, de.role_in_division, de.is_head, de.is_primary, e.first_name, e.last_name, p.title AS position_title FROM division_employees de JOIN employees e ON e.id = de.employee_id LEFT JOIN positions p ON p.id = e.position_id WHERE de.division_id = ? ORDER BY e.last_name`).all(req.params.id);
  res.json(div);
});

app.post('/api/divisions', requireAuth, requireEditor, (req, res) => {
  const { name, project_id, department_id, head_employee_id, color, description, sort_order } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  if (!!project_id === !!department_id) return res.status(400).json({ error: 'Specify exactly one of project_id or department_id' });
  try {
    const r = db.prepare(`INSERT INTO divisions (name, project_id, department_id, head_employee_id, color, description, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(name, project_id||null, department_id||null, head_employee_id||null, color||null, description||null, sort_order||0);
    res.json(db.prepare(`SELECT * FROM divisions WHERE id = ?`).get(r.lastInsertRowid));
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.put('/api/divisions/:id', requireAuth, requireEditor, (req, res) => {
  const { name, head_employee_id, color, description, sort_order } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  db.prepare(`UPDATE divisions SET name=?, head_employee_id=?, color=?, description=?, sort_order=? WHERE id=?`)
    .run(name, head_employee_id||null, color||null, description||null, sort_order||0, req.params.id);
  res.json(db.prepare(`SELECT * FROM divisions WHERE id = ?`).get(req.params.id));
});

app.delete('/api/divisions/:id', requireAuth, requireEditor, (req, res) => {
  db.prepare(`DELETE FROM divisions WHERE id = ?`).run(req.params.id);
  res.json({ success: true });
});

// Add a member to a division (idempotent — UNIQUE constraint)
app.post('/api/divisions/:id/members', requireAuth, requireEditor, (req, res) => {
  const { employee_id, role_in_division, is_head, is_primary } = req.body;
  if (!employee_id) return res.status(400).json({ error: 'employee_id required' });
  try {
    db.prepare(`INSERT INTO division_employees (division_id, employee_id, role_in_division, is_head, is_primary) VALUES (?, ?, ?, ?, ?) ON CONFLICT(division_id, employee_id) DO UPDATE SET role_in_division=excluded.role_in_division, is_head=excluded.is_head, is_primary=excluded.is_primary`).run(req.params.id, employee_id, role_in_division||null, is_head?1:0, is_primary?1:0);
    res.json({ success: true });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/divisions/:id/members/:eid', requireAuth, requireEditor, (req, res) => {
  db.prepare(`DELETE FROM division_employees WHERE division_id=? AND employee_id=?`).run(req.params.id, req.params.eid);
  res.json({ success: true });
});

// Replace all members of a division at once (used by dept/project admin forms)
app.put('/api/divisions/:id/members', requireAuth, requireEditor, (req, res) => {
  const { members } = req.body;
  // Accepts either {members: [{employee_id, role_in_division, is_head, is_primary}]} or {employee_ids: [ids]}
  const list = Array.isArray(members) ? members : (Array.isArray(req.body.employee_ids) ? req.body.employee_ids.map(id=>({employee_id:id})) : null);
  if (!list) return res.status(400).json({ error: 'members array required' });
  const tx = db.transaction(() => {
    db.prepare(`DELETE FROM division_employees WHERE division_id = ?`).run(req.params.id);
    const ins = db.prepare(`INSERT OR IGNORE INTO division_employees (division_id, employee_id, role_in_division, is_head, is_primary) VALUES (?, ?, ?, ?, ?)`);
    list.forEach(m => {
      const eid = m.employee_id || m;
      ins.run(req.params.id, eid, m.role_in_division||null, m.is_head?1:0, m.is_primary?1:0);
    });
  });
  tx();
  res.json({ success: true });
});

app.get('/api/employees/:id/divisions', requireAuth, (req, res) => {
  res.json(db.prepare(`SELECT de.*, d.name AS division_name, d.color AS division_color, d.project_id, d.department_id, d.head_employee_id FROM division_employees de JOIN divisions d ON d.id = de.division_id WHERE de.employee_id = ? ORDER BY d.name`).all(req.params.id));
});

// ── OrgChart ──────────────────────────────────────────────────────────────────
app.get('/api/orgchart', requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT e.id, e.first_name, e.last_name, e.email, e.phone, e.hire_date, e.bio, e.education, e.experience, e.manager_id, e.is_virtual, p.title AS position_title, p.id AS position_id, p.description AS position_description, p.project_id AS position_project_id, d.id AS dept_id, d.name AS dept, d.color AS dept_color, l.id AS location_id, l.name AS location_name, l.country AS location_country FROM employees e LEFT JOIN positions p ON e.position_id = p.id LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN locations l ON e.location_id = l.id`).all();
  const allEmails = db.prepare(`SELECT employee_id, email, label, is_primary FROM employee_emails ORDER BY is_primary DESC, id ASC`).all();
  const emailMap = {};
  allEmails.forEach(r => { (emailMap[r.employee_id] = emailMap[r.employee_id] || []).push({ email: r.email, label: r.label, is_primary: !!r.is_primary }); });
  const allAssign = db.prepare(`SELECT pa.employee_id, pa.project_id, pa.role_on_project, pa.is_primary, cp.name AS project_name, cp.color AS project_color, cp.status AS project_status FROM project_assignments pa JOIN client_projects cp ON cp.id = pa.project_id`).all();
  const projMap = {};
  allAssign.forEach(r => { (projMap[r.employee_id] = projMap[r.employee_id] || []).push({ project_id:r.project_id, project_name:r.project_name, project_color:r.project_color, project_status:r.project_status, role_on_project:r.role_on_project, is_primary:!!r.is_primary }); });
  const allDivAssign = db.prepare(`SELECT de.employee_id, de.division_id, d.name AS division_name, d.color AS division_color, d.project_id AS div_project_id, d.department_id AS div_dept_id, d.head_employee_id AS div_head_id FROM division_employees de JOIN divisions d ON d.id = de.division_id`).all();
  const divMap = {};
  allDivAssign.forEach(r => { (divMap[r.employee_id] = divMap[r.employee_id] || []).push({
    division_id: r.division_id, division_name: r.division_name, division_color: r.division_color,
    project_id: r.div_project_id, department_id: r.div_dept_id, head_employee_id: r.div_head_id,
    is_head: r.div_head_id === r.employee_id
  }); });
  // Heads-of map: which dept/project this employee leads
  const deptHeads = db.prepare(`SELECT id, head_employee_id FROM departments WHERE head_employee_id IS NOT NULL`).all();
  const projHeads = db.prepare(`SELECT id, head_employee_id FROM client_projects WHERE head_employee_id IS NOT NULL`).all();
  const headOfDeptMap = {}; deptHeads.forEach(r => { headOfDeptMap[r.head_employee_id] = r.id; });
  const headOfProjMap = {}; projHeads.forEach(r => { headOfProjMap[r.head_employee_id] = r.id; });
  res.json(rows.map(r => ({
    id: r.id, pid: r.manager_id || null,
    name: `${r.first_name} ${r.last_name}`.trim(),
    title: r.position_title || '',
    email: r.email || '',
    emails: emailMap[r.id] || (r.email ? [{email: r.email, label: null, is_primary: true}] : []),
    phone: r.phone || '',
    location_id: r.location_id || null,
    location_name: r.location_name || '',
    location_country: r.location_country || '',
    hire_date: r.hire_date || '',
    bio: r.bio || '',
    education: r.education || '',
    experience: r.experience || '',
    dept: r.dept || '',
    dept_id: r.dept_id || null,
    dept_color: r.dept_color || '#2563eb',
    position_id: r.position_id || null,
    position_description: r.position_description || '',
    position_project_id: r.position_project_id || null,
    is_virtual: r.is_virtual || 0,
    is_project_employee: !!r.position_project_id, // employees whose position belongs to a project
    head_of_dept_id:    headOfDeptMap[r.id] || null,
    head_of_project_id: headOfProjMap[r.id] || null,
    projects: projMap[r.id] || [],
    divisions: divMap[r.id] || [],
  })));
});

app.listen(PORT, () => {
  console.log(`\n  ✅  OrgChart  → http://localhost:${PORT}`);
  console.log(`  ✅  Admin     → http://localhost:${PORT}/admin.html`);
  console.log(`  ✅  Login     → http://localhost:${PORT}/login.html\n`);
});
