#!/usr/bin/env node
const bcrypt = require('bcrypt');
const db     = require('./database');

const VALID_ROLES = ['viewer', 'editor', 'admin', 'developer', 'superadmin'];
const MIN_PASSWORD_LEN = 6;

const [, , cmd, ...args] = process.argv;

function fail(msg, code = 1) { console.error('❌ ' + msg); process.exit(code); }

function help() {
  console.log(`
KiKxxl-evroTarget OrgChart — User Management

Commands:
  add <username> <password> <role> <email>  Create a new user
  list                                 List all users
  delete <username>                    Delete a user
  passwd <username> <new-password>     Reset a user's password (CLI emergency fallback)
  role <username> <new-role>           Change a user's role

Roles:
  viewer      — read-only access to the chart
  editor      — edit org data, manage viewers
  admin       — full org + user management (CEO, HR)
  developer   — API keys, webhooks, sync mode, bulk import (IT)
  superadmin  — everything, no restrictions

Examples:
  node manage-users.js add besart MySecret123 superadmin besart@example.com
  node manage-users.js add itguy ITpass456 developer it@example.com
  node manage-users.js list
  node manage-users.js role alice admin
  node manage-users.js passwd alice NewPass456
`);
}

function countSuperadmins(excludeUsername) {
  const sql = excludeUsername
    ? `SELECT COUNT(*) AS c FROM users WHERE role='superadmin' AND username != ? COLLATE NOCASE`
    : `SELECT COUNT(*) AS c FROM users WHERE role='superadmin'`;
  return excludeUsername
    ? db.prepare(sql).get(excludeUsername).c
    : db.prepare(sql).get().c;
}

function countAdmins(excludeUsername) {
  // Counts admins + superadmins (both can manage the system)
  const sql = excludeUsername
    ? `SELECT COUNT(*) AS c FROM users WHERE role IN ('admin','superadmin') AND username != ? COLLATE NOCASE`
    : `SELECT COUNT(*) AS c FROM users WHERE role IN ('admin','superadmin')`;
  return excludeUsername
    ? db.prepare(sql).get(excludeUsername).c
    : db.prepare(sql).get().c;
}

(async () => {
  try {
    if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
      help(); process.exit(0);
    }

    // ── add ───────────────────────────────────────────────────────────────────
    if (cmd === 'add') {
      const [username, password, role, email] = args;
      if (!username || !password || !role || !email) fail('Usage: add <username> <password> <role> <email>');
      if (!VALID_ROLES.includes(role)) fail(`Role must be one of: ${VALID_ROLES.join(', ')}`);
      if (password.length < MIN_PASSWORD_LEN) fail(`Password must be at least ${MIN_PASSWORD_LEN} characters.`);
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) fail('Invalid email address.');
      if (db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(username)) {
        fail(`User "${username}" already exists.`);
      }
      if (db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email.trim())) {
        fail(`Email "${email}" is already in use.`);
      }
      const hash = await bcrypt.hash(password, 10);
      db.prepare('INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)').run(username, hash, role, email.trim());
      console.log(`✅ Created ${role} "${username}" (${email.trim()}).`);
      return;
    }

    // ── list ──────────────────────────────────────────────────────────────────
    if (cmd === 'list') {
      const rows = db.prepare(
        `SELECT id, username, email, role, created_at FROM users ORDER BY
           CASE role
             WHEN 'superadmin' THEN 1
             WHEN 'admin'      THEN 2
             WHEN 'developer'  THEN 3
             WHEN 'editor'     THEN 4
             WHEN 'viewer'     THEN 5
             ELSE 6
           END, username COLLATE NOCASE`
      ).all();
      if (rows.length === 0) {
        console.log('(no users yet — create one with `add`)');
        return;
      }
      console.log('\n  ID  ROLE         USERNAME                EMAIL                   CREATED');
      console.log('  ──  ───────────  ──────────────────────  ──────────────────────  ───────────────────');
      rows.forEach(r => {
        console.log(
          `  ${String(r.id).padEnd(2)}  ${r.role.padEnd(11)}  ${r.username.padEnd(22)}  ${(r.email||'—').padEnd(22)}  ${r.created_at}`
        );
      });
      console.log('');
      return;
    }

    // ── delete ────────────────────────────────────────────────────────────────
    if (cmd === 'delete') {
      const [username] = args;
      if (!username) fail('Usage: delete <username>');
      const user = db.prepare('SELECT id, role FROM users WHERE username = ? COLLATE NOCASE').get(username);
      if (!user) fail(`User "${username}" not found.`);
      if (user.role === 'superadmin' && countSuperadmins(username) === 0) {
        fail(`Cannot delete "${username}": last superadmin.`);
      }
      if (['admin','superadmin'].includes(user.role) && countAdmins(username) === 0) {
        fail(`Cannot delete "${username}": last admin-level user.`);
      }
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
      console.log(`✅ Deleted "${username}".`);
      return;
    }

    // ── passwd ────────────────────────────────────────────────────────────────
    if (cmd === 'passwd') {
      const [username, password] = args;
      if (!username || !password) fail('Usage: passwd <username> <new-password>');
      if (password.length < MIN_PASSWORD_LEN) fail(`Password must be at least ${MIN_PASSWORD_LEN} characters.`);
      const user = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(username);
      if (!user) fail(`User "${username}" not found.`);
      const hash = await bcrypt.hash(password, 10);
      db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, user.id);
      console.log(`✅ Password updated for "${username}".`);
      return;
    }

    // ── role ──────────────────────────────────────────────────────────────────
    if (cmd === 'role') {
      const [username, newRole] = args;
      if (!username || !newRole) fail('Usage: role <username> <role>');
      if (!VALID_ROLES.includes(newRole)) fail(`Role must be one of: ${VALID_ROLES.join(', ')}`);
      const user = db.prepare('SELECT id, role FROM users WHERE username = ? COLLATE NOCASE').get(username);
      if (!user) fail(`User "${username}" not found.`);
      if (user.role === 'superadmin' && newRole !== 'superadmin' && countSuperadmins(username) === 0) {
        fail(`Cannot demote "${username}": last superadmin.`);
      }
      if (['admin','superadmin'].includes(user.role) && !['admin','superadmin'].includes(newRole) && countAdmins(username) === 0) {
        fail(`Cannot demote "${username}": last admin-level user.`);
      }
      db.prepare('UPDATE users SET role = ? WHERE id = ?').run(newRole, user.id);
      console.log(`✅ "${username}" is now ${newRole}.`);
      return;
    }

    fail(`Unknown command: ${cmd}\nRun \`node manage-users.js help\` for usage.`);

  } catch (e) { fail(`Error: ${e.message}`); }
})();
