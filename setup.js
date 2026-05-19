#!/usr/bin/env node
// setup.js — One-command bootstrap for KiKxxl-evroTarget OrgChart.
//
// Usage:
//   node setup.js
//
// What it does:
//   1. Runs `npm install` to install all dependencies
//   2. Creates the superadmin user (besart / besart)
//   3. Imports employees and org data from data.json
//
// Safe to re-run: npm install is idempotent, manage-users.js checks for
// existing users, and import-employees.js is idempotent by design.

const { execSync } = require('child_process');
const path = require('path');

const cwd = __dirname;

function run(cmd, label) {
  console.log(`\n━━━ ${label} ━━━`);
  try {
    execSync(cmd, { cwd, stdio: 'inherit' });
  } catch (e) {
    // Don't abort on non-zero exit — manage-users.js exits 1 if user exists
    console.warn(`  ⚠  "${label}" exited with code ${e.status || '?'} (may be OK if already done)`);
  }
}

console.log('\n🚀  KiKxxl-evroTarget OrgChart — Setup\n');

run('npm install', 'Installing dependencies');
run('node manage-users.js add besart besart superadmin besart.grabanica@gmail.com', 'Creating superadmin user');
run('node import-employees.js data.json', 'Importing org data from data.json');

console.log(`
✅  Setup complete!

  Start the server:   npm start
  Then open:           http://localhost:3000

  Login:  besart / besart
  Role:   superadmin

  Admin panel:  http://localhost:3000/admin.html
`);
