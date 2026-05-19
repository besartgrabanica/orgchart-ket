const Database = require('better-sqlite3');
const path     = require('path');
const db       = new Database(path.join(__dirname, 'orgchart.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS departments (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    color             TEXT NOT NULL DEFAULT '#2563eb',
    description       TEXT,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    head_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS standards (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT NOT NULL UNIQUE,
    full_name   TEXT NOT NULL,
    description TEXT,
    url         TEXT
  );

  CREATE TABLE IF NOT EXISTS standard_clauses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    standard_id  INTEGER NOT NULL REFERENCES standards(id) ON DELETE CASCADE,
    parent_id    INTEGER REFERENCES standard_clauses(id) ON DELETE CASCADE,
    clause_code  TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    sort_order   INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS department_clauses (
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    clause_id     INTEGER NOT NULL REFERENCES standard_clauses(id) ON DELETE CASCADE,
    compliance    TEXT NOT NULL DEFAULT 'applicable'
                  CHECK(compliance IN ('applicable','implemented','partial','not_applicable')),
    notes         TEXT,
    PRIMARY KEY (department_id, clause_id)
  );

  CREATE TABLE IF NOT EXISTS department_standard_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    standard_id   INTEGER NOT NULL REFERENCES standards(id)   ON DELETE CASCADE,
    clause_text   TEXT NOT NULL,
    comment       TEXT,
    sort_order    INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS department_standards (
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    standard_id   INTEGER NOT NULL REFERENCES standards(id)   ON DELETE CASCADE,
    scope         TEXT,
    PRIMARY KEY (department_id, standard_id)
  );

  CREATE TABLE IF NOT EXISTS positions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    title         TEXT NOT NULL,
    department_id INTEGER REFERENCES departments(id),
    project_id    INTEGER REFERENCES client_projects(id),
    description   TEXT,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS department_relations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    dept_a_id    INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    dept_b_id    INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    relation     TEXT,
    input_from_b TEXT,
    output_to_b  TEXT,
    UNIQUE(dept_a_id, dept_b_id)
  );

  CREATE TABLE IF NOT EXISTS locations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    country    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS department_locations (
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    location_id   INTEGER NOT NULL REFERENCES locations(id)   ON DELETE CASCADE,
    PRIMARY KEY (department_id, location_id)
  );

  CREATE TABLE IF NOT EXISTS employees (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name  TEXT NOT NULL,
    last_name   TEXT NOT NULL,
    position_id INTEGER REFERENCES positions(id),
    email       TEXT,
    phone       TEXT,
    location_id INTEGER REFERENCES locations(id),
    hire_date   TEXT,
    bio         TEXT,
    education   TEXT,
    experience  TEXT,
    is_virtual  INTEGER NOT NULL DEFAULT 0,
    manager_id  INTEGER REFERENCES employees(id),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS employee_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    label       TEXT,
    is_primary  INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS client_projects (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    client_company    TEXT,
    description       TEXT,
    color             TEXT NOT NULL DEFAULT '#0f766e',
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK(status IN ('active','onboarding','paused','ended')),
    start_date        TEXT,
    end_date          TEXT,
    languages         TEXT,
    client_contact    TEXT,
    notes             TEXT,
    head_employee_id  INTEGER REFERENCES employees(id) ON DELETE SET NULL,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS project_assignments (
    employee_id     INTEGER NOT NULL REFERENCES employees(id)        ON DELETE CASCADE,
    project_id      INTEGER NOT NULL REFERENCES client_projects(id)  ON DELETE CASCADE,
    role_on_project TEXT,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (employee_id, project_id)
  );

  CREATE TABLE IF NOT EXISTS project_standards (
    project_id  INTEGER NOT NULL REFERENCES client_projects(id) ON DELETE CASCADE,
    standard_id INTEGER NOT NULL REFERENCES standards(id)       ON DELETE CASCADE,
    scope       TEXT,
    PRIMARY KEY (project_id, standard_id)
  );

  -- ── Users ────────────────────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT NOT NULL,
    email      TEXT,
    role       TEXT NOT NULL DEFAULT 'viewer'
               CHECK(role IN ('viewer','editor','admin','developer','superadmin')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',
    created_by   INTEGER REFERENCES users(id),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at   DATETIME
  );

  -- ── Drop 2: invitations ───────────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS invitations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL
                CHECK(role IN ('viewer','editor','admin','developer','superadmin')),
    token_hash  TEXT NOT NULL UNIQUE,
    invited_by  INTEGER REFERENCES users(id),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME NOT NULL,
    accepted_at DATETIME,
    accepted_by INTEGER REFERENCES users(id),
    revoked_at  DATETIME
  );

  -- ── Drop 2: password resets ───────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used_at    DATETIME,
    request_ip TEXT
  );

  -- ── Drop 2: outbound webhooks ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS webhooks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT NOT NULL,
    url           TEXT NOT NULL,
    secret        TEXT NOT NULL,
    events        TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_by    INTEGER REFERENCES users(id),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_fired_at DATETIME,
    last_status   INTEGER,
    last_error    TEXT
  );

  -- ── Drop 2: app settings (sync mode etc.) ────────────────────────────────
  CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id)
  );

  -- ── Divisions (simplified: no sub-divisions, single optional head) ───────
  -- A division belongs to EITHER a project OR a department (not both).
  -- head_employee_id is the optional single head of the division.
  CREATE TABLE IF NOT EXISTS divisions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    project_id        INTEGER REFERENCES client_projects(id) ON DELETE CASCADE,
    department_id     INTEGER REFERENCES departments(id)     ON DELETE CASCADE,
    head_employee_id  INTEGER REFERENCES employees(id)       ON DELETE SET NULL,
    color             TEXT,
    description       TEXT,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- Exactly one of project_id or department_id must be set
    CHECK (
      (project_id    IS NOT NULL AND department_id IS NULL) OR
      (department_id IS NOT NULL AND project_id    IS NULL)
    )
  );

  -- An employee can belong to multiple divisions (membership is just a join row).
  CREATE TABLE IF NOT EXISTS division_employees (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    division_id       INTEGER NOT NULL REFERENCES divisions(id)  ON DELETE CASCADE,
    employee_id       INTEGER NOT NULL REFERENCES employees(id)  ON DELETE CASCADE,
    role_in_division  TEXT,
    is_head           INTEGER NOT NULL DEFAULT 0,
    is_primary        INTEGER NOT NULL DEFAULT 0,
    UNIQUE(division_id, employee_id)
  );

  -- ── Pessimistic record locks ───────────────────────────────────────────────
  -- Only one user at a time can edit a given entity (employee, department,
  -- project, or division). Locks auto-expire after 5 minutes unless the
  -- client sends a heartbeat to refresh locked_at.
  CREATE TABLE IF NOT EXISTS record_locks (
    entity_type   TEXT    NOT NULL,  -- 'employee','department','project','division'
    entity_id     INTEGER NOT NULL,
    locked_by     INTEGER NOT NULL REFERENCES users(id),
    locked_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_id)
  );
`);

// ── Migration: users.role CHECK → include all five roles ──────────────────────
(function migrateUsersRole() {
  const row = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='users'`).get();
  if (!row || !row.sql) return;
  if (row.sql.includes("'superadmin'")) return; // already migrated
  console.log('🔧 Migrating users.role CHECK to include developer + superadmin…');
  db.exec(`
    BEGIN;
    CREATE TABLE users_new (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT NOT NULL,
      email      TEXT,
      role       TEXT NOT NULL DEFAULT 'viewer'
                 CHECK(role IN ('viewer','editor','admin','developer','superadmin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO users_new (id, username, password, email, role, created_at)
      SELECT id, username, password, email, role, created_at FROM users;
    DROP TABLE users;
    ALTER TABLE users_new RENAME TO users;
    COMMIT;
  `);
  console.log('✅ users.role migrated.');
})();

// ── Migration: invitations.role CHECK → include all five roles ────────────────
(function migrateInvitationsRole() {
  const row = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='invitations'`).get();
  if (!row || !row.sql) return;
  if (row.sql.includes("'superadmin'")) return;
  console.log('🔧 Migrating invitations.role CHECK to include developer + superadmin…');
  db.exec(`
    BEGIN;
    CREATE TABLE invitations_new (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      email       TEXT NOT NULL,
      role        TEXT NOT NULL
                  CHECK(role IN ('viewer','editor','admin','developer','superadmin')),
      token_hash  TEXT NOT NULL UNIQUE,
      invited_by  INTEGER REFERENCES users(id),
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at  DATETIME NOT NULL,
      accepted_at DATETIME,
      accepted_by INTEGER REFERENCES users(id),
      revoked_at  DATETIME
    );
    INSERT INTO invitations_new SELECT * FROM invitations;
    DROP TABLE invitations;
    ALTER TABLE invitations_new RENAME TO invitations;
    COMMIT;
  `);
  console.log('✅ invitations.role migrated.');
})();

// ── Migration: add users.email if missing (Drop 2) ────────────────────────────
(function migrateUsersEmail() {
  const cols = db.prepare(`PRAGMA table_info(users)`).all();
  if (cols.some(c => c.name === 'email')) return;
  console.log('🔧 Adding users.email column…');
  db.exec(`ALTER TABLE users ADD COLUMN email TEXT`);
  console.log('✅ users.email added.');
})();

// ── Migration: add sort_order to departments if missing ───────────────────────
(function migrateDeptSortOrder() {
  const cols = db.prepare(`PRAGMA table_info(departments)`).all();
  if (cols.some(c => c.name === 'sort_order')) return;
  console.log('🔧 Adding departments.sort_order column…');
  db.exec(`ALTER TABLE departments ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`);
  console.log('✅ departments.sort_order added.');
})();

// ── Migration: add sort_order to positions if missing ────────────────────────
(function migratePosSortOrder() {
  const cols = db.prepare(`PRAGMA table_info(positions)`).all();
  if (cols.some(c => c.name === 'sort_order')) return;
  console.log('🔧 Adding positions.sort_order column…');
  db.exec(`ALTER TABLE positions ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`);
  console.log('✅ positions.sort_order added.');
})();

// ── Migration: add project_id to positions (positions can belong to a project) ─
(function migratePosProjectId() {
  const cols = db.prepare(`PRAGMA table_info(positions)`).all();
  if (cols.some(c => c.name === 'project_id')) return;
  console.log('🔧 Adding positions.project_id column…');
  db.exec(`ALTER TABLE positions ADD COLUMN project_id INTEGER REFERENCES client_projects(id)`);
  console.log('✅ positions.project_id added.');
})();

// ── Migration: add head_employee_id to departments ────────────────────────────
(function migrateDeptHead() {
  const cols = db.prepare(`PRAGMA table_info(departments)`).all();
  if (cols.some(c => c.name === 'head_employee_id')) return;
  console.log('🔧 Adding departments.head_employee_id column…');
  db.exec(`ALTER TABLE departments ADD COLUMN head_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL`);
  console.log('✅ departments.head_employee_id added.');
})();

// ── Migration: add head_employee_id to client_projects ────────────────────────
(function migrateProjectHead() {
  const cols = db.prepare(`PRAGMA table_info(client_projects)`).all();
  if (cols.some(c => c.name === 'head_employee_id')) return;
  console.log('🔧 Adding client_projects.head_employee_id column…');
  db.exec(`ALTER TABLE client_projects ADD COLUMN head_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL`);
  console.log('✅ client_projects.head_employee_id added.');
})();

// ── Migration: add head_employee_id to divisions ─────────────────────────────
(function migrateDivisionHead() {
  const cols = db.prepare(`PRAGMA table_info(divisions)`).all();
  if (cols.some(c => c.name === 'head_employee_id')) return;
  console.log('🔧 Adding divisions.head_employee_id column…');
  db.exec(`ALTER TABLE divisions ADD COLUMN head_employee_id INTEGER REFERENCES employees(id) ON DELETE SET NULL`);
  console.log('✅ divisions.head_employee_id added.');
})();

// ── Migration: copy legacy employees.email → employee_emails ─────────────────
(function migrateEmployeeEmails() {
  const hasAny = db.prepare(`SELECT COUNT(*) AS c FROM employee_emails`).get().c;
  if (hasAny > 0) return;
  const rows = db.prepare(`SELECT id, email FROM employees WHERE email IS NOT NULL AND email != ''`).all();
  if (rows.length === 0) return;
  const ins = db.prepare(`INSERT INTO employee_emails (employee_id, email, is_primary) VALUES (?, ?, 1)`);
  const tx = db.transaction(() => { rows.forEach(r => ins.run(r.id, r.email)); });
  tx();
  console.log(`✅ Migrated ${rows.length} legacy email${rows.length === 1 ? '' : 's'} into employee_emails.`);
})();

// ── Seed: default app settings ────────────────────────────────────────────────
(function seedAppSettings() {
  const has = db.prepare(`SELECT COUNT(*) AS c FROM app_settings WHERE key = 'sync_mode'`).get().c;
  if (has > 0) return;
  db.prepare(`INSERT INTO app_settings (key, value) VALUES ('sync_mode', 'off')`).run();
})();

// ── Seed: ensure Operations department always exists ─────────────────────────
// Operations is a structural pass-through node that client projects branch off.
// It is created on first boot so it is always available in relationship
// definitions, even before any client projects are added.
(function seedOperationsDept() {
  const has = db.prepare(`SELECT id FROM departments WHERE name = 'Operations' COLLATE NOCASE`).get();
  if (has) return;
  db.prepare(`INSERT INTO departments (name, color, description, sort_order) VALUES ('Operations', '#0f766e', 'Structural department that client projects branch off. Add employees here only if they belong directly to Operations rather than a specific project.', 999)`)
    .run();
  console.log('✅ Operations department seeded.');
})();

// ── Migration: division_employees — add role/head/primary columns ────────────
(function migrateDivisionEmployees() {
  const row = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='division_employees'`).get();
  if (!row || !row.sql) return;
  if (row.sql.includes('role_in_division')) return; // already migrated
  try {
    db.prepare(`ALTER TABLE division_employees ADD COLUMN role_in_division TEXT`).run();
    db.prepare(`ALTER TABLE division_employees ADD COLUMN is_head INTEGER NOT NULL DEFAULT 0`).run();
    db.prepare(`ALTER TABLE division_employees ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0`).run();
    console.log('✅ Migrated division_employees: added role_in_division, is_head, is_primary.');
  } catch(e) { /* columns may already exist */ }
})();

// ── Migration: employees — add education and experience columns ──────────────
(function migrateEmployeesEduExp() {
  const row = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='employees'`).get();
  if (!row || !row.sql) return;
  if (row.sql.includes('education')) return;
  try {
    db.prepare(`ALTER TABLE employees ADD COLUMN education TEXT`).run();
    db.prepare(`ALTER TABLE employees ADD COLUMN experience TEXT`).run();
    console.log('✅ Migrated employees: added education, experience.');
  } catch(e) { /* columns may already exist */ }
})();

// ── Migration: standards — add description column ────────────────────────────
(function migrateStandardsDesc() {
  const row = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='standards'`).get();
  if (!row || !row.sql) return;
  if (row.sql.includes('description')) return;
  try {
    db.prepare(`ALTER TABLE standards ADD COLUMN description TEXT`).run();
    console.log('✅ Migrated standards: added description.');
  } catch(e) {}
})();

// To create your first superadmin account run:
//   node manage-users.js add <username> <password> superadmin
module.exports = db;
