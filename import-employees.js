#!/usr/bin/env node
// import-employees.js — bulk-import org data from a JSON file.
//
// Usage:
//   node import-employees.js path/to/data.json
//   node import-employees.js path/to/data.json --enable-sync
//   node import-employees.js path/to/data.json --dry-run
//
// Idempotent: running twice does not duplicate. Lookups are by name (case-
// insensitive) for departments, positions, locations, projects; for employees
// the natural key is first_name + last_name + first email.
//
// JSON shape (all fields optional except as noted):
// {
//   "departments": [
//     {"name":"HR","color":"#ec4899","description":"…"},
//     ...
//   ],
//   "positions": [
//     {"title":"HR Manager","department":"HR","description":"…"},
//     ...
//   ],
//   "locations": [
//     {"name":"Pristina","country":"Kosovo"},
//     ...
//   ],
//   "client_projects": [
//     {"name":"Freenet","client_company":"Freenet GmbH","status":"active",
//      "color":"#0f766e","languages":"DE","description":"…"},
//     ...
//   ],
//   "employees": [
//     {
//       "first_name":"Alice","last_name":"Hoxha",                        // required
//       "position":"HR Manager",       // looked up by title
//       "manager":"Bob Krasniqi",      // looked up by "First Last", optional
//       "location":"Pristina",         // looked up by name
//       "phone":"+383 ...",
//       "hire_date":"2023-04-01",
//       "bio":"…",
//       "emails":[
//         {"email":"alice@kikxxl-evrotarget.com","is_primary":true,"label":"work"},
//         {"email":"alice@evrotarget.com"}
//       ],
//       "projects":[
//         {"project":"Freenet","role_on_project":"Team Leader","is_primary":true},
//         {"project":"E.ON",   "role_on_project":"Quality Lead"}
//       ]
//     },
//     ...
//   ]
// }

const fs   = require('fs');
const path = require('path');
const db   = require('./database');

const args = process.argv.slice(2);
const filePath = args.find(a => !a.startsWith('--'));
const dryRun     = args.includes('--dry-run');
const enableSync = args.includes('--enable-sync');

if (!filePath) {
  console.error('Usage: node import-employees.js <data.json> [--dry-run] [--enable-sync]');
  process.exit(1);
}
if (!fs.existsSync(filePath)) {
  console.error(`File not found: ${filePath}`);
  process.exit(1);
}

let data;
try {
  data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
} catch (e) {
  console.error('Failed to parse JSON:', e.message);
  process.exit(1);
}

const stats = {
  departments: { created: 0, found: 0 },
  positions:   { created: 0, found: 0 },
  locations:   { created: 0, found: 0 },
  projects:    { created: 0, found: 0 },
  employees:   { created: 0, updated: 0 },
  emails:      { created: 0 },
  assignments: { created: 0 },
  divisions:   { created: 0, found: 0 },
  warnings:    [],
};

function warn(msg) { stats.warnings.push(msg); }

function findOrCreateDept(d) {
  if (!d || !d.name) return null;
  const existing = db.prepare(`SELECT * FROM departments WHERE name = ? COLLATE NOCASE`).get(d.name.trim());
  if (existing) { stats.departments.found++; return existing.id; }
  if (dryRun) { stats.departments.created++; return -1; }
  const r = db.prepare(`INSERT INTO departments (name, color, description) VALUES (?, ?, ?)`)
    .run(d.name.trim(), d.color || '#2563eb', d.description || null);
  stats.departments.created++;
  return r.lastInsertRowid;
}

function findOrCreatePosition(p) {
  if (!p || !p.title) return null;
  // Resolve parent (department XOR project) first
  let deptId = null, projectId = null;
  if (p.department) {
    const dr = db.prepare(`SELECT id FROM departments WHERE name = ? COLLATE NOCASE`).get(p.department.trim());
    if (!dr) warn(`Position "${p.title}" references unknown department "${p.department}"`);
    else deptId = dr.id;
  }
  if (p.project) {
    const pr = db.prepare(`SELECT id FROM client_projects WHERE name = ? COLLATE NOCASE`).get(p.project.trim());
    if (!pr) warn(`Position "${p.title}" references unknown project "${p.project}"`);
    else projectId = pr.id;
  }
  if (deptId && projectId) {
    warn(`Position "${p.title}" specifies both department and project — using project only`);
    deptId = null;
  }
  // Match on (title, parent) so the same title can exist under different parents
  const existing = db.prepare(`SELECT * FROM positions WHERE title = ? COLLATE NOCASE AND IFNULL(department_id,0) = IFNULL(?,0) AND IFNULL(project_id,0) = IFNULL(?,0)`).get(p.title.trim(), deptId, projectId);
  if (existing) {
    stats.positions.found++;
    // Update description if it was empty and data provides one
    if (!existing.description && p.description && !dryRun) {
      db.prepare('UPDATE positions SET description = ? WHERE id = ?').run(p.description.trim(), existing.id);
    }
    return existing.id;
  }
  if (dryRun) { stats.positions.created++; return -1; }
  const r = db.prepare(`INSERT INTO positions (title, department_id, project_id, description) VALUES (?, ?, ?, ?)`)
    .run(p.title.trim(), deptId, projectId, p.description || null);
  stats.positions.created++;
  return r.lastInsertRowid;
}

function findOrCreateLocation(l) {
  if (!l || !l.name) return null;
  const existing = db.prepare(`SELECT * FROM locations WHERE name = ? COLLATE NOCASE`).get(l.name.trim());
  if (existing) { stats.locations.found++; return existing.id; }
  if (dryRun) { stats.locations.created++; return -1; }
  const r = db.prepare(`INSERT INTO locations (name, country) VALUES (?, ?)`)
    .run(l.name.trim(), l.country || null);
  stats.locations.created++;
  return r.lastInsertRowid;
}

function findOrCreateProject(p) {
  if (!p || !p.name) return null;
  const existing = db.prepare(`SELECT * FROM client_projects WHERE name = ? COLLATE NOCASE`).get(p.name.trim());
  if (existing) { stats.projects.found++; return existing.id; }
  if (dryRun) { stats.projects.created++; return -1; }
  const r = db.prepare(`INSERT INTO client_projects (name, client_company, description, color, status, start_date, end_date, languages, client_contact, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      p.name.trim(),
      p.client_company || null,
      p.description || null,
      p.color || '#0f766e',
      ['active','onboarding','paused','ended'].includes(p.status) ? p.status : 'active',
      p.start_date || null,
      p.end_date || null,
      p.languages || null,
      p.client_contact || null,
      p.notes || null
    );
  stats.projects.created++;
  return r.lastInsertRowid;
}

function lookupEmployee(firstName, lastName, primaryEmail) {
  // Try by primary email first (most reliable)
  if (primaryEmail) {
    const r = db.prepare(`SELECT e.* FROM employees e JOIN employee_emails em ON em.employee_id = e.id WHERE em.email = ? COLLATE NOCASE LIMIT 1`).get(primaryEmail);
    if (r) return r;
  }
  // Fall back to first+last name
  return db.prepare(`SELECT * FROM employees WHERE first_name = ? COLLATE NOCASE AND last_name = ? COLLATE NOCASE LIMIT 1`).get(firstName, lastName);
}

function upsertEmployee(emp, managerIdLookup) {
  if (!emp.first_name || !emp.last_name) {
    warn(`Skipping employee with missing name: ${JSON.stringify(emp).slice(0,80)}…`);
    return null;
  }
  let positionId = null;
  if (emp.position) {
    const pr = db.prepare(`SELECT id FROM positions WHERE title = ? COLLATE NOCASE`).get(emp.position.trim());
    if (!pr) warn(`Employee "${emp.first_name} ${emp.last_name}" references unknown position "${emp.position}"`);
    else positionId = pr.id;
  }
  let locationId = null;
  if (emp.location) {
    const lr = db.prepare(`SELECT id FROM locations WHERE name = ? COLLATE NOCASE`).get(emp.location.trim());
    if (!lr) warn(`Employee "${emp.first_name} ${emp.last_name}" references unknown location "${emp.location}"`);
    else locationId = lr.id;
  }
  // Manager is resolved in a 2nd pass after all employees exist
  const managerId = null;

  const emails = Array.isArray(emp.emails) ? emp.emails.filter(e => e.email && e.email.trim()) : [];
  if (emails.length > 0 && !emails.some(e => e.is_primary)) emails[0].is_primary = true;
  const primaryEmail = (emails.find(e => e.is_primary) || emails[0] || {}).email || null;

  const existing = lookupEmployee(emp.first_name.trim(), emp.last_name.trim(), primaryEmail);
  if (existing) {
    if (dryRun) { stats.employees.updated++; return existing.id; }
    db.prepare(`UPDATE employees SET first_name=?, last_name=?, position_id=?, email=?, phone=?, location_id=?, hire_date=?, bio=?, education=COALESCE(?,education), experience=COALESCE(?,experience), manager_id=? WHERE id=?`)
      .run(
        emp.first_name.trim(), emp.last_name.trim(),
        positionId, primaryEmail, emp.phone || null,
        locationId, emp.hire_date || null, emp.bio || null,
        emp.education || null, emp.experience || null,
        managerId, existing.id
      );
    // Replace emails
    db.prepare(`DELETE FROM employee_emails WHERE employee_id = ?`).run(existing.id);
    const insE = db.prepare(`INSERT INTO employee_emails (employee_id, email, label, is_primary) VALUES (?, ?, ?, ?)`);
    emails.forEach(e => { insE.run(existing.id, e.email.trim(), e.label || null, e.is_primary ? 1 : 0); stats.emails.created++; });
    stats.employees.updated++;
    return existing.id;
  }
  if (dryRun) { stats.employees.created++; return -1; }
  const r = db.prepare(`INSERT INTO employees (first_name, last_name, position_id, email, phone, location_id, hire_date, bio, education, experience, manager_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      emp.first_name.trim(), emp.last_name.trim(),
      positionId, primaryEmail, emp.phone || null,
      locationId, emp.hire_date || null, emp.bio || null,
      emp.education || null, emp.experience || null,
      managerId
    );
  const empId = r.lastInsertRowid;
  const insE = db.prepare(`INSERT INTO employee_emails (employee_id, email, label, is_primary) VALUES (?, ?, ?, ?)`);
  emails.forEach(e => { insE.run(empId, e.email.trim(), e.label || null, e.is_primary ? 1 : 0); stats.emails.created++; });
  stats.employees.created++;
  return empId;
}

function resolveManagers(empArray, idMap) {
  // Second pass: now that all employees exist, set manager_id
  empArray.forEach(emp => {
    if (!emp.manager) return;
    const empId = idMap[`${emp.first_name.trim().toLowerCase()}|${emp.last_name.trim().toLowerCase()}`];
    if (!empId || empId < 0) return;
    const parts = emp.manager.trim().split(/\s+/);
    if (parts.length < 2) { warn(`Employee "${emp.first_name} ${emp.last_name}": manager must be "First Last", got "${emp.manager}"`); return; }
    const mFirst = parts[0], mLast = parts.slice(1).join(' ');
    const mr = db.prepare(`SELECT id FROM employees WHERE first_name = ? COLLATE NOCASE AND last_name = ? COLLATE NOCASE LIMIT 1`).get(mFirst, mLast);
    if (!mr) { warn(`Employee "${emp.first_name} ${emp.last_name}" references unknown manager "${emp.manager}"`); return; }
    if (mr.id === empId) { warn(`Employee "${emp.first_name} ${emp.last_name}" cannot be their own manager`); return; }
    if (!dryRun) db.prepare(`UPDATE employees SET manager_id = ? WHERE id = ?`).run(mr.id, empId);
  });
}

function resolveAssignments(empArray, idMap) {
  empArray.forEach(emp => {
    if (!Array.isArray(emp.projects) || emp.projects.length === 0) return;
    const empId = idMap[`${emp.first_name.trim().toLowerCase()}|${emp.last_name.trim().toLowerCase()}`];
    if (!empId || empId < 0) return;
    let primaryAssigned = false;
    emp.projects.forEach((pa, idx) => {
      if (!pa.project) return;
      const pr = db.prepare(`SELECT id FROM client_projects WHERE name = ? COLLATE NOCASE`).get(pa.project.trim());
      if (!pr) { warn(`Employee "${emp.first_name} ${emp.last_name}" references unknown project "${pa.project}"`); return; }
      let isPri = !!pa.is_primary;
      if (isPri && primaryAssigned) isPri = false; // only one primary
      if (isPri) primaryAssigned = true;
      if (!dryRun) {
        db.prepare(`INSERT OR REPLACE INTO project_assignments (employee_id, project_id, role_on_project, is_primary) VALUES (?, ?, ?, ?)`)
          .run(empId, pr.id, pa.role_on_project || null, isPri ? 1 : 0);
      }
      stats.assignments.created++;
    });
    // If user supplied projects but never marked one primary, mark the first
    if (!primaryAssigned && emp.projects.length > 0 && !dryRun) {
      const firstProj = emp.projects.find(x => x.project);
      if (firstProj) {
        const pr = db.prepare(`SELECT id FROM client_projects WHERE name = ? COLLATE NOCASE`).get(firstProj.project.trim());
        if (pr) db.prepare(`UPDATE project_assignments SET is_primary = 1 WHERE employee_id = ? AND project_id = ?`).run(empId, pr.id);
      }
    }
  });
}

console.log(`📥 ${dryRun ? 'DRY-RUN: ' : ''}Importing from ${path.resolve(filePath)}\n`);

(data.departments     || []).forEach(findOrCreateDept);
(data.locations       || []).forEach(findOrCreateLocation);
(data.client_projects || []).forEach(findOrCreateProject);
(data.positions       || []).forEach(findOrCreatePosition); // after projects, since positions can reference a project

const idMap = {};
(data.employees || []).forEach(emp => {
  const id = upsertEmployee(emp);
  if (id) idMap[`${emp.first_name.trim().toLowerCase()}|${emp.last_name.trim().toLowerCase()}`] = id;
});
resolveManagers(data.employees || [], idMap);
resolveAssignments(data.employees || [], idMap);

// Resolve heads: dept.head and project.head reference an employee by name
function lookupEmpId(name) {
  if (!name) return null;
  const key = name.trim().toLowerCase();
  // Try idMap first (employees we just imported); fall back to DB
  const parts = key.split(/\s+/);
  const fk = `${parts[0]||''}|${parts.slice(1).join(' ')}`;
  if (idMap[fk]) return idMap[fk];
  const r = db.prepare(`SELECT id FROM employees WHERE LOWER(first_name || ' ' || last_name) = ?`).get(key);
  return r ? r.id : null;
}

(data.departments || []).forEach(d => {
  if (!d.head) return;
  const eid = lookupEmpId(d.head);
  if (!eid) { warn(`Department "${d.name}" head "${d.head}" not found`); return; }
  if (!dryRun) db.prepare(`UPDATE departments SET head_employee_id=? WHERE name=? COLLATE NOCASE`).run(eid, d.name);
});

(data.client_projects || []).forEach(p => {
  if (!p.head) return;
  const eid = lookupEmpId(p.head);
  if (!eid) { warn(`Project "${p.name}" head "${p.head}" not found`); return; }
  if (!dryRun) db.prepare(`UPDATE client_projects SET head_employee_id=? WHERE name=? COLLATE NOCASE`).run(eid, p.name);
});

// Divisions: top-level data.divisions list
(data.divisions || []).forEach(div => {
  let projectId = null, deptId = null;
  if (div.project) {
    const r = db.prepare(`SELECT id FROM client_projects WHERE name=? COLLATE NOCASE`).get(div.project.trim());
    if (!r) { warn(`Division "${div.name}" references unknown project "${div.project}"`); return; }
    projectId = r.id;
  } else if (div.department) {
    const r = db.prepare(`SELECT id FROM departments WHERE name=? COLLATE NOCASE`).get(div.department.trim());
    if (!r) { warn(`Division "${div.name}" references unknown department "${div.department}"`); return; }
    deptId = r.id;
  } else {
    warn(`Division "${div.name}" must specify either "project" or "department"`); return;
  }
  let headId = null;
  if (div.head) {
    headId = lookupEmpId(div.head);
    if (!headId) warn(`Division "${div.name}" head "${div.head}" not found`);
  }
  if (dryRun) { stats.divisions = stats.divisions || {created:0,found:0}; stats.divisions.created++; return; }
  // Upsert by (name + parent)
  const existing = db.prepare(`SELECT id FROM divisions WHERE name=? COLLATE NOCASE AND IFNULL(project_id,0)=IFNULL(?,0) AND IFNULL(department_id,0)=IFNULL(?,0)`).get(div.name.trim(), projectId, deptId);
  let divId;
  if (existing) {
    db.prepare(`UPDATE divisions SET head_employee_id=?, color=?, description=? WHERE id=?`).run(headId, div.color||null, div.description||null, existing.id);
    divId = existing.id;
    stats.divisions = stats.divisions || {created:0,found:0}; stats.divisions.found++;
  } else {
    const r = db.prepare(`INSERT INTO divisions (name, project_id, department_id, head_employee_id, color, description) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(div.name.trim(), projectId, deptId, headId, div.color||null, div.description||null);
    divId = r.lastInsertRowid;
    stats.divisions = stats.divisions || {created:0,found:0}; stats.divisions.created++;
  }
});

// Per-employee division memberships: emp.divisions = ["German Team", ...]
(data.employees || []).forEach(emp => {
  if (!emp.divisions || !Array.isArray(emp.divisions)) return;
  const empId = idMap[`${emp.first_name.trim().toLowerCase()}|${emp.last_name.trim().toLowerCase()}`];
  if (!empId) return;
  emp.divisions.forEach(divName => {
    // Match by name; if there are multiple divisions with the same name across parents, ambiguous → warn
    const matches = db.prepare(`SELECT id FROM divisions WHERE name=? COLLATE NOCASE`).all(divName.trim());
    if (matches.length === 0) { warn(`Employee ${emp.first_name} ${emp.last_name} references unknown division "${divName}"`); return; }
    if (matches.length > 1) { warn(`Employee ${emp.first_name} ${emp.last_name} division "${divName}" is ambiguous (${matches.length} matches)`); return; }
    if (!dryRun) db.prepare(`INSERT OR IGNORE INTO division_employees (division_id, employee_id) VALUES (?, ?)`).run(matches[0].id, empId);
  });
});

// ── Standards ────────────────────────────────────────────────────────────────
stats.standards = { created: 0, found: 0 };
stats.deptStandards = { created: 0 };
stats.relations = { created: 0 };

(data.standards || []).forEach(s => {
  if (!s.code || !s.full_name) return;
  const existing = db.prepare('SELECT id FROM standards WHERE code = ? COLLATE NOCASE').get(s.code.trim());
  if (existing) {
    stats.standards.found++;
    if (s.description && !dryRun) db.prepare('UPDATE standards SET description = COALESCE(?, description), full_name = ? WHERE id = ?').run(s.description || null, s.full_name.trim(), existing.id);
    return;
  }
  if (dryRun) { stats.standards.created++; return; }
  db.prepare('INSERT INTO standards (code, full_name, description, url) VALUES (?, ?, ?, ?)').run(s.code.trim(), s.full_name.trim(), s.description || null, s.url || null);
  stats.standards.created++;
});

// Map standards to departments
(data.department_standards || []).forEach(ds => {
  if (!ds.department || !ds.standard) return;
  const dept = db.prepare('SELECT id FROM departments WHERE name = ? COLLATE NOCASE').get(ds.department.trim());
  const std = db.prepare('SELECT id FROM standards WHERE code = ? COLLATE NOCASE').get(ds.standard.trim());
  if (!dept || !std) { warn(`dept-standard mapping: ${ds.department} / ${ds.standard} — not found`); return; }
  if (dryRun) { stats.deptStandards.created++; return; }
  db.prepare('INSERT INTO department_standards (department_id, standard_id, scope) VALUES (?, ?, ?) ON CONFLICT(department_id, standard_id) DO UPDATE SET scope=COALESCE(excluded.scope, scope)').run(dept.id, std.id, ds.scope || null);
  stats.deptStandards.created++;
});

// Department relations
(data.department_relations || []).forEach(rel => {
  if (!rel.dept_a || !rel.dept_b) return;
  const a = db.prepare('SELECT id FROM departments WHERE name = ? COLLATE NOCASE').get(rel.dept_a.trim());
  const b = db.prepare('SELECT id FROM departments WHERE name = ? COLLATE NOCASE').get(rel.dept_b.trim());
  if (!a || !b) { warn(`relation: ${rel.dept_a} ↔ ${rel.dept_b} — department not found`); return; }
  if (dryRun) { stats.relations.created++; return; }
  // Check if already exists
  const existing = db.prepare('SELECT id FROM department_relations WHERE (dept_a_id=? AND dept_b_id=?) OR (dept_a_id=? AND dept_b_id=?)').get(a.id, b.id, b.id, a.id);
  if (existing) return;
  db.prepare('INSERT INTO department_relations (dept_a_id, dept_b_id, relation, input_from_b, output_to_b) VALUES (?, ?, ?, ?, ?)').run(a.id, b.id, rel.relation || null, rel.input_from_b || null, rel.output_to_b || null);
  stats.relations.created++;
});

if (enableSync && !dryRun) {
  db.prepare(`INSERT INTO app_settings (key, value, updated_at) VALUES ('sync_mode', 'on', CURRENT_TIMESTAMP)
              ON CONFLICT(key) DO UPDATE SET value='on', updated_at=CURRENT_TIMESTAMP`).run();
  console.log('🔒 Sync mode ENABLED. Manual edits via the admin UI are now blocked. Disable in Admin → Settings.\n');
}

console.log('✅ Import complete.\n');
console.log(`  Departments:     ${stats.departments.created} created, ${stats.departments.found} matched existing`);
console.log(`  Positions:       ${stats.positions.created} created, ${stats.positions.found} matched`);
console.log(`  Locations:       ${stats.locations.created} created, ${stats.locations.found} matched`);
console.log(`  Client projects: ${stats.projects.created} created, ${stats.projects.found} matched`);
console.log(`  Employees:       ${stats.employees.created} created, ${stats.employees.updated} updated`);
console.log(`  Emails:          ${stats.emails.created} created`);
console.log(`  Assignments:     ${stats.assignments.created} created`);
console.log(`  Divisions:       ${stats.divisions.created} created, ${stats.divisions.found} matched`);
console.log(`  Standards:       ${stats.standards.created} created, ${stats.standards.found} matched`);
console.log(`  Dept standards:  ${stats.deptStandards.created} mapped`);
console.log(`  Relations:       ${stats.relations.created} created`);
if (stats.warnings.length > 0) {
  console.log(`\n  ⚠️  ${stats.warnings.length} warning${stats.warnings.length===1?'':'s'}:`);
  stats.warnings.forEach(w => console.log('     - ' + w));
}
if (dryRun) console.log('\n  (dry run — no changes were saved)');
console.log('');
