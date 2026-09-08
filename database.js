import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DB_PATH || path.join(__dirname, 'mesai.db');
export const rawDb = new DatabaseSync(dbPath);

export const db = {
  prepare(sql) {
    const stmt = rawDb.prepare(sql);
    return {
      run(...params) {
        return stmt.run(...params);
      },
      get(...params) {
        return stmt.get(...params);
      },
      all(...params) {
        return stmt.all(...params);
      }
    };
  },
  exec(sql) {
    return rawDb.exec(sql);
  }
};

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, key] = storedHash.split(':');
  const keyBuffer = Buffer.from(key, 'hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_no TEXT UNIQUE NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'employee',
      department TEXT DEFAULT 'Yüklenici',
      is_active INTEGER DEFAULT 1,
      auth_method TEXT DEFAULT 'webauthn',
      pin_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      credential_id TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      counter INTEGER DEFAULT 0,
      transports TEXT,
      device_name TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS attendances (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      work_date TEXT NOT NULL,
      check_in_time DATETIME,
      check_in_verified INTEGER DEFAULT 0,
      check_in_accuracy REAL,
      check_in_distance REAL,
      check_out_time DATETIME,
      check_out_verified INTEGER DEFAULT 0,
      check_out_accuracy REAL,
      check_out_distance REAL,
      status TEXT DEFAULT 'normal',
      verification_mode TEXT DEFAULT 'webauthn_gps',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, work_date),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id INTEGER NOT NULL,
      target_user_id INTEGER NOT NULL,
      attendance_id INTEGER,
      action TEXT NOT NULL,
      old_value TEXT,
      new_value TEXT,
      reason TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS security_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      event_type TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const defaultSettings = [
    ['center_lat', '41.025544'],
    ['center_lon', '28.889816'],
    ['geofence_radius', '150'],
    ['work_start_time', '08:00'],
    ['work_end_time', '17:00'],
    ['late_tolerance_minutes', '10'],
    ['max_gps_accuracy', '60']
  ];

  const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  defaultSettings.forEach(([k, v]) => insertSetting.run(k, v));

  const checkAdmin = db.prepare('SELECT id FROM users WHERE employee_no = ?').get('admin');
  if (!checkAdmin) {
    const defaultAdminHash = hashPassword('Admin123!');
    db.prepare(`
      INSERT INTO users (employee_no, first_name, last_name, password_hash, role, department)
      VALUES (?, ?, ?, ?, 'admin', 'Yönetim')
    `).run('admin', 'Sistem', 'Yöneticisi', defaultAdminHash);
    console.log('[BILGI] Varsayılan yönetici hesabı oluşturuldu: admin / Admin123!');
  }
}
// database.js içine:
db.exec(`
  CREATE TABLE IF NOT EXISTS leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    leave_type TEXT NOT NULL,       -- 'Yillik', 'Rapor', 'Idari', 'Ucretsiz'
    start_date TEXT NOT NULL,       -- '2026-09-07'
    end_date TEXT NOT NULL,         -- '2026-09-10'
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);