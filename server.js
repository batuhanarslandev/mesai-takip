import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

import { db, initDatabase, verifyPassword, hashPassword } from './database.js';
import { calculateHaversineDistance, evaluateShiftStatus } from './geofence.js';
import { createSession, getSession, destroySession, logSecurityEvent } from './auth.js';

dotenv.config();
initDatabase();

// credentials tablosunda device_fingerprint sütunu yoksa dinamik olarak ekle
try {
  db.exec('ALTER TABLE credentials ADD COLUMN device_fingerprint TEXT;');
} catch (_) {
  // Sütun zaten mevcutsa hatayı yut
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = Fastify({ 
  logger: true,
  trustProxy: true // Bulut proxy arkasındaki IP ve domain'i doğru yakalar
});

const RP_NAME = process.env.RP_NAME || 'Kurum Mesai Portali';
const PORT = process.env.PORT || 3000;

app.register(fastifyCookie, { secret: process.env.COOKIE_SECRET || 'gizli-kamu-mesai-anahtari-12345' });
app.register(fastifyStatic, {
  root: path.join(__dirname, 'public'),
  prefix: '/'
});

// Dinamik Domain & Origin Çözücü
function getWebAuthnConfig(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
  const cleanHost = host.split(':')[0];
  const proto = req.headers['x-forwarded-proto'] || (req.protocol || 'http');
  const origin = `${proto}://${host}`;

  return {
    rpID: cleanHost,
    expectedOrigin: origin
  };
}

const webauthnChallenges = new Map();

function authGuard(req, reply, allowedRoles = ['employee', 'admin']) {
  const sessionId = req.cookies.session_id;
  const session = getSession(sessionId);
  if (!session || !allowedRoles.includes(session.role)) {
    reply.status(401).send({ error: 'Yetkisiz erişim. Oturum açmalısınız.' });
    return null;
  }
  return session;
}

// ----------------------------------------------------
// KULLANICI / ADMİN GİRİŞİ & OTURUM
// ----------------------------------------------------
app.post('/api/auth/login', async (req, reply) => {
  const { employee_no, password } = req.body;
  const ip = req.ip;
  const ua = req.headers['user-agent'];

  const user = db.prepare('SELECT * FROM users WHERE employee_no = ? AND is_active = 1').get(employee_no);
  if (!user || !verifyPassword(password, user.password_hash)) {
    logSecurityEvent(user ? user.id : null, 'auth_failed', ip, ua, { employee_no });
    return reply.status(400).send({ error: 'Personel numarası veya şifre hatalı.' });
  }

  const sessionId = createSession(user.id, user.role);
  reply.setCookie('session_id', sessionId, {
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' || req.protocol === 'https',
    sameSite: 'lax',
    maxAge: 43200
  });

  const credential = db.prepare('SELECT id FROM credentials WHERE user_id = ? AND is_active = 1').get(user.id);

  return {
    success: true,
    user: {
      id: user.id,
      employee_no: user.employee_no,
      first_name: user.first_name,
      last_name: user.last_name,
      role: user.role,
      has_device: !!credential
    }
  };
});

app.post('/api/auth/logout', async (req, reply) => {
  const sessionId = req.cookies.session_id;
  if (sessionId) destroySession(sessionId);
  reply.clearCookie('session_id', { path: '/' });
  return { success: true };
});

app.get('/api/auth/me', async (req, reply) => {
  const session = authGuard(req, reply);
  if (!session) return;

  const user = db.prepare('SELECT id, employee_no, first_name, last_name, role, auth_method FROM users WHERE id = ?').get(session.userId);
  const credential = db.prepare('SELECT id FROM credentials WHERE user_id = ? AND is_active = 1').get(user.id);

  const today = new Date().toISOString().slice(0, 10);
  const attendance = db.prepare('SELECT * FROM attendances WHERE user_id = ? AND work_date = ?').get(user.id, today);

  return {
    user: { ...user, has_device: !!credential },
    today_attendance: attendance || null
  };
});

// ----------------------------------------------------
// WEBAUTHN / CİHAZ EŞLEŞTİRME (DONANIM KİLİDİ DAHİL)
// ----------------------------------------------------
app.get('/api/webauthn/register-options', async (req, reply) => {
  try {
    const session = authGuard(req, reply);
    if (!session) return;

    const existingDevice = db.prepare('SELECT id FROM credentials WHERE user_id = ? AND is_active = 1').get(session.userId);
    if (existingDevice) {
      return reply.status(400).send({ error: 'Zaten eşleştirilmiş bir cihazınız bulunmaktadır.' });
    }

    const user = db.prepare('SELECT id, employee_no, first_name, last_name FROM users WHERE id = ?').get(session.userId);
    const { rpID } = getWebAuthnConfig(req);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpID,
      userID: new TextEncoder().encode(String(user.id)),
      userName: user.employee_no,
      userDisplayName: `${user.first_name} ${user.last_name}`,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred'
      }
    });

    webauthnChallenges.set(user.id, options.challenge);
    return options;
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Kayıt seçenekleri oluşturulamadı: ${err.message}` });
  }
});

app.post('/api/webauthn/register-verify', async (req, reply) => {
  try {
    const session = authGuard(req, reply);
    if (!session) return;

    const { device_fingerprint, ...attestationResponse } = req.body;
    const ip = req.ip;
    const ua = req.headers['user-agent'];

    if (!device_fingerprint) {
      return reply.status(400).send({ error: 'Cihaz donanım kimliği doğrulanamadı.' });
    }

    // 1. KRİTİK KONTROL: Bu fiziksel cihaz başka bir personele zaten zimmetli mi?
    const existingBinding = db.prepare(`
      SELECT c.id, u.employee_no, u.first_name, u.last_name 
      FROM credentials c
      JOIN users u ON c.user_id = u.id
      WHERE c.device_fingerprint = ? AND c.user_id != ? AND c.is_active = 1
    `).get(device_fingerprint, session.userId);

    if (existingBinding) {
      logSecurityEvent(session.userId, 'device_sharing_attempt', ip, ua, {
        registered_to: existingBinding.employee_no,
        registered_name: `${existingBinding.first_name} ${existingBinding.last_name}`,
        fingerprint: device_fingerprint
      });
      return reply.status(403).send({ 
        error: `GÜVENLİK İHLALİ: Bu telefon zaten [${existingBinding.employee_no} - ${existingBinding.first_name} ${existingBinding.last_name}] personeline zimmetlidir. Başka personel adına eşleştirilemez!` 
      });
    }

    const expectedChallenge = webauthnChallenges.get(session.userId);
    webauthnChallenges.delete(session.userId);

    const { rpID, expectedOrigin } = getWebAuthnConfig(req);

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpID
    });

    if (!verification.verified || !verification.registrationInfo) {
      return reply.status(400).send({ error: 'Cihaz doğrulaması başarısız oldu.' });
    }

    const info = verification.registrationInfo;
    const credentialID = info.credential?.id || info.credentialID;
    const credentialPublicKey = info.credential?.publicKey || info.credentialPublicKey;
    const counter = info.credential?.counter ?? info.counter ?? 0;

    const credIdBase64 = typeof credentialID === 'string' 
      ? credentialID 
      : Buffer.from(credentialID).toString('base64url');

    const pubKeyBase64 = typeof credentialPublicKey === 'string'
      ? credentialPublicKey
      : Buffer.from(credentialPublicKey).toString('base64url');

    const clientTransports = attestationResponse.response?.transports || [];
    const finalTransports = clientTransports.length > 0 ? clientTransports : ['internal'];

    // Donanım parmak izi ile birlikte kaydet
    db.prepare(`
      INSERT INTO credentials (user_id, credential_id, public_key, counter, transports, device_name, device_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      session.userId,
      credIdBase64,
      pubKeyBase64,
      counter,
      JSON.stringify(finalTransports),
      req.headers['user-agent'] || 'Bilinmeyen Cihaz',
      device_fingerprint
    );

    return { success: true, message: 'Cihaz bu personele başarıyla zimmetlendi.' };
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Cihaz onay hatası: ${err.message}` });
  }
});

app.get('/api/webauthn/assertion-options', async (req, reply) => {
  try {
    const session = authGuard(req, reply);
    if (!session) return;

    const cred = db.prepare('SELECT credential_id, transports FROM credentials WHERE user_id = ? AND is_active = 1').get(session.userId);
    if (!cred) {
      return reply.status(400).send({ error: 'Kayıtlı cihaz bulunamadı. Lütfen önce cihazınızı tanıtın.' });
    }

    const { rpID } = getWebAuthnConfig(req);

    let parsedTransports = ['internal'];
    try {
      if (cred.transports) {
        const t = JSON.parse(cred.transports);
        if (Array.isArray(t) && t.length > 0) parsedTransports = t;
      }
    } catch (_) {}

    const options = await generateAuthenticationOptions({
      rpID: rpID,
      allowCredentials: [{
        id: cred.credential_id,
        type: 'public-key',
        transports: parsedTransports
      }],
      userVerification: 'required'
    });

    webauthnChallenges.set(session.userId, options.challenge);
    return options;
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Giriş seçenekleri oluşturulamadı: ${err.message}` });
  }
});

// ----------------------------------------------------
// MESAİ İŞLEMLERİ (GEOFENCE & WEBAUTHN & DONANIM DENETİMİ)
// ----------------------------------------------------
app.post('/api/attendance/check-in', async (req, reply) => {
  try {
    const session = authGuard(req, reply);
    if (!session) return;

    const { assertion, coords, device_fingerprint } = req.body;
    const ip = req.ip;
    const ua = req.headers['user-agent'];

    if (!coords || typeof coords.latitude !== 'number' || typeof coords.longitude !== 'number') {
      return reply.status(400).send({ error: 'Konum verisi alınamadı.' });
    }

    const cred = db.prepare('SELECT * FROM credentials WHERE user_id = ? AND is_active = 1').get(session.userId);
    if (!cred) {
      return reply.status(400).send({ error: 'Yetkilendirilmiş donanım cihazı bulunamadı.' });
    }

    // DONANIM DENETİMİ: Başka bir cihazdan veya yetkisiz tarayıcıdan deneme kontrolü
    if (cred.device_fingerprint && device_fingerprint && cred.device_fingerprint !== device_fingerprint) {
      logSecurityEvent(session.userId, 'unauthorized_device_attempt', ip, ua, {
        saved_fp: cred.device_fingerprint,
        attempted_fp: device_fingerprint
      });
      return reply.status(403).send({ 
        error: 'GÜVENLİK İHLALİ: İşlem yapılan cihaz, sisteme kayıtlı olan fiziksel telefonunuz ile uyuşmuyor!' 
      });
    }

    const settingsRows = db.prepare('SELECT key, value FROM settings').all();
    const settings = Object.fromEntries(settingsRows.map(r => [r.key, r.value]));

    const maxAccuracy = parseFloat(settings.max_gps_accuracy || '60');
    if (coords.accuracy > maxAccuracy) {
      logSecurityEvent(session.userId, 'gps_inaccurate', ip, ua, { accuracy: coords.accuracy });
      return reply.status(400).send({
        error: `Konum doğruluğu yetersiz (${Math.round(coords.accuracy)}m). Lütfen açık alanda tekrar deneyin.`
      });
    }

    const centerLat = parseFloat(settings.center_lat);
    const centerLon = parseFloat(settings.center_lon);
    const allowedRadius = parseFloat(settings.geofence_radius);

    const distance = calculateHaversineDistance(centerLat, centerLon, coords.latitude, coords.longitude);
    if (distance > allowedRadius) {
      logSecurityEvent(session.userId, 'geofence_violation', ip, ua, { distance, allowedRadius });
      return reply.status(400).send({
        error: `Mesai başlatılamadı. Çalışma alanının dışındasınız. (Mesafe: ${Math.round(distance)}m, İzin verilen: ${allowedRadius}m)`
      });
    }

    const expectedChallenge = webauthnChallenges.get(session.userId);
    webauthnChallenges.delete(session.userId);

    const { rpID, expectedOrigin } = getWebAuthnConfig(req);

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(cred.credential_id, 'base64url'),
        credentialPublicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.counter
      }
    });

    if (!verification.verified) {
      logSecurityEvent(session.userId, 'device_mismatch', ip, ua, {});
      return reply.status(400).send({ error: 'Cihaz biyometrik doğrulaması geçersiz.' });
    }

    const newCounter = verification.authenticationInfo?.newCounter ?? cred.counter;
    db.prepare('UPDATE credentials SET counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newCounter, cred.id);

    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const existing = db.prepare('SELECT * FROM attendances WHERE user_id = ? AND work_date = ?').get(session.userId, today);

    if (existing && existing.check_in_time) {
      return reply.status(400).send({ error: 'Bugün için mesai giriş kaydınız zaten bulunmaktadır.' });
    }

    const shiftStatus = evaluateShiftStatus(now, settings.work_start_time, parseInt(settings.late_tolerance_minutes));

    if (!existing) {
      db.prepare(`
        INSERT INTO attendances (
          user_id, work_date, check_in_time, check_in_verified, check_in_accuracy, check_in_distance, status, verification_mode
        ) VALUES (?, ?, CURRENT_TIMESTAMP, 1, ?, ?, ?, 'webauthn_gps')
      `).run(session.userId, today, coords.accuracy, distance, shiftStatus);
    } else {
      db.prepare(`
        UPDATE attendances SET
          check_in_time = CURRENT_TIMESTAMP,
          check_in_verified = 1,
          check_in_accuracy = ?,
          check_in_distance = ?,
          status = ?,
          verification_mode = 'webauthn_gps'
        WHERE id = ?
      `).run(coords.accuracy, distance, shiftStatus, existing.id);
    }

    const formattedTime = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
    return {
      success: true,
      message: `Mesainiz başladı. Giriş saati: ${formattedTime} (${shiftStatus === 'late' ? 'Geç Giriş' : 'Zamanında'})`
    };
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Mesai başlatma hatası: ${err.message}` });
  }
});

app.post('/api/attendance/check-out', async (req, reply) => {
  try {
    const session = authGuard(req, reply);
    if (!session) return;

    const { assertion, coords, device_fingerprint } = req.body;
    const ip = req.ip;
    const ua = req.headers['user-agent'];

    if (!coords || typeof coords.latitude !== 'number' || typeof coords.longitude !== 'number') {
      return reply.status(400).send({ error: 'Konum bilgisi eksik.' });
    }

    const cred = db.prepare('SELECT * FROM credentials WHERE user_id = ? AND is_active = 1').get(session.userId);
    if (!cred) {
      return reply.status(400).send({ error: 'Yetkilendirilmiş donanım cihazı bulunamadı.' });
    }

    // DONANIM DENETİMİ: Çıkış anında cihaz doğrulaması
    if (cred.device_fingerprint && device_fingerprint && cred.device_fingerprint !== device_fingerprint) {
      logSecurityEvent(session.userId, 'unauthorized_device_attempt', ip, ua, {
        action: 'check-out',
        saved_fp: cred.device_fingerprint,
        attempted_fp: device_fingerprint
      });
      return reply.status(403).send({ 
        error: 'GÜVENLİK İHLALİ: Çıkış yapılan cihaz, sisteme kayıtlı olan fiziksel telefonunuz ile uyuşmuyor!' 
      });
    }

    const settingsRows = db.prepare('SELECT key, value FROM settings').all();
    const settings = Object.fromEntries(settingsRows.map(r => [r.key, r.value]));

    const distance = calculateHaversineDistance(
      parseFloat(settings.center_lat),
      parseFloat(settings.center_lon),
      coords.latitude,
      coords.longitude
    );

    if (distance > parseFloat(settings.geofence_radius)) {
      logSecurityEvent(session.userId, 'geofence_violation_checkout', ip, ua, { distance });
      return reply.status(400).send({
        error: `Mesai bitirilemedi. Kurum sınırları dışındasınız. (Mesafe: ${Math.round(distance)}m)`
      });
    }

    const today = new Date().toISOString().slice(0, 10);
    const attendance = db.prepare('SELECT * FROM attendances WHERE user_id = ? AND work_date = ?').get(session.userId, today);

    if (!attendance || !attendance.check_in_time) {
      return reply.status(400).send({ error: 'Mesai çıkışı yapabilmek için önce giriş kaydınız olmalıdır.' });
    }
    if (attendance.check_out_time) {
      return reply.status(400).send({ error: 'Bugün için çıkış kaydı zaten alınmıştır.' });
    }

    const expectedChallenge = webauthnChallenges.get(session.userId);
    webauthnChallenges.delete(session.userId);

    const { rpID, expectedOrigin } = getWebAuthnConfig(req);

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge,
      expectedOrigin: expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(cred.credential_id, 'base64url'),
        credentialPublicKey: Buffer.from(cred.public_key, 'base64url'),
        counter: cred.counter
      }
    });

    if (!verification.verified) {
      return reply.status(400).send({ error: 'Cihaz doğrulaması reddedildi.' });
    }

    const newCounter = verification.authenticationInfo?.newCounter ?? cred.counter;
    db.prepare('UPDATE credentials SET counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newCounter, cred.id);

    db.prepare(`
      UPDATE attendances SET
        check_out_time = CURRENT_TIMESTAMP,
        check_out_verified = 1,
        check_out_accuracy = ?,
        check_out_distance = ?
      WHERE id = ?
    `).run(coords.accuracy, distance, attendance.id);

    const now = new Date();
    const formattedTime = now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
    return { success: true, message: `Mesainiz tamamlandı. Çıkış saati: ${formattedTime}` };
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Mesai bitirme hatası: ${err.message}` });
  }
});

// ----------------------------------------------------
// SABİT TERMİNAL / ESKİ TELEFON PIN GİRİŞİ (FALLBACK)
// ----------------------------------------------------
app.post('/api/terminal/check-in', async (req, reply) => {
  const { employee_no, pin } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE employee_no = ? AND is_active = 1').get(employee_no);

  if (!user || user.auth_method !== 'pin_fallback' || !user.pin_hash) {
    return reply.status(400).send({ error: 'Bu personel için terminal/PIN giriş yetkisi bulunmuyor.' });
  }

  if (!verifyPassword(pin, user.pin_hash)) {
    return reply.status(400).send({ error: 'Geçersiz personel PIN kodu.' });
  }

  const today = new Date().toISOString().slice(0, 10);
  const existing = db.prepare('SELECT * FROM attendances WHERE user_id = ? AND work_date = ?').get(user.id, today);

  if (existing && existing.check_in_time) {
    return reply.status(400).send({ error: 'Bugün için zaten giriş yapılmış.' });
  }

  db.prepare(`
    INSERT INTO attendances (user_id, work_date, check_in_time, check_in_verified, status, verification_mode)
    VALUES (?, ?, CURRENT_TIMESTAMP, 1, 'normal', 'terminal_pin')
  `).run(user.id, today);

  return { success: true, message: `${user.first_name} ${user.last_name} için terminal girişi yapıldı.` };
});

// ----------------------------------------------------
// YÖNETİM (ADMIN) ENDPOINT'LERİ
// ----------------------------------------------------
app.get('/api/admin/employees', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const employees = db.prepare(`
    SELECT u.id, u.employee_no, u.first_name, u.last_name, u.department, u.role, u.is_active,
           c.id as has_device, c.last_used_at as device_last_used
    FROM users u
    LEFT JOIN credentials c ON u.id = c.user_id AND c.is_active = 1
    WHERE u.role = 'employee'
    ORDER BY u.employee_no ASC
  `).all();

  return employees;
});

app.post('/api/admin/add-employee', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const { employee_no, first_name, last_name, password, department } = req.body;

  if (!employee_no || !first_name || !last_name || !password) {
    return reply.status(400).send({ error: 'Sicil no, ad, soyad ve şifre zorunludur.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE employee_no = ?').get(employee_no);
  if (existing) {
    return reply.status(400).send({ error: `${employee_no} sicil numaralı personel zaten sistemde kayıtlı.` });
  }

  const passwordHash = hashPassword(password);

  db.prepare(`
    INSERT INTO users (employee_no, first_name, last_name, password_hash, role, department, is_active)
    VALUES (?, ?, ?, ?, 'employee', ?, 1)
  `).run(employee_no, first_name, last_name, passwordHash, department || 'Genel');

  return { success: true, message: `${first_name} ${last_name} başarıyla sisteme eklendi.` };
});

app.post('/api/admin/import-employees', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const { employees } = req.body;
  if (!Array.isArray(employees) || employees.length === 0) {
    return reply.status(400).send({ error: 'Geçerli bir personel listesi gönderilmedi.' });
  }

  const insertStmt = db.prepare(`
    INSERT INTO users (employee_no, first_name, last_name, password_hash, role, department, is_active)
    VALUES (?, ?, ?, ?, 'employee', ?, 1)
    ON CONFLICT(employee_no) DO UPDATE SET
      first_name = excluded.first_name,
      last_name = excluded.last_name,
      department = excluded.department
  `);

  let count = 0;
  const insertMany = db.transaction((list) => {
    for (const emp of list) {
      if (emp.no && emp.name && emp.surname) {
        const hashed = hashPassword(emp.pass || '123456');
        insertStmt.run(String(emp.no), emp.name, emp.surname, hashed, emp.dept || 'Genel');
        count++;
      }
    }
  });

  try {
    insertMany(employees);
    return { success: true, message: `${count} adet personel başarıyla yüklendi/güncellendi.` };
  } catch (err) {
    req.log.error(err);
    return reply.status(500).send({ error: `Toplu aktarım hatası: ${err.message}` });
  }
});

app.get('/api/admin/dashboard', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const today = new Date().toISOString().slice(0, 10);
  const totalEmployees = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'employee' AND is_active = 1").get().count;
  const attendanceToday = db.prepare('SELECT * FROM attendances WHERE work_date = ?').all(today);

  const presentCount = attendanceToday.filter(a => a.check_in_time).length;
  const lateCount = attendanceToday.filter(a => a.status === 'late').length;
  const checkedOutCount = attendanceToday.filter(a => a.check_out_time).length;
  const missingCheckouts = attendanceToday.filter(a => a.check_in_time && !a.check_out_time).length;
  const securityViolations = db.prepare('SELECT COUNT(*) as count FROM security_logs WHERE date(created_at) = ?').get(today).count;

  return {
    totalEmployees,
    presentCount,
    absentCount: Math.max(0, totalEmployees - presentCount),
    lateCount,
    checkedOutCount,
    missingCheckouts,
    securityViolations
  };
});

app.get('/api/admin/puantaj', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const date = req.query.date || new Date().toISOString().slice(0, 10);

  const records = db.prepare(`
    SELECT
      u.id as user_id,
      u.employee_no,
      u.first_name,
      u.last_name,
      u.department,
      a.id as attendance_id,
      a.check_in_time,
      a.check_out_time,
      a.status,
      a.verification_mode,
      a.check_in_distance
    FROM users u
    LEFT JOIN attendances a ON u.id = a.user_id AND a.work_date = ?
    WHERE u.role = 'employee' AND u.is_active = 1
    ORDER BY u.employee_no ASC
  `).all(date);

  return records;
});

app.post('/api/admin/manual-adjust', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const { attendance_id, user_id, work_date, check_in_time, check_out_time, reason } = req.body;
  if (!reason || reason.trim().length < 5) {
    return reply.status(400).send({ error: 'Manuel düzeltme için geçerli bir gerekçe girilmelidir.' });
  }

  let record = attendance_id ? db.prepare('SELECT * FROM attendances WHERE id = ?').get(attendance_id) : null;
  const oldVal = record ? JSON.stringify(record) : null;

  if (record) {
    db.prepare(`
      UPDATE attendances SET
        check_in_time = COALESCE(?, check_in_time),
        check_out_time = COALESCE(?, check_out_time),
        status = 'manual_adjusted'
      WHERE id = ?
    `).run(check_in_time, check_out_time, record.id);
  } else {
    const res = db.prepare(`
      INSERT INTO attendances (user_id, work_date, check_in_time, check_out_time, status, verification_mode)
      VALUES (?, ?, ?, ?, 'manual_adjusted', 'admin_manual')
    `).run(user_id, work_date, check_in_time, check_out_time);
    record = { id: res.lastInsertRowid };
  }

  const newVal = JSON.stringify({ check_in_time, check_out_time, status: 'manual_adjusted' });

  db.prepare(`
    INSERT INTO audit_logs (admin_id, target_user_id, attendance_id, action, old_value, new_value, reason)
    VALUES (?, ?, ?, 'manual_attendance_edit', ?, ?, ?)
  `).run(session.userId, user_id || record.user_id, record.id, oldVal, newVal, reason);

  return { success: true, message: 'Mesai kaydı denetim izi oluşturularak güncellendi.' };
});

app.post('/api/admin/reset-device', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const { user_id, reason } = req.body;
  if (!reason) return reply.status(400).send({ error: 'Cihaz sıfırlama gerekçesi belirtilmelidir.' });

  db.prepare('DELETE FROM credentials WHERE user_id = ?').run(user_id);

  db.prepare(`
    INSERT INTO audit_logs (admin_id, target_user_id, action, reason)
    VALUES (?, ?, 'reset_device_credential', ?)
  `).run(session.userId, user_id, reason);

  return { success: true, message: 'Personelin cihaz eşleştirmesi kaldırıldı.' };
});

app.get('/api/admin/settings', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;
  const rows = db.prepare('SELECT key, value FROM settings').all();
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
});

app.post('/api/admin/settings', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const update = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  for (const [key, value] of Object.entries(req.body)) {
    update.run(key, String(value));
  }
  return { success: true, message: 'Sistem parametreleri güncellendi.' };
});

// Güvenlik Günlüğü (İsteğe bağlı ?type=device filtresi destekler)
app.get('/api/admin/security-logs', async (req, reply) => {
  const session = authGuard(req, reply, ['admin']);
  if (!session) return;

  const filterType = req.query.type;
  let query = `
    SELECT s.*, u.employee_no, u.first_name, u.last_name
    FROM security_logs s
    LEFT JOIN users u ON s.user_id = u.id
  `;
  const params = [];

  if (filterType === 'device') {
    query += ` WHERE s.event_type IN ('device_sharing_attempt', 'unauthorized_device_attempt') `;
  }

  query += ` ORDER BY s.created_at DESC LIMIT 100 `;

  return db.prepare(query).all(...params);
});

// Sunucu Başlatma
app.listen({ port: Number(PORT), host: '0.0.0.0' }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`[BAŞARILI] Sistem dinlemede: ${address}`);
});