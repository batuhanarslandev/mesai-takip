import crypto from 'node:crypto';
import { db } from './database.js';

const sessions = new Map();

export function createSession(userId, role) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const sessionData = {
    userId,
    role,
    createdAt: Date.now(),
    expiresAt: Date.now() + 12 * 60 * 60 * 1000 // 12 saat
  };
  sessions.set(sessionId, sessionData);
  return sessionId;
}

export function getSession(sessionId) {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

export function destroySession(sessionId) {
  sessions.delete(sessionId);
}

export function logSecurityEvent(userId, eventType, ip, userAgent, details = {}) {
  try {
    db.prepare(`
      INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(userId, eventType, ip, userAgent, JSON.stringify(details));
  } catch (err) {
    console.error('Güvenlik logu yazılamadı:', err);
  }
}