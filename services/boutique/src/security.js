'use strict';
// Sessions, protection CSRF, limitation de débit en mémoire (E04, SS2).
const crypto = require('node:crypto');
const db = require('./db');

const SESSION_COOKIE = '__Host-ostral_sid'; // préfixe __Host- : Secure, Path=/, pas de Domain
const CSRF_COOKIE = '__Host-ostral_csrf';

function cookieOpts(maxAgeMs, sameSite) {
  // HttpOnly + Secure + SameSite. TLS est terminé au WAF (F01/F02) : le navigateur ne voit que HTTPS.
  return { httpOnly: true, secure: true, sameSite, path: '/', maxAge: maxAgeMs };
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k && !(k in out)) {
      try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
    }
  }
  return out;
}

function makeSessions(cfg) {
  const hashToken = (token) => crypto.createHmac('sha256', cfg.sessionSecret).update(token).digest();

  async function create(res, customerId, ip) {
    const token = crypto.randomBytes(32).toString('base64url');
    const ttlMs = cfg.sessionTtlMinutes * 60 * 1000;
    await db.query(
      `INSERT INTO sessions (id_hash, customer_id, ip, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
      [hashToken(token), customerId, ip, cfg.sessionTtlMinutes * 60],
    );
    // SameSite=Lax : le cookie doit suivre la redirection de retour depuis le PSP (navigation GET
    // de premier niveau) ; les requêtes POST sont protégées par le jeton CSRF.
    res.cookie(SESSION_COOKIE, token, cookieOpts(ttlMs, 'lax'));
  }

  async function destroy(req, res) {
    const token = req.cookies[SESSION_COOKIE];
    if (token) await db.query('DELETE FROM sessions WHERE id_hash = $1', [hashToken(token)]);
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  }

  // Middleware : charge le client connecté (req.customer) si la session est valide
  async function load(req, _res, next) {
    try {
      req.customer = null;
      const token = req.cookies[SESSION_COOKIE];
      if (token && token.length <= 64) {
        const r = await db.query(
          `SELECT c.id, c.email, c.full_name, c.address_line, c.postal_code, c.city
             FROM sessions s JOIN customers c ON c.id = s.customer_id
            WHERE s.id_hash = $1 AND s.expires_at > now()`,
          [hashToken(token)],
        );
        req.customer = r.rows[0] || null;
      }
      next();
    } catch (err) { next(err); }
  }

  return { create, destroy, load };
}

// Jeton CSRF « double soumission » : cookie HttpOnly SameSite=Strict + champ caché du formulaire.
function csrf(req, res, next) {
  let token = req.cookies[CSRF_COOKIE];
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    token = crypto.randomBytes(32).toString('base64url');
    res.cookie(CSRF_COOKIE, token, cookieOpts(24 * 3600 * 1000, 'strict'));
  }
  req.csrfToken = token;
  if (req.method === 'POST') {
    const sent = (req.body && typeof req.body._csrf === 'string') ? req.body._csrf : '';
    const a = Buffer.from(sent);
    const b = Buffer.from(req.cookies[CSRF_COOKIE] || '');
    if (a.length === 0 || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      const err = new Error('jeton CSRF invalide');
      err.status = 403;
      err.securityEvent = 'csrf_rejected';
      return next(err);
    }
  }
  next();
}

// Limiteur à fenêtre fixe en mémoire (inscriptions). Le WAF applique aussi sa propre limite (F01).
function memoryLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, windowMs).unref();
  return function hit(key) {
    const now = Date.now();
    let e = hits.get(key);
    if (!e || e.reset <= now) { e = { count: 0, reset: now + windowMs }; hits.set(key, e); }
    e.count += 1;
    return e.count <= max;
  };
}

module.exports = { parseCookies, makeSessions, csrf, memoryLimiter, SESSION_COOKIE };
