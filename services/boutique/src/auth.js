'use strict';
// Inscription / connexion des clients — E04 et SS2 (piratage en masse des comptes clients) :
//  - mots de passe hachés bcrypt (coût 12), longueur minimale 12 ;
//  - limitation des échecs par IP (fenêtre glissante, comptage en base) ;
//  - verrouillage temporaire du compte après N échecs consécutifs, quelle que soit l'IP
//    (couvre le « credential stuffing » distribué) ;
//  - journal des tentatives (table login_attempts + app.log pour Wazuh, E08) ;
//  - message d'erreur générique et temps de réponse homogène (pas d'énumération de comptes).
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');
const log = require('./logger');
const { layout, csrfField, msg, esc } = require('./views');
const { memoryLimiter } = require('./security');

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const GENERIC_FAIL = 'Identifiants invalides, ou compte temporairement verrouillé après plusieurs échecs. Réessayez plus tard.';

function str(v, max) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function loginPage(req, m, email = '') {
  return layout(req, 'Connexion', `${msg(m)}
<form method="post" action="/login">${csrfField(req)}
<label>Adresse e-mail <input type="email" name="email" value="${esc(email)}" required autocomplete="username"></label>
<label>Mot de passe <input type="password" name="password" required autocomplete="current-password"></label>
<button>Se connecter</button></form>
<p><a href="/register">Créer un compte</a></p>`);
}

function registerPage(req, m, v = {}) {
  return layout(req, 'Créer un compte', `${msg(m)}
<form method="post" action="/register">${csrfField(req)}
<label>Nom complet <input name="full_name" value="${esc(v.full_name)}" required maxlength="120"></label>
<label>Adresse e-mail <input type="email" name="email" value="${esc(v.email)}" required autocomplete="username"></label>
<label>Mot de passe (12 caractères minimum) <input type="password" name="password" required minlength="12" autocomplete="new-password"></label>
<label>Adresse <input name="address_line" value="${esc(v.address_line)}" required maxlength="200"></label>
<label>Code postal <input name="postal_code" value="${esc(v.postal_code)}" required pattern="[0-9]{5}"></label>
<label>Ville <input name="city" value="${esc(v.city)}" required maxlength="100"></label>
<button>Créer mon compte</button></form>`);
}

function buildRouter(cfg, sessions) {
  const router = express.Router();
  const L = cfg.login;
  // Hachage factice : on exécute toujours un bcrypt.compare pour un temps de réponse homogène
  const dummyHash = bcrypt.hashSync('compte-inexistant-ostral', cfg.bcryptCost);
  const registerLimiter = memoryLimiter({ windowMs: 3600 * 1000, max: 10 });

  async function recordAttempt(email, customerId, ip, success, reason) {
    await db.query(
      'INSERT INTO login_attempts (email, customer_id, ip, success, reason) VALUES ($1, $2, $3, $4, $5)',
      [email.slice(0, 254), customerId, ip || null, success, reason],
    );
  }

  router.get('/login', (req, res) => res.send(loginPage(req)));

  router.post('/login', async (req, res, next) => {
    try {
      const email = str(req.body.email, 254).toLowerCase();
      const password = typeof req.body.password === 'string' ? req.body.password : '';
      const ip = req.ip;

      // 1) Limitation par IP (SS2) — en complément de la limitation de débit du WAF (F01)
      const ipFails = await db.query(
        `SELECT count(*)::int AS n FROM login_attempts
          WHERE ip = $1 AND success = false AND created_at > now() - make_interval(mins => $2)`,
        [ip, L.windowMinutes],
      );
      if (ipFails.rows[0].n >= L.maxPerIp) {
        await recordAttempt(email, null, ip, false, 'ip_rate_limited');
        log.security('login_blocked_ip', { ip, email, failures: ipFails.rows[0].n, window_min: L.windowMinutes });
        res.set('Retry-After', String(L.windowMinutes * 60));
        return res.status(429).send(loginPage(req, { text: 'Trop de tentatives depuis votre adresse. Réessayez plus tard.' }, email));
      }

      const r = await db.query(
        'SELECT id, password_hash, locked_until, locked_until > now() AS locked FROM customers WHERE email = $1',
        [email],
      );
      const customer = r.rows[0];

      // 2) Compte verrouillé : on refuse sans même évaluer le mot de passe
      if (customer && customer.locked) {
        await bcrypt.compare(password, dummyHash);
        await recordAttempt(email, customer.id, ip, false, 'account_locked');
        log.security('login_failed', { ip, email, customer_id: customer.id, reason: 'account_locked' });
        return res.status(401).send(loginPage(req, { text: GENERIC_FAIL }, email));
      }

      const valid = password.length > 0 && password.length <= 128
        && await bcrypt.compare(password, customer ? customer.password_hash : dummyHash);

      if (!customer || !valid) {
        const reason = customer ? 'bad_password' : 'unknown_account';
        await recordAttempt(email, customer ? customer.id : null, ip, false, reason);
        log.security('login_failed', { ip, email, customer_id: customer?.id, reason });
        if (customer) {
          // 3) Verrouillage temporaire après N échecs consécutifs (E04)
          const u = await db.query(
            `UPDATE customers SET
                failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END,
                locked_until    = CASE WHEN failed_attempts + 1 >= $2
                                       THEN now() + make_interval(mins => $3) ELSE locked_until END
              WHERE id = $1
          RETURNING locked_until > now() AS locked`,
            [customer.id, L.maxPerAccount, L.lockMinutes],
          );
          if (u.rows[0]?.locked) {
            log.security('account_locked', { ip, email, customer_id: customer.id, lock_min: L.lockMinutes });
          }
        }
        return res.status(401).send(loginPage(req, { text: GENERIC_FAIL }, email));
      }

      await db.query(
        'UPDATE customers SET failed_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1',
        [customer.id],
      );
      await recordAttempt(email, customer.id, ip, true, null);
      // Nouvelle session à chaque connexion (pas de fixation de session) ; l'ancienne est supprimée
      await sessions.destroy(req, res);
      await sessions.create(res, customer.id, ip);
      log.security('login_success', { ip, email, customer_id: customer.id });
      return res.redirect(303, '/account');
    } catch (err) { return next(err); }
  });

  router.get('/register', (req, res) => res.send(registerPage(req)));

  router.post('/register', async (req, res, next) => {
    try {
      const ip = req.ip;
      const v = {
        full_name: str(req.body.full_name, 120),
        email: str(req.body.email, 254).toLowerCase(),
        address_line: str(req.body.address_line, 200),
        postal_code: str(req.body.postal_code, 5),
        city: str(req.body.city, 100),
      };
      const password = typeof req.body.password === 'string' ? req.body.password : '';

      if (!registerLimiter(ip)) {
        log.security('register_rate_limited', { ip });
        return res.status(429).send(registerPage(req, { text: 'Trop de créations de compte depuis votre adresse.' }, v));
      }
      const errors = [];
      if (!EMAIL_RE.test(v.email)) errors.push('adresse e-mail invalide');
      // bcrypt ne prend en compte que 72 octets : on borne la longueur pour éviter toute ambiguïté
      if (password.length < 12 || Buffer.byteLength(password) > 72) errors.push('mot de passe de 12 à 72 caractères');
      if (!v.full_name || !v.address_line || !v.city) errors.push('champs obligatoires manquants');
      if (!/^\d{5}$/.test(v.postal_code)) errors.push('code postal invalide');
      if (errors.length) return res.status(400).send(registerPage(req, { text: `Erreur : ${errors.join(', ')}.` }, v));

      const hash = await bcrypt.hash(password, cfg.bcryptCost);
      const ins = await db.query(
        `INSERT INTO customers (email, password_hash, full_name, address_line, postal_code, city)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (email) DO NOTHING RETURNING id`,
        [v.email, hash, v.full_name, v.address_line, v.postal_code, v.city],
      );
      if (ins.rowCount === 0) {
        log.security('register_duplicate', { ip, email: v.email });
        return res.status(400).send(registerPage(req, { text: 'Impossible de créer un compte avec ces informations.' }, v));
      }
      const id = ins.rows[0].id;
      log.security('account_created', { ip, email: v.email, customer_id: id });
      await sessions.create(res, id, ip);
      return res.redirect(303, '/account');
    } catch (err) { return next(err); }
  });

  router.post('/logout', async (req, res, next) => {
    try {
      if (req.customer) log.security('logout', { ip: req.ip, customer_id: req.customer.id });
      await sessions.destroy(req, res);
      res.redirect(303, '/');
    } catch (err) { next(err); }
  });

  return router;
}

function requireLogin(req, res, next) {
  if (!req.customer) return res.redirect(303, '/login');
  return next();
}

module.exports = { buildRouter, requireLogin };
