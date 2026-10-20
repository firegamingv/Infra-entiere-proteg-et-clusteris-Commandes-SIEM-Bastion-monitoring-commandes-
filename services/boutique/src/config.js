'use strict';
// Configuration de la boutique (Z1). Tous les secrets viennent de l'environnement
// (injectés par compose depuis .env, jamais dans l'image ni dans git — E12).

function required(name) {
  const v = process.env[name];
  if (!v || v.startsWith('CHANGEME')) {
    // On refuse de démarrer avec un secret absent ou laissé à sa valeur d'exemple.
    throw new Error(`Variable d'environnement obligatoire absente ou non modifiée : ${name}`);
  }
  return v;
}

function optional(name, def) {
  const v = process.env[name];
  return v === undefined || v === '' ? def : v;
}

function int(name, def) {
  const n = parseInt(optional(name, String(def)), 10);
  if (!Number.isFinite(n)) throw new Error(`Valeur entière invalide pour ${name}`);
  return n;
}

function load() {
  return {
    port: int('PORT', 3000),
    // Seul le WAF (z1_cloud, 10.10.1.10) est un proxy de confiance (F02) : X-Forwarded-For
    // n'est pris en compte que s'il vient de lui.
    trustedProxy: optional('TRUSTED_PROXY', '10.10.1.10'),
    publicBaseUrl: optional('BOUTIQUE_PUBLIC_URL', 'https://ostral.local').replace(/\/+$/, ''),
    logFile: optional('LOG_FILE', '/var/log/boutique/app.log'),

    db: {
      host: optional('PGHOST', 'boutique-db'),
      port: int('PGPORT', 5432),
      database: optional('PGDATABASE', 'boutique'),
      user: optional('PGUSER', 'boutique'),
      password: required('BOUTIQUE_DB_PASSWORD'),
      max: int('PG_POOL_MAX', 10),
    },

    // Sessions : jeton aléatoire côté cookie, empreinte HMAC(SESSION_SECRET) en base.
    sessionSecret: required('SESSION_SECRET'),
    sessionTtlMinutes: int('SESSION_TTL_MINUTES', 120),

    // E04 / SS2 : limitation des tentatives de connexion
    login: {
      windowMinutes: int('LOGIN_WINDOW_MINUTES', 15),
      maxPerIp: int('LOGIN_MAX_PER_IP', 20),
      maxPerAccount: int('LOGIN_MAX_PER_ACCOUNT', 5),
      lockMinutes: int('LOGIN_LOCK_MINUTES', 15),
    },
    bcryptCost: int('BCRYPT_COST', 12),

    // E02 / F03 : PSP (paiement entièrement délégué, SAQ A)
    psp: {
      apiUrl: optional('PSP_API_URL', 'http://psp-mock:4000').replace(/\/+$/, ''),
      publicUrl: optional('PSP_PUBLIC_URL', 'http://localhost:4000').replace(/\/+$/, ''),
      apiKey: required('PSP_API_KEY'),
      webhookSecret: required('PSP_WEBHOOK_SECRET'),
      webhookToleranceSeconds: int('PSP_WEBHOOK_TOLERANCE_SECONDS', 300),
      // La notification n'est acceptée que depuis le PSP joint par z1_egress (défense en profondeur)
      notifyAllowedIps: optional('PSP_NOTIFY_ALLOWED_IPS', '10.10.11.30')
        .split(',').map((s) => s.trim()).filter(Boolean),
    },
    carrier: {
      apiUrl: optional('CARRIER_API_URL', 'http://psp-mock:4000').replace(/\/+$/, ''),
      apiKey: required('CARRIER_API_KEY'),
    },

    // F04 : API ERP via le WAF en mTLS
    erp: {
      host: optional('ERP_API_HOST', 'waf'),
      port: int('ERP_API_PORT', 9443),
      servername: optional('ERP_API_SERVERNAME', 'erp-api.ostral.internal'),
      caFile: optional('ERP_CA_FILE', '/run/certs/ca.crt'),
      certFile: optional('ERP_CLIENT_CERT_FILE', '/run/certs/boutique-client.crt'),
      keyFile: optional('ERP_CLIENT_KEY_FILE', '/run/certs/boutique-client.key'),
      db: required('ODOO_DB'),
      user: required('ODOO_API_USER'),
      apiKey: required('ODOO_API_KEY'),
      timeoutMs: int('ERP_TIMEOUT_MS', 10000),
    },

    // R2 : worker de la file d'attente
    outbox: {
      pollSeconds: int('OUTBOX_POLL_SECONDS', 10),
      batchSize: int('OUTBOX_BATCH_SIZE', 5),
      baseDelaySeconds: int('OUTBOX_BASE_DELAY_SECONDS', 15),
      maxDelaySeconds: int('OUTBOX_MAX_DELAY_SECONDS', 1800),
      alertAfterAttempts: int('OUTBOX_ALERT_AFTER_ATTEMPTS', 10),
    },
  };
}

module.exports = { load };
