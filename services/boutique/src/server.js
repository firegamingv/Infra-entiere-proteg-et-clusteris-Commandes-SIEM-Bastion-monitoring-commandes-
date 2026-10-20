'use strict';
// OSTRAL — boutique en ligne (Z1). Joignable uniquement par le WAF (F02, z1_cloud) ; sorties
// limitées au PSP/transporteur (F03, z1_egress) et à l'API ERP via le WAF en mTLS (F04).
const express = require('express');
const helmet = require('helmet');
const config = require('./config');
const log = require('./logger');
const db = require('./db');
const migrate = require('./migrate');
const security = require('./security');
const auth = require('./auth');
const shop = require('./shop');
const payment = require('./payment');
const worker = require('./worker');
const { layout } = require('./views');

async function main() {
  const cfg = config.load();
  log.init(cfg.logFile);
  db.init(cfg.db);

  // Attente de la base puis migrations (schéma clients, produits, commandes, outbox)
  for (let i = 1; ; i += 1) {
    try { await migrate.run(); break; } catch (err) {
      if (i >= 30) throw err;
      log.warn('db_unavailable', { attempt: i, error: err.message });
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  const app = express();
  // Seul le WAF est un proxy de confiance : req.ip = IP client réelle transmise par le WAF (F02)
  app.set('trust proxy', cfg.trustedProxy);
  app.disable('x-powered-by');
  app.set('etag', false);

  // En-têtes de sécurité. form-action autorise la redirection 303 vers la page hébergée du PSP.
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'none'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'"],
        'form-action': ["'self'", new URL(cfg.psp.publicUrl).origin],
        'frame-ancestors': ["'none'"],
      },
    },
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: 'same-origin' },
  }));
  app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  // Supervision (Uptime Kuma, healthcheck Docker) : pas de données sensibles
  app.get('/healthz', async (_req, res) => {
    try {
      await db.query('SELECT 1');
      res.json({ status: 'ok' });
    } catch {
      res.status(503).json({ status: 'degraded' });
    }
  });

  // Notification PSP : corps brut (signature HMAC), hors CSRF (authentifiée par la signature)
  app.use(payment.buildRouter(cfg));

  app.use((req, _res, next) => { req.cookies = security.parseCookies(req.headers.cookie); next(); });
  app.use(express.urlencoded({ extended: false, limit: '8kb', parameterLimit: 20 }));
  app.use(security.csrf);
  const sessions = security.makeSessions(cfg);
  app.use(sessions.load);
  app.use(auth.buildRouter(cfg, sessions));
  app.use(shop.buildRouter(cfg));

  app.use((req, res) => res.status(404).send(layout(req, 'Page introuvable', '')));

  // Gestionnaire d'erreurs : journalise, ne divulgue rien au client
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    if (err.securityEvent) log.security(err.securityEvent, { ip: req.ip, path: req.path, method: req.method });
    else if (status >= 500) log.error('http_error', { ip: req.ip, path: req.path, method: req.method, error: err.message });
    else log.warn('http_client_error', { ip: req.ip, path: req.path, status, error: err.type || err.message });
    if (res.headersSent) return;
    req.customer = req.customer || null;
    req.csrfToken = req.csrfToken || '';
    res.status(status).send(layout(req, status >= 500 ? 'Erreur interne' : 'Requête refusée', ''));
  });

  // Purge périodique des sessions expirées et du journal de tentatives ancien (RGPD : minimisation)
  setInterval(() => {
    db.query('DELETE FROM sessions WHERE expires_at < now()').catch(() => {});
    db.query("DELETE FROM login_attempts WHERE created_at < now() - interval '90 days'").catch(() => {});
  }, 15 * 60 * 1000).unref();

  const w = worker.start(cfg);
  const server = app.listen(cfg.port, '0.0.0.0', () => log.info('boutique_started', { port: cfg.port }));
  server.headersTimeout = 20000;
  server.requestTimeout = 30000;

  const shutdown = (sig) => {
    log.info('boutique_stopping', { signal: sig });
    w.stop();
    server.close(() => db.getPool().end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(0), 10000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  log.error('boutique_fatal', { error: err.message });
  process.exit(1);
});
