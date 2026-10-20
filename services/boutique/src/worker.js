'use strict';
// Worker de la file d'attente (outbox) — R2 « coupure du lien boutique ↔ ERP ».
// Les commandes payées restent en base tant que l'ERP (via le WAF, F04/F05) ou le transporteur
// (F03) ne les a pas acceptées. Réessais avec backoff exponentiel plafonné + gigue, sans limite de
// nombre : l'ERP a un RTO de 8 h, aucune commande n'est abandonnée. Alerte SIEM au-delà de N essais.
const db = require('./db');
const log = require('./logger');
const psp = require('./psp');
const { OdooClient } = require('./odoo');

function backoffSeconds(attempts, base, max) {
  const raw = Math.min(max, base * 2 ** Math.min(attempts, 20));
  return Math.round(raw * (0.5 + Math.random() * 0.5)); // gigue : évite les rafales synchronisées
}

function start(cfg) {
  const odoo = new OdooClient(cfg.erp);
  const oc = cfg.outbox;
  let running = false;
  let stopped = false;

  async function handle(item) {
    if (item.kind === 'erp_order') {
      const erpId = await odoo.pushOrder(item.payload);
      await db.query('UPDATE orders SET erp_order_id = $1, erp_synced_at = now() WHERE id = $2', [erpId, item.aggregate_id]);
      return { erp_order_id: erpId };
    }
    if (item.kind === 'carrier_label') {
      const label = await psp.createLabel(cfg, item.payload);
      await db.query('UPDATE orders SET tracking_number = $1 WHERE id = $2', [label.tracking_number.slice(0, 64), item.aggregate_id]);
      return { tracking_number: label.tracking_number };
    }
    throw new Error(`type inconnu ${item.kind}`);
  }

  async function tick() {
    if (running || stopped) return;
    running = true;
    try {
      // Réservation des éléments (verrou court) : compatible avec plusieurs instances de la boutique
      const claimed = await db.query(
        `UPDATE outbox SET locked_until = now() + interval '2 minutes'
          WHERE id IN (SELECT id FROM outbox
                        WHERE status = 'pending' AND next_attempt_at <= now()
                          AND (locked_until IS NULL OR locked_until < now())
                        ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
        RETURNING id, kind, aggregate_id, payload, attempts`,
        [oc.batchSize],
      );
      for (const item of claimed.rows) {
        const ref = item.payload?.order_ref;
        try {
          const out = await handle(item);
          await db.query(
            `UPDATE outbox SET status = 'done', processed_at = now(), attempts = attempts + 1,
                    locked_until = NULL, last_error = NULL WHERE id = $1`, [item.id],
          );
          log.info('outbox_delivered', { outbox_id: item.id, kind: item.kind, order_ref: ref, attempts: item.attempts + 1, ...out });
        } catch (err) {
          if (item.kind === 'erp_order') odoo.resetConnection(); // nouvelle poignée TLS / reconnexion au prochain essai
          const attempts = item.attempts + 1;
          const delay = backoffSeconds(attempts, oc.baseDelaySeconds, oc.maxDelaySeconds);
          await db.query(
            `UPDATE outbox SET attempts = $2, last_error = $3, locked_until = NULL,
                    next_attempt_at = now() + make_interval(secs => $4) WHERE id = $1`,
            [item.id, attempts, String(err.message).slice(0, 500), delay],
          );
          const fields = { outbox_id: item.id, kind: item.kind, order_ref: ref, attempts, retry_in_s: delay, error: err.message };
          if (attempts >= oc.alertAfterAttempts) log.error('outbox_backlog_alert', fields);
          else log.warn('outbox_retry', fields);
        }
      }
    } catch (err) {
      log.error('outbox_worker_error', { error: err.message });
    } finally {
      running = false;
    }
  }

  const timer = setInterval(tick, oc.pollSeconds * 1000);
  setImmediate(tick);
  log.info('outbox_worker_started', { poll_s: oc.pollSeconds, erp: `${cfg.erp.host}:${cfg.erp.port}`, sni: cfg.erp.servername });
  return { stop() { stopped = true; clearInterval(timer); } };
}

module.exports = { start, backoffSeconds };
