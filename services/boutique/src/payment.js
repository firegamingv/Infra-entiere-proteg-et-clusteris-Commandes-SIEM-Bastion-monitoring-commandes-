'use strict';
// Réception de la notification de paiement du PSP (E02) — POST /payment/notify
// Contrôles, dans l'ordre :
//  1. origine réseau : PSP joint par z1_egress uniquement (le WAF ne doit pas exposer cette route) ;
//  2. signature HMAC-SHA256 du corps brut, comparaison à temps constant ;
//  3. horodatage dans une fenêtre de tolérance (anti-rejeu) ;
//  4. event_id unique en base (anti-rejeu, idempotence) ;
//  5. cohérence avec la commande (identifiant de paiement, montant, devise).
// Une commande payée est insérée dans l'outbox DANS LA MÊME TRANSACTION (R2) : aucune commande
// payée ne peut être perdue si l'ERP ou le transporteur est indisponible.
const express = require('express');
const db = require('./db');
const log = require('./logger');
const hmac = require('./hmac');

function normalizeIp(ip) {
  return typeof ip === 'string' && ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function buildRouter(cfg) {
  const router = express.Router();

  router.post('/payment/notify', express.raw({ type: 'application/json', limit: '16kb' }), async (req, res, next) => {
    // Adresse de la connexion TCP (et non X-Forwarded-For) : la notification arrive directement du PSP
    const peer = normalizeIp(req.socket.remoteAddress);
    try {
      if (!cfg.psp.notifyAllowedIps.includes(peer)) {
        log.security('payment_notify_rejected', { peer, reason: 'source_non_autorisee' });
        return res.status(403).json({ error: 'forbidden' });
      }
      const check = hmac.verify({
        secret: cfg.psp.webhookSecret,
        rawBody: req.body,
        timestampHeader: req.get('x-psp-timestamp'),
        signatureHeader: req.get('x-psp-signature'),
        toleranceSeconds: cfg.psp.webhookToleranceSeconds,
      });
      if (!check.ok) {
        log.security('payment_notify_rejected', { peer, reason: check.reason });
        return res.status(401).json({ error: 'invalid_signature' });
      }

      let evt;
      try { evt = JSON.parse(req.body.toString('utf8')); } catch { evt = null; }
      if (!evt || typeof evt.event_id !== 'string' || typeof evt.payment_id !== 'string'
          || typeof evt.order_ref !== 'string' || !['succeeded', 'failed'].includes(evt.status)
          || !Number.isInteger(evt.amount_cents) || typeof evt.currency !== 'string') {
        log.security('payment_notify_rejected', { peer, reason: 'contenu_invalide' });
        return res.status(400).json({ error: 'bad_request' });
      }

      const result = await db.tx(async (c) => {
        const ins = await c.query(
          `INSERT INTO payment_events (event_id, payment_id, order_ref, status)
           VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING`,
          [evt.event_id.slice(0, 100), evt.payment_id.slice(0, 100), evt.order_ref.slice(0, 40), evt.status],
        );
        if (ins.rowCount === 0) return 'duplicate';

        const o = (await c.query(
          `SELECT o.*, c.email, c.full_name, c.address_line, c.postal_code, c.city
             FROM orders o JOIN customers c ON c.id = o.customer_id
            WHERE o.reference = $1 FOR UPDATE OF o`,
          [evt.order_ref],
        )).rows[0];
        if (!o) return 'unknown_order';
        if (o.psp_payment_id !== evt.payment_id) return 'payment_mismatch';
        if (o.total_cents !== evt.amount_cents || o.currency !== evt.currency) return 'amount_mismatch';
        if (o.status === 'paid') return 'already_paid';

        if (evt.status === 'failed') {
          await c.query("UPDATE orders SET status = 'failed' WHERE id = $1", [o.id]);
          return 'failed';
        }

        await c.query("UPDATE orders SET status = 'paid', paid_at = now() WHERE id = $1", [o.id]);
        const lines = (await c.query(
          `SELECT l.sku, l.name, l.quantity, l.unit_price_cents, p.weight_grams
             FROM order_lines l JOIN products p ON p.id = l.product_id
            WHERE l.order_id = $1 ORDER BY l.id`, [o.id],
        )).rows;
        const customer = {
          email: o.email, name: o.full_name, street: o.address_line, zip: o.postal_code, city: o.city,
        };
        // Instantané des données à transmettre (la file ne dépend plus de l'état des tables)
        await c.query(
          `INSERT INTO outbox (kind, aggregate_id, payload) VALUES
             ('erp_order', $1, $2), ('carrier_label', $1, $3)
           ON CONFLICT (kind, aggregate_id) DO NOTHING`,
          [
            o.id,
            JSON.stringify({ order_ref: o.reference, currency: o.currency, total_cents: o.total_cents, customer, lines }),
            JSON.stringify({
              order_ref: o.reference,
              recipient: { name: o.full_name, street: o.address_line, zip: o.postal_code, city: o.city, country: 'FR' },
              weight_grams: lines.reduce((w, l) => w + l.weight_grams * l.quantity, 0),
              parcels: lines.reduce((n, l) => n + l.quantity, 0),
            }),
          ],
        );
        return 'paid';
      });

      const fields = { peer, event_id: evt.event_id, payment_id: evt.payment_id, order_ref: evt.order_ref, result };
      if (['payment_mismatch', 'amount_mismatch', 'unknown_order'].includes(result)) {
        // Anomalie : notification correctement signée mais incohérente — à investiguer (SIEM)
        log.security('payment_notify_anomaly', fields);
      } else {
        log.info('payment_notify', fields);
      }
      return res.status(200).json({ received: true, result });
    } catch (err) { return next(err); }
  });

  return router;
}

module.exports = { buildRouter, normalizeIp };
