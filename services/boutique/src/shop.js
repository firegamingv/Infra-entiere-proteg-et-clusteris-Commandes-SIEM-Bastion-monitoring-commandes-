'use strict';
// Catalogue, commandes et redirection vers le paiement hébergé du PSP (E02, SAQ A).
const crypto = require('node:crypto');
const express = require('express');
const db = require('./db');
const log = require('./logger');
const psp = require('./psp');
const { requireLogin } = require('./auth');
const { layout, csrfField, esc, euros, msg, STATUS_LABELS } = require('./views');

const SKU_RE = /^[A-Z0-9-]{3,32}$/;
const REF_RE = /^OST-[0-9]{8}-[0-9A-F]{10}$/;

function newReference() {
  const d = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  return `OST-${d}-${crypto.randomBytes(5).toString('hex').toUpperCase()}`;
}

// Charge une commande en vérifiant qu'elle appartient au client connecté (pas d'IDOR)
async function loadOwnOrder(req) {
  if (!REF_RE.test(req.params.ref)) return null;
  const r = await db.query('SELECT * FROM orders WHERE reference = $1 AND customer_id = $2',
    [req.params.ref, req.customer.id]);
  if (!r.rows[0]) return null;
  const lines = await db.query('SELECT * FROM order_lines WHERE order_id = $1 ORDER BY id', [r.rows[0].id]);
  return { ...r.rows[0], lines: lines.rows };
}

function orderPage(req, o, m) {
  const rows = o.lines.map((l) => `<tr><td>${esc(l.name)}</td><td>${l.quantity}</td>
    <td>${euros(l.unit_price_cents)}</td><td>${euros(l.unit_price_cents * l.quantity)}</td></tr>`).join('');
  const payable = ['pending', 'awaiting_payment', 'failed'].includes(o.status);
  return layout(req, `Commande ${o.reference}`, `${msg(m)}
<p>Statut : <strong>${esc(STATUS_LABELS[o.status] || o.status)}</strong></p>
<table><tr><th>Article</th><th>Qté</th><th>Prix unitaire</th><th>Total</th></tr>${rows}
<tr><th colspan="3">Total TTC</th><th>${euros(o.total_cents)}</th></tr></table>
${o.tracking_number ? `<p>Suivi transporteur : <code>${esc(o.tracking_number)}</code></p>` : ''}
${o.erp_synced_at ? '<p>Commande transmise à notre service logistique.</p>' : ''}
${payable ? `<form method="post" action="/orders/${esc(o.reference)}/pay">${csrfField(req)}
<button>Payer ${euros(o.total_cents)} sur la page sécurisée du prestataire</button></form>` : ''}
<p><a href="/account">Retour à mon compte</a></p>`);
}

function buildRouter(cfg) {
  const router = express.Router();

  router.get('/', async (req, res, next) => {
    try {
      const r = await db.query('SELECT sku, name, description, price_cents FROM products WHERE active ORDER BY id');
      const cards = r.rows.map((p) => `<div class="card"><h2>${esc(p.name)}</h2><p>${esc(p.description)}</p>
        <p><strong>${euros(p.price_cents)}</strong></p><a href="/products/${esc(p.sku)}">Voir le produit</a></div>`).join('');
      res.send(layout(req, 'Catalogue', `<div class="grid">${cards}</div>`));
    } catch (err) { next(err); }
  });

  router.get('/products/:sku', async (req, res, next) => {
    try {
      if (!SKU_RE.test(req.params.sku)) return res.status(404).send(layout(req, 'Introuvable', ''));
      const r = await db.query('SELECT * FROM products WHERE sku = $1 AND active', [req.params.sku]);
      const p = r.rows[0];
      if (!p) return res.status(404).send(layout(req, 'Introuvable', ''));
      const form = req.customer
        ? `<form method="post" action="/orders">${csrfField(req)}<input type="hidden" name="sku" value="${esc(p.sku)}">
           <label>Quantité <input type="number" name="quantity" value="1" min="1" max="20"></label><button>Commander</button></form>`
        : '<p><a href="/login">Connectez-vous</a> pour commander.</p>';
      return res.send(layout(req, p.name, `<p>${esc(p.description)}</p><p><strong>${euros(p.price_cents)}</strong></p>
        <p>Référence : ${esc(p.sku)}</p>${form}`));
    } catch (err) { return next(err); }
  });

  // Création d'une commande (un article). Le prix vient de la base, jamais du formulaire.
  router.post('/orders', requireLogin, async (req, res, next) => {
    try {
      const sku = typeof req.body.sku === 'string' ? req.body.sku : '';
      const qty = parseInt(req.body.quantity, 10);
      if (!SKU_RE.test(sku) || !Number.isInteger(qty) || qty < 1 || qty > 20) {
        return res.status(400).send(layout(req, 'Commande invalide', '<p class="err">Quantité ou produit invalide.</p>'));
      }
      const ref = await db.tx(async (c) => {
        const p = (await c.query('SELECT * FROM products WHERE sku = $1 AND active', [sku])).rows[0];
        if (!p) return null;
        const reference = newReference();
        const o = await c.query(
          'INSERT INTO orders (reference, customer_id, total_cents) VALUES ($1, $2, $3) RETURNING id',
          [reference, req.customer.id, p.price_cents * qty],
        );
        await c.query(
          `INSERT INTO order_lines (order_id, product_id, sku, name, quantity, unit_price_cents)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [o.rows[0].id, p.id, p.sku, p.name, qty, p.price_cents],
        );
        return reference;
      });
      if (!ref) return res.status(404).send(layout(req, 'Introuvable', ''));
      log.info('order_created', { ip: req.ip, customer_id: req.customer.id, order_ref: ref });
      return res.redirect(303, `/orders/${ref}`);
    } catch (err) { return next(err); }
  });

  router.get('/orders/:ref', requireLogin, async (req, res, next) => {
    try {
      const o = await loadOwnOrder(req);
      if (!o) return res.status(404).send(layout(req, 'Introuvable', ''));
      return res.send(orderPage(req, o));
    } catch (err) { return next(err); }
  });

  // E02 : la boutique crée la session de paiement chez le PSP puis redirige le navigateur vers la
  // page hébergée. Aucun champ carte n'existe dans la boutique (SAQ A).
  router.post('/orders/:ref/pay', requireLogin, async (req, res, next) => {
    try {
      const o = await loadOwnOrder(req);
      if (!o) return res.status(404).send(layout(req, 'Introuvable', ''));
      if (!['pending', 'awaiting_payment', 'failed'].includes(o.status)) return res.redirect(303, `/orders/${o.reference}`);
      let payment;
      try {
        payment = await psp.createPayment(cfg, {
          orderRef: o.reference, amountCents: o.total_cents, currency: o.currency, customerEmail: req.customer.email,
        });
      } catch (err) {
        log.error('psp_unavailable', { order_ref: o.reference, error: err.message });
        return res.status(503).send(orderPage(req, o, { text: 'Le service de paiement est momentanément indisponible. Réessayez dans quelques minutes.' }));
      }
      await db.query(
        `UPDATE orders SET status = 'awaiting_payment', psp_payment_id = $1
          WHERE id = $2 AND status IN ('pending', 'awaiting_payment', 'failed')`,
        [payment.paymentId, o.id],
      );
      log.info('payment_redirect', { ip: req.ip, customer_id: req.customer.id, order_ref: o.reference, payment_id: payment.paymentId });
      return res.redirect(303, payment.redirectUrl);
    } catch (err) { return next(err); }
  });

  // Retour navigateur depuis le PSP : purement informatif. Le statut « payée » ne provient QUE de la
  // notification serveur signée (/payment/notify), jamais des paramètres de cette URL.
  router.get('/orders/:ref/return', requireLogin, async (req, res, next) => {
    try {
      const o = await loadOwnOrder(req);
      if (!o) return res.status(404).send(layout(req, 'Introuvable', ''));
      const m = o.status === 'paid'
        ? { type: 'ok', text: 'Merci ! Votre paiement est confirmé.' }
        : { text: 'Paiement en cours de confirmation par le prestataire : actualisez la page dans quelques secondes.' };
      return res.send(orderPage(req, o, m));
    } catch (err) { return next(err); }
  });

  router.get('/account', requireLogin, async (req, res, next) => {
    try {
      const c = req.customer;
      const r = await db.query(
        'SELECT reference, status, total_cents, created_at FROM orders WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 50',
        [c.id],
      );
      const rows = r.rows.map((o) => `<tr><td><a href="/orders/${esc(o.reference)}">${esc(o.reference)}</a></td>
        <td>${esc(o.created_at.toISOString().slice(0, 10))}</td><td>${esc(STATUS_LABELS[o.status] || o.status)}</td>
        <td>${euros(o.total_cents)}</td></tr>`).join('');
      res.send(layout(req, 'Mon compte', `<p>${esc(c.full_name)} — ${esc(c.email)}<br>
        ${esc(c.address_line)}, ${esc(c.postal_code)} ${esc(c.city)}</p>
        <h2>Mes commandes</h2><table><tr><th>Référence</th><th>Date</th><th>Statut</th><th>Total</th></tr>${rows}</table>`));
    } catch (err) { next(err); }
  });

  return router;
}

module.exports = { buildRouter };
