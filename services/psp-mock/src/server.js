'use strict';
// OSTRAL — PSP et transporteur SIMULÉS (Z0 logique : prestataires sur Internet).
// Réseaux : z0_internet (10.10.0.40, page de paiement atteinte par le navigateur du client via le
// port publié 4000) et z1_egress (10.10.11.30, flux F03 depuis la boutique).
//
// Rôle dans la démonstration E02 / PCI DSS SAQ A : le formulaire de carte est servi par le PSP,
// pas par la boutique ; les données de carte ne sortent jamais d'ici (ni stockées, ni journalisées,
// ni transmises à la boutique). La boutique ne reçoit qu'une notification signée HMAC-SHA256.
// Maquette uniquement : aucun vrai paiement, cartes factices, état en mémoire.
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');

function required(name) {
  const v = process.env[name];
  if (!v || v.startsWith('CHANGEME')) throw new Error(`Variable obligatoire absente ou non modifiée : ${name}`);
  return v;
}

const cfg = {
  port: parseInt(process.env.PORT || '4000', 10),
  publicUrl: (process.env.PSP_PUBLIC_URL || 'http://localhost:4000').replace(/\/+$/, ''),
  apiKey: required('PSP_API_KEY'),
  webhookSecret: required('PSP_WEBHOOK_SECRET'),
  carrierApiKey: required('CARRIER_API_KEY'),
  notifyUrl: process.env.MERCHANT_NOTIFY_URL || 'http://boutique:3000/payment/notify',
  // Seules les URL de retour vers la boutique publique sont acceptées (pas de redirection ouverte)
  returnOrigin: new URL(process.env.MERCHANT_PUBLIC_URL || 'https://ostral.local').origin,
};

function log(level, event, fields = {}) {
  process.stdout.write(`${JSON.stringify({ '@timestamp': new Date().toISOString(), service: 'psp-mock', level, event, ...fields })}\n`);
}

function esc(v) {
  return String(v ?? '').replace(/[&<>"'`=]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;', '=': '&#61;',
  }[c]));
}

function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a || '')).digest();
  const y = crypto.createHash('sha256').update(String(b || '')).digest();
  return crypto.timingSafeEqual(x, y);
}

function requireApiKey(expected, label) {
  return (req, res, next) => {
    if (!safeEqual(req.get('x-api-key'), expected)) {
      log('security', 'api_key_rejected', { api: label, peer: req.socket.remoteAddress });
      return res.status(401).json({ error: 'unauthorized' });
    }
    return next();
  };
}

function luhn(num) {
  let sum = 0;
  for (let i = 0; i < num.length; i += 1) {
    let d = Number(num[num.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

const payments = new Map(); // payment_id -> { ... } (mémoire, expiration 1 h)
setInterval(() => {
  const limit = Date.now() - 3600 * 1000;
  for (const [id, p] of payments) if (p.createdAt < limit) payments.delete(id);
}, 600 * 1000).unref();

// Notification signée vers la boutique, avec réessais (le PSP réel fait de même)
async function notifyMerchant(p) {
  const body = JSON.stringify({
    event_id: `evt_${crypto.randomUUID()}`,
    type: `payment.${p.status}`,
    payment_id: p.id,
    order_ref: p.orderRef,
    status: p.status,
    amount_cents: p.amountCents,
    currency: p.currency,
    created_at: new Date().toISOString(),
  });
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    // Horodatage et signature recalculés à chaque envoi (fenêtre anti-rejeu côté boutique)
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = crypto.createHmac('sha256', cfg.webhookSecret).update(`${ts}.`).update(body).digest('hex');
    try {
      const res = await fetch(cfg.notifyUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-psp-timestamp': ts, 'x-psp-signature': `v1=${sig}` },
        body,
        signal: AbortSignal.timeout(5000),
      });
      log('info', 'merchant_notified', { payment_id: p.id, order_ref: p.orderRef, status: p.status, http: res.status, attempt });
      if (res.ok) return;
      if (res.status >= 400 && res.status < 500) return; // refus définitif : inutile d'insister
    } catch (err) {
      log('warn', 'merchant_notify_failed', { payment_id: p.id, attempt, error: err.message });
    }
    await new Promise((r) => setTimeout(r, 2000 * attempt));
  }
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'none'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      // Après soumission, redirection 303 vers la boutique : doit être autorisée par form-action
      'form-action': ["'self'", cfg.returnOrigin],
      'frame-ancestors': ["'none'"],
      'upgrade-insecure-requests': null, // maquette servie en HTTP sur localhost:4000
    },
  },
  strictTransportSecurity: false,
}));
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

// --- API marchand (F03, depuis la boutique sur z1_egress) ---------------------------------------
app.post('/api/payments', requireApiKey(cfg.apiKey, 'payments'), express.json({ limit: '4kb' }), (req, res) => {
  const b = req.body || {};
  let returnUrl;
  try { returnUrl = new URL(b.return_url); } catch { returnUrl = null; }
  if (typeof b.order_ref !== 'string' || !/^[A-Z0-9-]{4,40}$/.test(b.order_ref)
      || !Number.isInteger(b.amount_cents) || b.amount_cents <= 0 || b.amount_cents > 10_000_000
      || b.currency !== 'EUR' || !returnUrl || returnUrl.origin !== cfg.returnOrigin) {
    return res.status(400).json({ error: 'invalid_request' });
  }
  const id = `pay_${crypto.randomBytes(12).toString('hex')}`;
  payments.set(id, {
    id,
    orderRef: b.order_ref,
    amountCents: b.amount_cents,
    currency: b.currency,
    returnUrl: returnUrl.toString(),
    formToken: crypto.randomBytes(16).toString('hex'),
    status: 'created',
    createdAt: Date.now(),
  });
  log('info', 'payment_created', { payment_id: id, order_ref: b.order_ref, amount_cents: b.amount_cents });
  return res.status(201).json({ payment_id: id, redirect_url: `${cfg.publicUrl}/pay/${id}` });
});

// --- Page de paiement hébergée (navigateur du client, via z0_internet) ----------------------------
function payPage(p, error) {
  const amount = (p.amountCents / 100).toLocaleString('fr-FR', { style: 'currency', currency: p.currency });
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Paiement sécurisé — PSP simulé</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:40px auto;padding:0 16px}
label{display:block;margin:10px 0}input{width:100%;padding:6px}.err{color:#a00}.note{font-size:.85em;color:#555}</style></head>
<body><h1>PSP simulé</h1><p>Commande <strong>${esc(p.orderRef)}</strong> — montant <strong>${esc(amount)}</strong></p>
${error ? `<p class="err">${esc(error)}</p>` : ''}
<form method="post" action="/pay/${esc(p.id)}" autocomplete="off">
<input type="hidden" name="form_token" value="${esc(p.formToken)}">
<label>Titulaire <input name="holder" required maxlength="80"></label>
<label>Numéro de carte (factice) <input name="pan" required inputmode="numeric" maxlength="23"></label>
<label>Expiration (MM/AA) <input name="exp" required pattern="[0-9]{2}/[0-9]{2}"></label>
<label>CVC <input name="cvc" required inputmode="numeric" maxlength="4"></label>
<button name="action" value="pay">Payer</button> <button name="action" value="cancel" formnovalidate>Annuler</button>
</form>
<p class="note">Maquette : carte 4242 4242 4242 4242 = acceptée, 4000 0000 0000 0002 = refusée.
Les données saisies ne quittent pas le PSP : la boutique OSTRAL ne les voit jamais (SAQ A).</p></body></html>`;
}

app.get('/pay/:id', (req, res) => {
  const p = payments.get(req.params.id);
  if (!p) return res.status(404).send('Paiement inconnu ou expiré');
  if (p.status !== 'created') return res.redirect(303, p.returnUrl);
  return res.send(payPage(p));
});

app.post('/pay/:id', express.urlencoded({ extended: false, limit: '2kb', parameterLimit: 10 }), (req, res) => {
  const p = payments.get(req.params.id);
  if (!p) return res.status(404).send('Paiement inconnu ou expiré');
  if (p.status !== 'created') return res.redirect(303, p.returnUrl);
  if (!safeEqual(req.body.form_token, p.formToken)) return res.status(403).send('Formulaire invalide');

  if (req.body.action === 'cancel') {
    p.status = 'failed';
  } else {
    const pan = String(req.body.pan || '').replace(/[\s-]/g, '');
    const exp = /^(\d{2})\/(\d{2})$/.exec(String(req.body.exp || ''));
    if (!/^\d{13,19}$/.test(pan) || !luhn(pan) || !exp || Number(exp[1]) < 1 || Number(exp[1]) > 12
        || !/^\d{3,4}$/.test(String(req.body.cvc || ''))) {
      return res.status(400).send(payPage(p, 'Données de carte invalides.'));
    }
    p.status = pan === '4000000000000002' ? 'failed' : 'succeeded';
    // Seuls les 4 derniers chiffres apparaissent dans le journal du PSP ; rien n'est conservé
    log('info', 'payment_authorized', { payment_id: p.id, order_ref: p.orderRef, status: p.status, card_last4: pan.slice(-4) });
  }
  notifyMerchant(p).catch(() => {});
  // Retour navigateur vers la boutique (informatif : la boutique se fie à la notification signée)
  return res.redirect(303, p.returnUrl);
});

// --- Transporteur simulé (F03, clé API dédiée) ----------------------------------------------------
app.post('/carrier/labels', requireApiKey(cfg.carrierApiKey, 'carrier'), express.json({ limit: '4kb' }), (req, res) => {
  const b = req.body || {};
  const r = b.recipient || {};
  if (typeof b.order_ref !== 'string' || typeof r.name !== 'string' || typeof r.zip !== 'string' || typeof r.city !== 'string') {
    return res.status(400).json({ error: 'invalid_request' });
  }
  const tracking = `OSTR${crypto.randomBytes(6).toString('hex').toUpperCase()}FR`;
  log('info', 'label_created', { order_ref: b.order_ref, tracking_number: tracking, weight_grams: b.weight_grams });
  return res.status(201).json({ tracking_number: tracking, label_url: `${cfg.publicUrl}/carrier/labels/${tracking}.pdf`, carrier: 'Transporteur simulé' });
});

app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  log('error', 'http_error', { error: err.type || err.message });
  res.status(err.status || 500).json({ error: 'error' });
});

const server = app.listen(cfg.port, '0.0.0.0', () => log('info', 'psp_mock_started', { port: cfg.port }));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
