'use strict';
// Clients sortants F03 (boutique → PSP / transporteur) via le réseau z1_egress, authentifiés par
// clé API. Dans la maquette ces flux sont en HTTP sur un réseau interne isolé ; en production ce
// sont des appels HTTPS (TCP 443) vers les fournisseurs (cf. matrice de flux, F03).

async function postJson(url, apiKey, body, timeoutMs = 10000) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey, accept: 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error',
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* corps non JSON */ }
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} depuis ${new URL(url).host}`);
    err.status = res.status;
    throw err;
  }
  if (!data || typeof data !== 'object') throw new Error('réponse non JSON');
  return data;
}

// E02 : création d'une session de paiement côté PSP (serveur à serveur). Le montant est fixé ici,
// le navigateur ne peut pas le modifier ; il est simplement redirigé vers la page hébergée du PSP.
async function createPayment(cfg, { orderRef, amountCents, currency, customerEmail }) {
  const data = await postJson(`${cfg.psp.apiUrl}/api/payments`, cfg.psp.apiKey, {
    order_ref: orderRef,
    amount_cents: amountCents,
    currency,
    customer_email: customerEmail,
    return_url: `${cfg.publicBaseUrl}/orders/${encodeURIComponent(orderRef)}/return`,
  });
  if (typeof data.payment_id !== 'string' || typeof data.redirect_url !== 'string') {
    throw new Error('réponse PSP incomplète');
  }
  // Redirection ouverte interdite : l'URL doit pointer vers l'origine publique attendue du PSP
  const target = new URL(data.redirect_url);
  if (target.origin !== new URL(cfg.psp.publicUrl).origin) throw new Error('URL de redirection PSP inattendue');
  return { paymentId: data.payment_id, redirectUrl: target.toString() };
}

// Transporteur simulé : demande d'étiquette d'expédition (appelé par le worker de l'outbox)
async function createLabel(cfg, payload) {
  const data = await postJson(`${cfg.carrier.apiUrl}/carrier/labels`, cfg.carrier.apiKey, payload);
  if (typeof data.tracking_number !== 'string') throw new Error('réponse transporteur incomplète');
  return data;
}

module.exports = { createPayment, createLabel };
