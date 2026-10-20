'use strict';
// Vérification des notifications de paiement du PSP (E02) — fonctions pures, testables sans base.
//
// Format attendu (contrat avec psp-mock) :
//   en-tête X-PSP-Timestamp : horodatage Unix en secondes
//   en-tête X-PSP-Signature : "v1=" + hex(HMAC-SHA256(secret, timestamp + "." + corps_brut))
// Le corps brut (octets exacts reçus) est signé : aucune re-sérialisation JSON avant vérification.
const crypto = require('node:crypto');

function sign(secret, timestamp, rawBody) {
  return crypto.createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest('hex');
}

/**
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function verify({ secret, rawBody, timestampHeader, signatureHeader, toleranceSeconds = 300, now = Date.now() }) {
  if (!Buffer.isBuffer(rawBody)) return { ok: false, reason: 'corps_absent' };
  if (typeof timestampHeader !== 'string' || !/^\d{1,12}$/.test(timestampHeader)) {
    return { ok: false, reason: 'horodatage_invalide' };
  }
  // Anti-rejeu (1) : fenêtre de tolérance sur l'horodatage signé
  const ts = Number(timestampHeader);
  if (Math.abs(Math.floor(now / 1000) - ts) > toleranceSeconds) {
    return { ok: false, reason: 'horodatage_hors_fenetre' };
  }
  if (typeof signatureHeader !== 'string') return { ok: false, reason: 'signature_absente' };
  const m = /^v1=([0-9a-f]{64})$/.exec(signatureHeader.trim());
  if (!m) return { ok: false, reason: 'signature_mal_formee' };

  const expected = Buffer.from(sign(secret, timestampHeader, rawBody), 'hex');
  const received = Buffer.from(m[1], 'hex');
  // Comparaison à temps constant (les deux tampons font 32 octets, garanti par la regex)
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return { ok: false, reason: 'signature_invalide' };
  }
  // Anti-rejeu (2) : l'unicité de event_id est contrôlée en base (table payment_events)
  return { ok: true };
}

module.exports = { sign, verify };
