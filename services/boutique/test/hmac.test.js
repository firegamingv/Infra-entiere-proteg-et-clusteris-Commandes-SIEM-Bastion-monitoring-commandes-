'use strict';
// Tests unitaires de la vérification des notifications PSP (E02) — sans base de données.
// Exécution : npm test (node --test)
const test = require('node:test');
const assert = require('node:assert');
const { sign, verify } = require('../src/hmac');
const { backoffSeconds } = require('../src/worker');

const secret = 'secret-de-test';
const body = Buffer.from(JSON.stringify({ event_id: 'evt_1', status: 'succeeded' }));
const now = 1_760_000_000_000;
const ts = String(Math.floor(now / 1000));
const good = `v1=${sign(secret, ts, body)}`;

test('signature valide acceptée', () => {
  assert.deepStrictEqual(verify({ secret, rawBody: body, timestampHeader: ts, signatureHeader: good, now }), { ok: true });
});

test('corps modifié refusé', () => {
  const r = verify({ secret, rawBody: Buffer.from(body.toString().replace('succeeded', 'failed')), timestampHeader: ts, signatureHeader: good, now });
  assert.strictEqual(r.reason, 'signature_invalide');
});

test('mauvais secret refusé', () => {
  const bad = `v1=${sign('autre', ts, body)}`;
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: ts, signatureHeader: bad, now }).reason, 'signature_invalide');
});

test('horodatage hors fenêtre refusé (anti-rejeu)', () => {
  const old = String(Number(ts) - 301);
  const sig = `v1=${sign(secret, old, body)}`;
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: old, signatureHeader: sig, now }).reason, 'horodatage_hors_fenetre');
});

test('horodatage modifié refusé', () => {
  const other = String(Number(ts) + 10);
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: other, signatureHeader: good, now }).reason, 'signature_invalide');
});

test('en-têtes mal formés refusés', () => {
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: 'abc', signatureHeader: good, now }).reason, 'horodatage_invalide');
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: ts, signatureHeader: 'v1=zz', now }).reason, 'signature_mal_formee');
  assert.strictEqual(verify({ secret, rawBody: body, timestampHeader: ts, signatureHeader: undefined, now }).reason, 'signature_absente');
  assert.strictEqual(verify({ secret, rawBody: undefined, timestampHeader: ts, signatureHeader: good, now }).reason, 'corps_absent');
});

test('backoff borné (R2)', () => {
  for (let a = 1; a < 40; a += 1) {
    const d = backoffSeconds(a, 15, 1800);
    assert.ok(d >= 7 && d <= 1800, `délai ${d}`);
  }
});
