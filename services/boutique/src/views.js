'use strict';
// Pages HTML minimales rendues côté serveur (aucun framework front, aucun script : CSP stricte).

function esc(v) {
  return String(v ?? '').replace(/[&<>"'`=]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;', '=': '&#61;',
  }[c]));
}

function euros(cents) {
  return (cents / 100).toLocaleString('fr-FR', { style: 'currency', currency: 'EUR' });
}

const STATUS_LABELS = {
  pending: 'En attente de paiement',
  awaiting_payment: 'Paiement en cours',
  paid: 'Payée',
  failed: 'Paiement refusé',
  cancelled: 'Annulée',
};

function layout(req, title, body) {
  const c = req.customer;
  const nav = c
    ? `<a href="/account">Mon compte (${esc(c.full_name)})</a>
       <form method="post" action="/logout" class="inline">${csrfField(req)}<button>Déconnexion</button></form>`
    : '<a href="/login">Connexion</a> <a href="/register">Créer un compte</a>';
  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — OSTRAL</title>
<style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:0 16px;color:#222}
header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #ddd;padding:12px 0}
header a{margin-left:12px}.inline{display:inline}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.card{border:1px solid #ddd;border-radius:8px;padding:16px}.err{color:#a00}.ok{color:#070}
label{display:block;margin:8px 0}input{width:100%;max-width:360px;padding:6px}button{padding:6px 14px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #eee;padding:6px;text-align:left}
</style></head><body>
<header><a href="/"><strong>OSTRAL</strong> mobilier</a><nav>${nav}</nav></header>
<main><h1>${esc(title)}</h1>${body}</main>
<footer><p><small>Paiement sécurisé par notre prestataire de paiement : OSTRAL ne voit jamais vos données de carte.</small></p></footer>
</body></html>`;
}

function csrfField(req) {
  return `<input type="hidden" name="_csrf" value="${esc(req.csrfToken)}">`;
}

function msg(m) {
  if (!m) return '';
  return `<p class="${m.type === 'ok' ? 'ok' : 'err'}">${esc(m.text)}</p>`;
}

module.exports = { esc, euros, layout, csrfField, msg, STATUS_LABELS };
