'use strict';
// Client JSON-RPC Odoo — flux F04 : boutique (Z1) → API ERP publiée par le WAF (Z2) en mTLS.
//  - connexion https://waf:9443/jsonrpc, SNI et Host = erp-api.ostral.internal ;
//  - certificat serveur vérifié contre l'AC interne OSTRAL (ca.crt), jamais rejectUnauthorized=false ;
//  - certificat client boutique-client.crt/.key présenté au WAF (authentification mTLS) ;
//  - authentification applicative Odoo : utilisateur technique + clé API (moindre privilège).
// C'est le SEUL chemin de la boutique vers le SI interne (E05).
const fs = require('node:fs');
const https = require('node:https');

class OdooClient {
  constructor(erpCfg) {
    this.cfg = erpCfg;
    this.agent = null;
    this.uid = null;
    this.rpcId = 0;
  }

  // Chargement paresseux des certificats : la boutique démarre même si la PKI (lot B) n'est pas
  // encore générée ; le worker réessaiera plus tard (R2).
  getAgent() {
    if (!this.agent) {
      this.agent = new https.Agent({
        ca: fs.readFileSync(this.cfg.caFile),
        cert: fs.readFileSync(this.cfg.certFile),
        key: fs.readFileSync(this.cfg.keyFile),
        servername: this.cfg.servername,
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
        keepAlive: true,
        maxSockets: 2,
      });
    }
    return this.agent;
  }

  resetConnection() {
    if (this.agent) this.agent.destroy();
    this.agent = null;
    this.uid = null;
  }

  rpc(service, method, args) {
    const body = JSON.stringify({ jsonrpc: '2.0', method: 'call', id: ++this.rpcId, params: { service, method, args } });
    const opts = {
      host: this.cfg.host,
      port: this.cfg.port,
      method: 'POST',
      path: '/jsonrpc',
      agent: this.getAgent(),
      servername: this.cfg.servername,
      headers: {
        Host: this.cfg.servername,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        Accept: 'application/json',
      },
      timeout: this.cfg.timeoutMs,
    };
    return new Promise((resolve, reject) => {
      const req = https.request(opts, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > 1024 * 1024) { req.destroy(new Error('réponse ERP trop volumineuse')); return; }
          chunks.push(c);
        });
        res.on('end', () => {
          if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} depuis l'API ERP`));
          let data;
          try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return reject(new Error('réponse ERP non JSON')); }
          if (data.error) {
            const m = data.error.data?.message || data.error.message || 'erreur JSON-RPC';
            return reject(new Error(`Odoo : ${String(m).slice(0, 300)}`));
          }
          return resolve(data.result);
        });
      });
      req.on('timeout', () => req.destroy(new Error('délai dépassé vers l\'API ERP')));
      req.on('error', reject);
      req.end(body);
    });
  }

  async login() {
    if (this.uid) return this.uid;
    const uid = await this.rpc('common', 'login', [this.cfg.db, this.cfg.user, this.cfg.apiKey]);
    if (!uid) throw new Error('authentification Odoo refusée (utilisateur technique / clé API)');
    this.uid = uid;
    return uid;
  }

  async executeKw(model, method, args, kwargs = {}) {
    const uid = await this.login();
    return this.rpc('object', 'execute_kw', [this.cfg.db, uid, this.cfg.apiKey, model, method, args, kwargs]);
  }

  // Crée (de façon idempotente) le client puis la commande de vente dans Odoo.
  async pushOrder(p) {
    // Idempotence : si une commande avec cette référence existe déjà (réessai après coupure), on la réutilise
    const existing = await this.executeKw('sale.order', 'search', [[['client_order_ref', '=', p.order_ref]]], { limit: 1 });
    if (existing.length) return existing[0];

    let partnerId;
    const partners = await this.executeKw('res.partner', 'search', [[['email', '=ilike', p.customer.email]]], { limit: 1 });
    if (partners.length) {
      partnerId = partners[0];
    } else {
      partnerId = await this.executeKw('res.partner', 'create', [{
        name: p.customer.name,
        email: p.customer.email,
        street: p.customer.street,
        zip: p.customer.zip,
        city: p.customer.city,
        customer_rank: 1,
      }]);
    }

    const orderLines = [];
    for (const l of p.lines) {
      const productId = await this.ensureProduct(l);
      orderLines.push([0, 0, {
        product_id: productId,
        name: l.name,
        product_uom_qty: l.quantity,
        price_unit: l.unit_price_cents / 100,
      }]);
    }
    return this.executeKw('sale.order', 'create', [{
      partner_id: partnerId,
      client_order_ref: p.order_ref,
      origin: 'Boutique en ligne',
      order_line: orderLines,
    }]);
  }

  // Article Odoo retrouvé par sa référence interne (default_code = SKU boutique), créé si absent
  async ensureProduct(line) {
    const found = await this.executeKw('product.product', 'search', [[['default_code', '=', line.sku]]], { limit: 1 });
    if (found.length) return found[0];
    return this.executeKw('product.product', 'create', [{
      name: line.name,
      default_code: line.sku,
      list_price: line.unit_price_cents / 100,
      sale_ok: true,
    }]);
  }
}

module.exports = { OdooClient };
