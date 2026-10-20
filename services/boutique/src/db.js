'use strict';
// Accès à boutique-db (PostgreSQL 16, réseau z1_data : seule la boutique y accède).
const { Pool } = require('pg');

let pool = null;

function init(dbConfig) {
  pool = new Pool({
    ...dbConfig,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    statement_timeout: 15000,
    application_name: 'ostral-boutique',
  });
  pool.on('error', () => { /* erreurs de connexions inactives : gérées à l'usage */ });
  return pool;
}

function query(text, params) {
  return pool.query(text, params);
}

async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const res = await fn(client);
    await client.query('COMMIT');
    return res;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

function getPool() { return pool; }

module.exports = { init, query, tx, getPool };
