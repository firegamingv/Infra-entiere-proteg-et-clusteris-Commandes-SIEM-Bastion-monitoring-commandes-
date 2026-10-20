'use strict';
// Migrations SQL appliquées au démarrage (fichiers migrations/NNN_*.sql, dans l'ordre).
// Verrou consultatif PostgreSQL : si plusieurs instances démarrent (montée en charge
// élastique du cloud, D), une seule applique les migrations.
const fs = require('node:fs');
const path = require('node:path');
const db = require('./db');
const log = require('./logger');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');
const LOCK_ID = 742001; // identifiant arbitraire du verrou consultatif

async function run() {
  const client = await db.getPool().connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_ID]);
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    const done = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
    const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => /^\d+_.+\.sql$/.test(f)).sort();
    for (const file of files) {
      if (done.has(file)) continue;
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        log.info('migration_applied', { migration: file });
      } catch (err) {
        await client.query('ROLLBACK');
        throw new Error(`échec migration ${file} : ${err.message}`);
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_ID]).catch(() => {});
    client.release();
  }
}

module.exports = { run };
