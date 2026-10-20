'use strict';
// Journal applicatif en JSON lignes (une ligne = un événement) dans /var/log/boutique/app.log,
// volume nommé logs_boutique lu par Wazuh (E08, F11). Copie sur stdout pour `docker logs`.
// Règle : jamais de mot de passe, jeton de session, clé API ni donnée de carte dans les journaux.
const fs = require('node:fs');
const path = require('node:path');

let stream = null;

function init(file) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    stream = fs.createWriteStream(file, { flags: 'a' });
    stream.on('error', (err) => {
      stream = null;
      process.stderr.write(`journal indisponible (${err.code}), sortie standard uniquement\n`);
    });
  } catch (err) {
    stream = null;
    process.stderr.write(`journal indisponible (${err.code}), sortie standard uniquement\n`);
  }
}

// Neutralise les retours à la ligne (injection de faux événements dans le journal)
// Caractères de fin de ligne (CR, LF, séparateurs Unicode U+2028/U+2029)
const NEWLINES = new RegExp('[' + String.fromCharCode(13, 10, 0x2028, 0x2029) + ']', 'g');

function clean(v) {
  if (typeof v === 'string') return v.replace(NEWLINES, ' ').slice(0, 512);
  return v;
}

function write(level, event, fields = {}) {
  const entry = { '@timestamp': new Date().toISOString(), service: 'boutique', level, event };
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) entry[k] = clean(v);
  }
  const line = JSON.stringify(entry) + '\n';
  if (stream) stream.write(line);
  process.stdout.write(line);
}

module.exports = {
  init,
  info: (event, f) => write('info', event, f),
  warn: (event, f) => write('warn', event, f),
  error: (event, f) => write('error', event, f),
  // Événements de sécurité (connexions, échecs, verrouillages, actions sensibles) : catégorie dédiée
  security: (event, f) => write('security', event, f),
};
