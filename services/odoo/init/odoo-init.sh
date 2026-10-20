#!/bin/bash
# OSTRAL — Lot C — initialisation IDEMPOTENTE de l'ERP (service one-shot `odoo-init`)
#
#   1. Si la base `ostral` (créée vide par erp-db, propriété du compte `odoo`, F06) n'a pas encore
#      les modules attendus : installation de base, sale_management, stock, account, auth_ldap
#      SANS données de démonstration (--without-demo=all).
#   2. Toujours (rejouable sans effet de bord) : `odoo shell` exécute configure_ostral.py qui
#      - fixe le mot de passe du compte web `admin` (sinon « admin » par défaut) ;
#      - crée/actualise l'utilisateur technique `api-boutique` (droits ventes uniquement) et
#        IMPOSE sa clé API = ODOO_API_KEY (contrat boutique → ERP, F04/F05) ;
#      - configure auth_ldap vers samba-ad (STARTTLS, AC vérifiée) pour les salariés (F07).
# Odoo n'a jamais besoin du droit CREATEDB : la base existe déjà.
set -Eeuo pipefail

log() { echo "[ostral/odoo-init] $*"; }
trap 'log "ERREUR ligne $LINENO (code $?) — voir aussi /var/log/odoo/odoo.log"' ERR

CONF="${ODOO_RC:-/run/odoo/odoo.conf}"
DB="${ODOO_DB:-ostral}"
MODULES="${ODOO_INIT_MODULES:-base,sale_management,stock,account,auth_ldap}"
export ODOO_INIT_MODULES="$MODULES" ODOO_DB="$DB"

: "${ODOO_API_KEY:?ODOO_API_KEY manquant}"
: "${ODOO_WEB_ADMIN_PASSWORD:?ODOO_WEB_ADMIN_PASSWORD manquant}"
: "${SAMBA_ODOO_BIND_PASSWORD:?SAMBA_ODOO_BIND_PASSWORD manquant}"

# --- Attente de la base (normalement garantie par depends_on: service_healthy) -----------------
for i in $(seq 1 30); do
  if python3 /opt/ostral/init/db_state.py ping; then break; fi
  [[ $i -eq 30 ]] && { log "base $DB injoignable"; exit 1; }
  sleep 2
done

# --- 1. Installation des modules (seulement si nécessaire) -------------------------------------
if python3 /opt/ostral/init/db_state.py modules-ok; then
  log "modules déjà installés dans '$DB' : $MODULES"
else
  log "installation des modules dans '$DB' : $MODULES (sans démo)…"
  # --workers=0 : processus unique pour l'initialisation ; --no-http : aucun port ouvert
  odoo -c "$CONF" -d "$DB" -i "$MODULES" --without-demo=all \
       --workers=0 --max-cron-threads=0 --no-http --stop-after-init
  python3 /opt/ostral/init/db_state.py modules-ok || { log "modules non installés"; exit 1; }
  log "modules installés."
fi

# --- 2. Configuration applicative (rejouable) ---------------------------------------------------
log "configuration : admin web, api-boutique + clé API, LDAP…"
odoo shell -c "$CONF" -d "$DB" --workers=0 --max-cron-threads=0 --no-http \
  < /opt/ostral/init/configure_ostral.py
log "initialisation terminée."
