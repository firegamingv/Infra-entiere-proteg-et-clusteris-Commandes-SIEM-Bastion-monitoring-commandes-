#!/bin/sh
# OSTRAL — TEST MENSUEL DE RESTAURATION de l'ERP (calendrier de tests p. 11, E09 « 0 erreur », E10).
# Restaure la DERNIÈRE sauvegarde de la base ERP dans un PostgreSQL 16 temporaire et ISOLÉ :
# instance jetable lancée dans ce conteneur, sans écoute réseau (socket Unix seulement), détruite
# à la fin. Vérifications : base lisible, nombre de tables, nombre de commandes sale_order cohérent
# avec la production (lecture via backup_ro). Mesure la durée (comparée au RTO ERP de 8 h).
#
# Usage : docker compose exec backup restore-test.sh [--full-check] [--snapshot ID]
#   --full-check  relit 100 % des données du dépôt (restic check --read-data) — plus long
# Résultat : ligne JSON job=restore-test status=OK|ECHEC dans logs_backup (Wazuh règle 100703).
set -u
. /usr/local/bin/lib.sh

FULL_CHECK=0
SNAPSHOT=latest
while [ $# -gt 0 ]; do
  case "$1" in
    --full-check) FULL_CHECK=1 ;;
    --snapshot)   shift; SNAPSHOT="${1:?ID de snapshot attendu}" ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done
# Le 1er du mois (lancement par supercronic) : vérification intégrale des empreintes
[ "$(date +%d)" = "01" ] && FULL_CHECK=1

START=$(date +%s)
DB="${ERP_DB_NAME:-ostral}"
MIN_TABLES="${RESTORE_MIN_TABLES:-50}"
MAX_GAP="${RESTORE_MAX_ORDER_GAP:-1000}"
WORK="$SCRATCH/restore-test.$$"
PGDATA="$WORK/pgdata"
SOCK="$WORK/sock"
DUMP="$WORK/erp.dump"
TEST_DB=restore_test

cleanup() {
  if [ -f "$PGDATA/postmaster.pid" ]; then
    "$PG_BIN/pg_ctl" -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
  log_json restore-test ECHEC "$1" "duration_s=$(( $(date +%s) - START ))" ${2:+"$2"} ${3:+"$3"}
  exit 1
}

mkdir -p "$WORK" "$SOCK" && chmod 0700 "$WORK" "$SOCK" || fail "espace de travail inaccessible"

# --- 1. Extraction du dernier dump ERP depuis le dépôt chiffré ------------------------------
SNAP_ID="$(restic snapshots --json --tag erp-db $([ "$SNAPSHOT" = latest ] && echo --latest 1) 2>/dev/null \
  | jq -r 'if length>0 then .[-1].short_id else empty end')"
[ "$SNAPSHOT" != latest ] && SNAP_ID="$SNAPSHOT"
[ -n "$SNAP_ID" ] || fail "aucune sauvegarde erp-db dans le dépôt"
SNAP_TIME="$(restic snapshots --json "$SNAP_ID" 2>/dev/null | jq -r '.[0].time // empty' | cut -c1-19)"
info "restauration du snapshot $SNAP_ID ($SNAP_TIME)"
restic dump "$SNAP_ID" "/erp-$DB.dump" > "$DUMP" 2>"$WORK/dump.err" \
  || fail "restic dump impossible ($(tail -n1 "$WORK/dump.err"))" "snapshot=$SNAP_ID"
[ -s "$DUMP" ] || fail "dump vide" "snapshot=$SNAP_ID"
DUMP_SHA="$(sha256sum "$DUMP" | cut -c1-16)"

# --- 2. PostgreSQL temporaire isolé (aucune écoute TCP) ----------------------------------------
"$PG_BIN/initdb" -D "$PGDATA" -U postgres --auth=trust -E UTF8 --no-locale >"$WORK/initdb.log" 2>&1 \
  || fail "initdb en échec"
"$PG_BIN/pg_ctl" -D "$PGDATA" -w -t 60 -l "$WORK/pg.log" \
  -o "-c listen_addresses='' -c unix_socket_directories='$SOCK' -c fsync=off -c max_connections=10" start \
  >/dev/null 2>&1 || fail "démarrage du PostgreSQL de test impossible"
PSQL="$PG_BIN/psql -X -q -t -A -h $SOCK -U postgres"

$PSQL -d postgres -c "CREATE DATABASE $TEST_DB" >/dev/null || fail "création de la base de test impossible"

# --- 3. Restauration (sans propriétaires ni droits : rôles de prod absents par conception) -----
if ! "$PG_BIN/pg_restore" -h "$SOCK" -U postgres -d "$TEST_DB" --no-owner --no-privileges \
       --exit-on-error "$DUMP" >"$WORK/restore.log" 2>&1; then
  fail "pg_restore en erreur : $(tail -n 2 "$WORK/restore.log" | tr '\n' ' ')" "snapshot=$SNAP_ID"
fi

# --- 4. Vérifications de cohérence -----------------------------------------------------------
TABLES="$($PSQL -d "$TEST_DB" -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
case "$TABLES" in ''|*[!0-9]*) fail "base restaurée illisible" "snapshot=$SNAP_ID" ;; esac
[ "$TABLES" -ge "$MIN_TABLES" ] || fail "trop peu de tables restaurées ($TABLES < $MIN_TABLES)" "snapshot=$SNAP_ID" "tables=$TABLES"

HAS_SO="$($PSQL -d "$TEST_DB" -c "SELECT to_regclass('public.sale_order') IS NOT NULL")"
[ "$HAS_SO" = "t" ] || fail "table sale_order absente de la sauvegarde" "snapshot=$SNAP_ID" "tables=$TABLES"
ORDERS="$($PSQL -d "$TEST_DB" -c "SELECT count(*) FROM sale_order")"

# Comparaison avec la production (lecture seule, rôle backup_ro) : la sauvegarde ne peut pas
# contenir PLUS de commandes que la prod, et l'écart doit rester plausible (RPO 1 h).
PROD_ORDERS="$(PGPASSWORD="${ERP_DB_BACKUP_PASSWORD:-}" PGCONNECT_TIMEOUT=10 "$PG_BIN/psql" -X -q -t -A \
  -h "${ERP_DB_HOST:-erp-db}" -p "${ERP_DB_PORT:-5432}" -U "${ERP_DB_BACKUP_USER:-backup_ro}" -d "$DB" \
  -c "SELECT count(*) FROM sale_order" 2>/dev/null || true)"
case "$PROD_ORDERS" in
  ''|*[!0-9]*)
    PROD_ORDERS=-1
    info "production injoignable : comparaison des commandes ignorée" ;;
  *)
    [ "$ORDERS" -le "$PROD_ORDERS" ] \
      || fail "incohérence : $ORDERS commandes restaurées > $PROD_ORDERS en production" "tables=$TABLES" "orders=$ORDERS"
    [ $((PROD_ORDERS - ORDERS)) -le "$MAX_GAP" ] \
      || fail "écart de commandes trop important ($ORDERS restaurées / $PROD_ORDERS en prod)" "tables=$TABLES" "orders=$ORDERS" ;;
esac

# --- 5. Intégrité du dépôt (« 0 erreur ») -----------------------------------------------------
if [ "$FULL_CHECK" = 1 ]; then
  restic check --read-data >&2 || fail "restic check --read-data : erreur d'empreinte dans le dépôt" "tables=$TABLES" "orders=$ORDERS"
  CHECK=full
else
  restic check >&2 || fail "restic check : dépôt incohérent" "tables=$TABLES" "orders=$ORDERS"
  CHECK=structure
fi

DUR=$(( $(date +%s) - START ))
log_json restore-test OK "restauration ERP vérifiée : $TABLES tables, $ORDERS commandes (prod : $PROD_ORDERS), snapshot du $SNAP_TIME" \
  "snapshot=$SNAP_ID" "dump_sha256=$DUMP_SHA" "tables=$TABLES" "orders=$ORDERS" "prod_orders=$PROD_ORDERS" \
  "check=$CHECK" "duration_s=$DUR"
info "test de restauration OK en ${DUR}s (objectif RTO ERP : 8 h)"
exit 0
