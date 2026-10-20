#!/bin/sh
# OSTRAL — sauvegarde HORAIRE (RPO ERP = 1 h, dossier p. 10) :
#  1. pg_dump de la base ERP depuis erp-db:5432 avec le rôle lecture seule backup_ro (F16, mode
#     pull : le serveur de sauvegarde va chercher les données ; la base n'accède jamais au dépôt) ;
#  2. envoi dans le dépôt restic chiffré (2e copie, disques de Z7) ;
#  3. copie incrémentale vers le stockage objet verrouillé hors site (3e copie, F17, Object Lock).
set -u
. /usr/local/bin/lib.sh

START=$(date +%s)
DB="${ERP_DB_NAME:-ostral}"
PGPASSWORD="${ERP_DB_BACKUP_PASSWORD:?ERP_DB_BACKUP_PASSWORD manquant}"
PGCONNECT_TIMEOUT=15
export PGPASSWORD PGCONNECT_TIMEOUT

# --- 1+2. Base ERP ---------------------------------------------------------------------------
# --stdin-from-command : le snapshot est refusé si pg_dump échoue (pas de sauvegarde tronquée)
if SNAP="$(restic_backup_json --tag erp-db --tag hourly \
      --stdin-from-command --stdin-filename "erp-$DB.dump" -- \
      "$PG_BIN/pg_dump" -h "${ERP_DB_HOST:-erp-db}" -p "${ERP_DB_PORT:-5432}" \
      -U "${ERP_DB_BACKUP_USER:-backup_ro}" -d "$DB" --no-password -Fc -Z 0)"; then
  log_json erp-db OK "dump ERP $DB sauvegardé (snapshot $SNAP)" "snapshot=$SNAP" \
    "duration_s=$(( $(date +%s) - START ))"
  ERP_OK=1
else
  log_json erp-db ECHEC "pg_dump ou restic en échec pour la base $DB sur ${ERP_DB_HOST:-erp-db}" \
    "duration_s=$(( $(date +%s) - START ))"
  ERP_OK=0
fi

# --- 3. Copie hors site (même en cas d'échec du dump : on pousse ce qui existe) ----------------
T1=$(date +%s)
if offsite_mirror; then
  log_json offsite OK "dépôt copié vers le stockage objet verrouillé" \
    "local_files=$OFFSITE_LOCAL_FILES" "remote_files=$OFFSITE_REMOTE_FILES" \
    "duration_s=$(( $(date +%s) - T1 ))"
  OFF_OK=1
else
  log_json offsite ECHEC "copie hors site impossible ou incomplète (minio-offsite)" \
    "local_files=$OFFSITE_LOCAL_FILES" "remote_files=$OFFSITE_REMOTE_FILES"
  OFF_OK=0
fi

if [ "$ERP_OK" = 1 ] && [ "$OFF_OK" = 1 ]; then
  kuma_push "${UPTIME_KUMA_PUSH_HOURLY:-}" up "OK erp-db + hors site"
  exit 0
fi
kuma_push "${UPTIME_KUMA_PUSH_HOURLY:-}" down "ECHEC sauvegarde horaire (erp=$ERP_OK hors-site=$OFF_OK)"
exit 1
