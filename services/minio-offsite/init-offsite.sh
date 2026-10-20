#!/bin/bash
# OSTRAL — initialisation du stockage objet hors site (F17, E09, règle « 1 copie non modifiable »).
#  1. bucket créé AVEC verrouillage d'objets (Object Lock => versionnage obligatoire) ;
#  2. rétention par défaut COMPLIANCE 30 jours : aucun compte, même root, ne peut effacer ni
#     écraser une version avant 30 jours (dossier p. 11 : « même un administrateur ne peut pas ») ;
#  3. compte « backup » à clé d'accès en ÉCRITURE SEULE (PutObject + List, Delete* refusés).
# Le chiffrement est fait côté client par restic avant l'envoi (F17).
# Idempotent : rejouable avec « docker compose up minio-offsite-init ».
set -euo pipefail

: "${MINIO_ROOT_USER:?}" "${MINIO_ROOT_PASSWORD:?}"
: "${MINIO_BACKUP_ACCESS_KEY:?}" "${MINIO_BACKUP_SECRET_KEY:?}"
BUCKET="${OFFSITE_BUCKET:-ostral-backup-offsite}"
MODE="${OFFSITE_RETENTION_MODE:-COMPLIANCE}"
DAYS="${OFFSITE_RETENTION_DAYS:-30}"
POLICY_NAME="ostral-backup-writeonly"
POLICY_SRC=/ostral/policy-backup-writeonly.json

MC="$(command -v mc || echo /opt/bitnami/minio-client/bin/mc)"
mcx() { "$MC" --config-dir /tmp/.mc --quiet --no-color "$@"; }

if [ "${#MINIO_BACKUP_SECRET_KEY}" -lt 8 ] || [[ "$MINIO_BACKUP_SECRET_KEY" == CHANGEME* ]]; then
  echo "[offsite] MINIO_BACKUP_SECRET_KEY trop court ou valeur d'exemple" >&2
  exit 1
fi

# Alias root via variable d'environnement (secret absent de la ligne de commande)
export MC_HOST_offsite="http://${MINIO_ROOT_USER}:${MINIO_ROOT_PASSWORD}@minio-offsite:9000"

echo "[offsite] attente de minio-offsite..."
for _ in $(seq 1 30); do
  mcx ready offsite >/dev/null 2>&1 && break
  sleep 2
done
mcx ready offsite >/dev/null

# 1. Bucket verrouillé (le verrouillage ne peut être activé qu'à la création)
if mcx ls "offsite/$BUCKET" >/dev/null 2>&1; then
  echo "[offsite] bucket $BUCKET déjà présent"
else
  mcx mb --with-lock "offsite/$BUCKET"
  echo "[offsite] bucket $BUCKET créé avec Object Lock"
fi

# 2. Rétention par défaut (s'applique à chaque nouvelle version d'objet) ; échoue si le bucket
#    n'a pas été créé avec --with-lock
if ! mcx retention set --default "$MODE" "${DAYS}d" "offsite/$BUCKET"; then
  echo "[offsite] ERREUR : Object Lock non actif sur $BUCKET (bucket créé sans --with-lock ?)" >&2
  exit 1
fi
if ! mcx retention info --default "offsite/$BUCKET" | grep -qi "$MODE"; then
  echo "[offsite] ERREUR : rétention par défaut $MODE non confirmée" >&2
  exit 1
fi
echo "[offsite] rétention par défaut : $MODE ${DAYS} jours"

# 3. Politique d'écriture seule, adaptée au nom du bucket
sed "s/__BUCKET__/$BUCKET/g" "$POLICY_SRC" > /tmp/policy.json
mcx admin policy create offsite "$POLICY_NAME" /tmp/policy.json
mcx admin user add offsite "$MINIO_BACKUP_ACCESS_KEY" "$MINIO_BACKUP_SECRET_KEY"
if ! mcx admin policy entities offsite --user "$MINIO_BACKUP_ACCESS_KEY" 2>/dev/null | grep -q "$POLICY_NAME"; then
  mcx admin policy attach offsite "$POLICY_NAME" --user "$MINIO_BACKUP_ACCESS_KEY"
fi
echo "[offsite] compte $MINIO_BACKUP_ACCESS_KEY : politique $POLICY_NAME (écriture seule)"

# Contrôle : le compte backup ne doit PAS pouvoir supprimer (attendu : refus)
export MC_HOST_bk="http://${MINIO_BACKUP_ACCESS_KEY}:${MINIO_BACKUP_SECRET_KEY}@minio-offsite:9000"
echo "ostral-test $(date -u +%FT%TZ)" > /tmp/probe.txt
mcx cp --md5 /tmp/probe.txt "bk/$BUCKET/_probe/probe.txt" >/dev/null
if mcx rm "bk/$BUCKET/_probe/probe.txt" >/dev/null 2>&1; then
  # Un « rm » sans version ne fait qu'ajouter un marqueur ; on vérifie surtout la version verrouillée
  echo "[offsite] ATTENTION : suppression acceptée pour le compte backup (vérifier la politique)" >&2
  exit 1
fi
echo "[offsite] OK : écriture autorisée, suppression refusée pour le compte de sauvegarde"
