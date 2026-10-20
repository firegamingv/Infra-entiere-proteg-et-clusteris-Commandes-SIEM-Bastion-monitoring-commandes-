#!/bin/sh
# OSTRAL — sauvegarde NOCTURNE (3-2-1-1-0, E09) :
#  1. pull SSH en lecture seule de /srv/data sur admin-target (F16, clé dédiée, compte backup-ro
#     à commande forcée côté serveur : « export » => archive tar de /srv/data sur stdout) ;
#  2. filestore Odoo (volume odoo_data monté en lecture seule — écart maquette documenté) ;
#  3. archives Wazuh (/var/ossec/logs/archives, E08) : 12 mois de journaux non effaçables ;
#  4. rétention : 48 horaires, 30 quotidiennes, 12 mensuelles (p. 11) ;
#  5. « 0 erreur » : restic check + relecture d'un échantillon des données (empreintes SHA-256) ;
#  6. copie vers le stockage objet verrouillé (F17).
set -u
. /usr/local/bin/lib.sh

FAILED=0
fail() { FAILED=$((FAILED + 1)); }

# --- 1. admin-target (compte backup-ro, commande forcée backup-ro.sh du lot D) --------------
T=$(date +%s)
SSH_TARGET="${BACKUP_SSH_USER:-backup-ro}@${BACKUP_SSH_HOST:-10.10.3.30}"
SRC_PATH="${BACKUP_SSH_PATH:-/srv/data}"
REMOTE_CMD="${BACKUP_SSH_COMMAND:-export}"
# shellcheck disable=SC2046  # découpage voulu des options SSH
if SNAP="$(restic_backup_json --tag admin-target --tag nightly \
      --stdin-from-command --stdin-filename "admin-target-srv-data.tar" -- \
      ssh $(ssh_opts) "$SSH_TARGET" "$REMOTE_CMD")"; then
  log_json admin-target OK "pull SSH de $SRC_PATH sur admin-target (snapshot $SNAP)" \
    "snapshot=$SNAP" "duration_s=$(( $(date +%s) - T ))"
else
  log_json admin-target ECHEC "pull SSH de $SRC_PATH sur $SSH_TARGET impossible (BACKUP_SSH_PUBKEY autorisée ?)"
  fail
fi

# --- 2. Filestore Odoo -----------------------------------------------------------------------
T=$(date +%s)
if [ -d /mnt/odoo-data/filestore ]; then
  if SNAP="$(restic_backup_json --tag odoo-filestore --tag nightly /mnt/odoo-data/filestore)"; then
    log_json odoo-filestore OK "filestore Odoo sauvegardé (snapshot $SNAP)" "snapshot=$SNAP" \
      "duration_s=$(( $(date +%s) - T ))"
  else
    log_json odoo-filestore ECHEC "filestore Odoo illisible ou sauvegarde incomplète"
    fail
  fi
else
  log_json odoo-filestore OK "aucun filestore Odoo (pas encore de pièce jointe) : rien à sauvegarder"
fi

# --- 3. Archives Wazuh (si le profil siem a tourné) ------------------------------------------
T=$(date +%s)
if [ -d /mnt/wazuh-logs/archives ] && [ -n "$(ls -A /mnt/wazuh-logs/archives 2>/dev/null)" ]; then
  if SNAP="$(restic_backup_json --tag wazuh-archives --tag nightly /mnt/wazuh-logs/archives)"; then
    log_json wazuh-archives OK "archives SIEM copiées vers le stockage verrouillé (snapshot $SNAP)" \
      "snapshot=$SNAP" "duration_s=$(( $(date +%s) - T ))"
  else
    log_json wazuh-archives ECHEC "lecture des archives Wazuh impossible (group_add 999 ? volume wazuh_logs)"
    fail
  fi
else
  info "archives Wazuh absentes (profil siem inactif) : étape ignorée"
fi

# --- 4. Rétention (p. 11) ; archives SIEM : 12 mensuelles = 12 mois (E08) --------------------
T=$(date +%s)
if restic forget --host ostral-backup --group-by host,tags \
     --keep-hourly 48 --keep-daily 30 --keep-monthly 12 --prune >&2; then
  log_json retention OK "rétention appliquée : 48 horaires, 30 quotidiennes, 12 mensuelles" \
    "duration_s=$(( $(date +%s) - T ))"
else
  log_json retention ECHEC "restic forget/prune en échec"
  fail
fi

# --- 5. Vérification « 0 erreur » : structure + relecture de 10 % des paquets ----------------
T=$(date +%s)
if restic check --read-data-subset 10% >&2; then
  log_json check OK "restic check : structure et empreintes de 10 % des paquets vérifiées" \
    "duration_s=$(( $(date +%s) - T ))"
else
  log_json check ECHEC "restic check a détecté une erreur dans le dépôt"
  fail
fi

# --- 6. Copie hors site ----------------------------------------------------------------------
T=$(date +%s)
if offsite_mirror; then
  log_json offsite OK "dépôt copié vers le stockage objet verrouillé" \
    "local_files=$OFFSITE_LOCAL_FILES" "remote_files=$OFFSITE_REMOTE_FILES" \
    "duration_s=$(( $(date +%s) - T ))"
else
  log_json offsite ECHEC "copie hors site impossible ou incomplète (minio-offsite)" \
    "local_files=$OFFSITE_LOCAL_FILES" "remote_files=$OFFSITE_REMOTE_FILES"
  fail
fi

if [ "$FAILED" -eq 0 ]; then
  log_json nightly OK "sauvegarde nocturne complète"
  kuma_push "${UPTIME_KUMA_PUSH_NIGHTLY:-}" up "OK sauvegarde nocturne"
  exit 0
fi
log_json nightly ECHEC "sauvegarde nocturne : $FAILED étape(s) en échec" "failed_steps=$FAILED"
kuma_push "${UPTIME_KUMA_PUSH_NIGHTLY:-}" down "ECHEC sauvegarde nocturne ($FAILED étape(s))"
exit 1
