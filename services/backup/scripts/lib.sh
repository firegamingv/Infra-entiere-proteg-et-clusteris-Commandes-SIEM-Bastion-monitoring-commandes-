#!/bin/sh
# OSTRAL — fonctions communes du serveur de sauvegarde (sourcé par les autres scripts).
# Journal : une ligne JSON par tâche dans /var/log/backup/backup.json (volume logs_backup),
# lue par Wazuh (règles 100700-100703 : status=ECHEC => niveau 12, SMS d'astreinte).

LOG_FILE="${BACKUP_LOG_FILE:-/var/log/backup/backup.json}"
SSH_DIR="${BACKUP_SSH_DIR:-/var/lib/backup/ssh}"
SSH_KEY="$SSH_DIR/id_ed25519"
SCRATCH="${BACKUP_SCRATCH:-/var/lib/backup/scratch}"
HOST_TAG="ostral-backup"

# Binaires PostgreSQL 16 d'Alpine (initdb, pg_ctl, postgres, pg_dump, pg_restore, psql)
if [ -d /usr/libexec/postgresql16 ]; then
  PG_BIN=/usr/libexec/postgresql16
else
  PG_BIN="$(dirname "$(command -v pg_dump)")"
fi
export PG_BIN

now_iso() { date -Iseconds; }

info() { printf '[%s] %s\n' "$(now_iso)" "$*" >&2; }

# log_json JOB STATUS MESSAGE [clé=valeur ...]  (valeur numérique si entière)
log_json() {
  _job="$1"; _status="$2"; _msg="$3"; shift 3
  _line="$(jq -nc --arg ts "$(now_iso)" --arg job "$_job" --arg status "$_status" --arg msg "$_msg" \
      '{"@timestamp":$ts, service:"backup", zone:"Z7", job:$job, status:$status, message:$msg}')"
  for kv in "$@"; do
    _k="${kv%%=*}"; _v="${kv#*=}"
    case "$_v" in
      ''|*[!0-9]*) _line="$(printf '%s' "$_line" | jq -c --arg k "$_k" --arg v "$_v" '. + {($k): $v}')" ;;
      *)           _line="$(printf '%s' "$_line" | jq -c --arg k "$_k" --argjson v "$_v" '. + {($k): $v}')" ;;
    esac
  done
  printf '%s\n' "$_line" >> "$LOG_FILE" 2>/dev/null || info "journal $LOG_FILE non inscriptible"
  printf '%s\n' "$_line"
}

# Notification « push » vers Uptime Kuma : une sauvegarde absente déclenche l'alerte (p. 12)
kuma_push() { # kuma_push URL up|down MESSAGE
  [ -n "${1:-}" ] || return 0
  _m="$(printf '%s' "$3" | jq -sRr @uri)"
  wget -q -T 10 -O /dev/null "$1?status=$2&msg=$_m&ping=" 2>/dev/null || info "push Uptime Kuma impossible"
}

# restic backup en sortie JSON : affiche l'identifiant court du snapshot créé
restic_backup_json() {
  _out="$SCRATCH/restic-out.$$"
  _rc=0
  restic backup --json --host "$HOST_TAG" "$@" > "$_out" 2> "$_out.err" || _rc=$?
  _snap="$(jq -r 'select(.message_type=="summary") | .snapshot_id[0:8]' "$_out" 2>/dev/null | tail -n 1)"
  # « 0 erreur » : un code retour nul SANS identifiant de snapshot est aussi un échec
  if [ "$_rc" -eq 0 ] && [ -n "$_snap" ]; then
    echo "$_snap"
    rm -f "$_out" "$_out.err"
    return 0
  fi
  tail -n 5 "$_out.err" >&2
  rm -f "$_out" "$_out.err"
  [ "$_rc" -ne 0 ] || _rc=1
  return "$_rc"
}

# Options SSH du pull F16 (clé dédiée, aucune saisie, empreinte serveur mémorisée au 1er contact)
ssh_opts() {
  echo "-i $SSH_KEY -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=15" \
       "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SSH_DIR/known_hosts" \
       "-o ServerAliveInterval=30 -o LogLevel=ERROR"
}

# F17 : copie du dépôt restic (chiffré côté client) vers le bucket verrouillé (Object Lock).
# Clé d'accès en ÉCRITURE SEULE : PutObject + List, aucune suppression ni écrasement.
# mirror sans --overwrite ni --remove : les fichiers restic sont nommés par leur empreinte
# (immuables) ; le bucket est donc un sur-ensemble du dépôt local, lisible tel quel par restic.
offsite_mirror() {
  : "${MINIO_BACKUP_ACCESS_KEY:?MINIO_BACKUP_ACCESS_KEY manquant}"
  : "${MINIO_BACKUP_SECRET_KEY:?MINIO_BACKUP_SECRET_KEY manquant}"
  _ep="${OFFSITE_ENDPOINT:-http://minio-offsite:9000}"
  _bucket="${OFFSITE_BUCKET:-ostral-backup-offsite}"
  _scheme="${_ep%%://*}"; _hostport="${_ep#*://}"
  # Alias par variable d'environnement : le secret n'apparaît ni en argument ni sur disque
  MC_HOST_offsite="$_scheme://$MINIO_BACKUP_ACCESS_KEY:$MINIO_BACKUP_SECRET_KEY@$_hostport"
  export MC_HOST_offsite
  _cfg="/tmp/.mcli"
  OFFSITE_LOCAL_FILES=0; OFFSITE_REMOTE_FILES=0
  # --md5 : en-tête Content-MD5 exigé par MinIO pour les écritures dans un bucket verrouillé
  mcli --config-dir "$_cfg" --quiet --no-color mirror --md5 \
       --exclude "locks/*" /repo "offsite/$_bucket/restic" >&2 || return 1
  # Contrôle « 0 erreur » : chaque fichier local (hors verrous) est présent hors site
  OFFSITE_LOCAL_FILES="$(find /repo -type f ! -path '/repo/locks/*' | wc -l | tr -d ' ')"
  OFFSITE_REMOTE_FILES="$(mcli --config-dir "$_cfg" --quiet --no-color ls --recursive \
       "offsite/$_bucket/restic" | wc -l | tr -d ' ')"
  [ "$OFFSITE_REMOTE_FILES" -ge "$OFFSITE_LOCAL_FILES" ]
}

restic_init_if_needed() {
  if ! restic cat config >/dev/null 2>&1; then
    info "initialisation du dépôt restic chiffré dans $RESTIC_REPOSITORY"
    restic init
  fi
}
