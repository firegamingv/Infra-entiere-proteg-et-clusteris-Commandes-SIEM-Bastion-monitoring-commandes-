#!/bin/sh
# =============================================================================
# OSTRAL — lot D — commande forcée du compte backup-ro (F16 : sauvegarde en mode pull,
# compte en LECTURE SEULE). Appelée par sshd (ForceCommand + command= dans authorized_keys).
#
# Commandes acceptées (variable SSH_ORIGINAL_COMMAND) :
#   (vide) | export | tar          -> archive tar de /srv/data sur la sortie standard
#                                     ex. : ssh backup-ro@10.10.3.30 export > admin-target.tar
#   rsync --server --sender ...    -> rsync en mode ÉMETTEUR uniquement (lecture), chemins
#                                     limités à /srv/data
#                                     ex. : rsync -a backup-ro@10.10.3.30:/srv/data/ ./admin-target/
# Toute autre commande est refusée et journalisée (auth.log -> SIEM).
# Le compte n'a de toute façon aucun droit d'écriture sur /srv/data (root:root, lecture seule)
# et le système de fichiers racine du conteneur est en lecture seule.
# =============================================================================
set -eu

DATA=/srv/data
CMD="${SSH_ORIGINAL_COMMAND:-}"
SRC="${SSH_CLIENT%% *}"

journal() { logger -p auth.notice -t backup-ro "$*" 2>/dev/null || true; }
refuser() {
  journal "REFUS source=${SRC:-?} commande=\"$CMD\" motif=$1"
  echo "backup-ro : commande refusée ($1)" >&2
  exit 1
}

case "$CMD" in
  ""|export|tar)
    journal "EXPORT tar source=${SRC:-?} chemin=$DATA"
    exec tar -C "$DATA" -cf - .
    ;;
  "rsync --server --sender "*)
    # Pas de métacaractères (la commande n'est jamais passée à un shell, défense en profondeur).
    case "$CMD" in
      *[\;\&\|\`\$\<\>\\]*|*..*) refuser "caracteres_interdits" ;;
    esac
    set -f
    # shellcheck disable=SC2086
    set -- $CMD
    shift 3   # rsync --server --sender
    for arg in "$@"; do
      case "$arg" in
        .) ;;
        "$DATA"|"$DATA"/*) ;;
        --*) refuser "option_longue_interdite:$arg" ;;   # ex. --remove-source-files, --log-file
        -[A-Za-z0-9.]*) ;;                             # options courtes groupées (-logDtpre.iLsfxC)
        *) refuser "chemin_hors_perimetre:$arg" ;;
      esac
    done
    journal "EXPORT rsync source=${SRC:-?} commande=\"$CMD\""
    # shellcheck disable=SC2086
    exec $CMD
    ;;
  *)
    refuser "commande_non_autorisee"
    ;;
esac
