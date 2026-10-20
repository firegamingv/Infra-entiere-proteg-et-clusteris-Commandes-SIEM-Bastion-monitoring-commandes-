#!/usr/bin/env bash
# =============================================================================
# OSTRAL — Scan des images et de la configuration avant déploiement (E12)
# Lot F — « Scan Trivy avant tout déploiement ; blocage si vulnérabilité
# critique » (dossier d'architecture, page 13 : « Oui (commande fournie) »).
#
# 1. Vulnérabilités : chaque image du projet (`docker compose config --images`)
#    est analysée avec
#       trivy image --severity CRITICAL --exit-code 1 --ignore-unfixed
#    (profils siem et demo inclus : images officielles ET images construites
#    localement « ostral/* » — boutique, psp-mock, waf, erp-db, samba-ad,
#    wireguard, admin-target, poste, backup, bastion-demo — à construire avant)
#    -> le script sort en code 1 (déploiement BLOQUÉ) si une vulnérabilité
#       critique corrigeable est présente dans au moins une image.
# 2. Mauvaises configurations : `trivy config` sur les Dockerfiles (services/)
#    et les fragments compose (compose/) — informatif, bloquant avec
#    STRICT_CONFIG=1 (HIGH/CRITICAL).
# 3. Contrôles maison du compose fusionné (Trivy n'analyse pas le format
#    Compose) : tags « latest », socket Docker, no-new-privileges.
#
# Trivy : binaire local s'il existe, sinon conteneur aquasec/trivy (tag fixé)
# avec cache dans un volume nommé. En mode conteneur, les images sont passées
# par `docker save` (archive tar) : le socket Docker n'est JAMAIS monté, même
# pour l'outil de scan (cohérence avec la règle de durcissement).
#
# Usage   : bash scripts/trivy-scan.sh [image ...]   (défaut : images du projet)
# Options : TRIVY_IMAGE=aquasec/trivy:0.56.2  SEVERITE=CRITICAL
#           STRICT_CONFIG=1  NO_COLOR=1
# Rapports : reports/trivy-<horodatage>/ (un fichier par image + synthèse)
# Code de retour : 0 conforme, 1 bloqué (vulnérabilité critique ou contrôle
#                  bloquant en échec), 2 erreur d'exécution / prérequis.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE" || exit 2
export MSYS_NO_PATHCONV=1
RACINE_HOTE="$(pwd -W 2>/dev/null || pwd)"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.56.2}"
TRIVY_CACHE_VOL="${TRIVY_CACHE_VOL:-ostral_trivy_cache}"
SEVERITE="${SEVERITE:-CRITICAL}"
STRICT_CONFIG="${STRICT_CONFIG:-0}"
HORODATAGE="$(date '+%Y%m%d-%H%M%S')"
DOSSIER_RAPPORT="reports/trivy-$HORODATAGE"
SYNTHESE="$DOSSIER_RAPPORT/synthese.txt"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  VERT=$'\e[32m'; ROUGE=$'\e[31m'; JAUNE=$'\e[33m'; GRIS=$'\e[90m'; GRAS=$'\e[1m'; RAZ=$'\e[0m'
else
  VERT=""; ROUGE=""; JAUNE=""; GRIS=""; GRAS=""; RAZ=""
fi

command -v docker >/dev/null 2>&1 || { echo "${ROUGE}Docker est requis.${RAZ}" >&2; exit 2; }
mkdir -p "$DOSSIER_RAPPORT" || exit 2
: > "$SYNTHESE"
# Affiche en couleur et écrit la même ligne, sans couleur, dans la synthèse
log() { local coul="$1"; shift; printf '%s%s%s\n' "$coul" "$*" "$RAZ"; printf '%s\n' "$*" >> "$SYNTHESE"; }

# --- Choix du moteur Trivy ---------------------------------------------------
if command -v trivy >/dev/null 2>&1; then
  MOTEUR="local"
  log "$GRIS" "Moteur : binaire local ($(trivy --version 2>/dev/null | head -n1))"
else
  MOTEUR="conteneur"
  log "$GRIS" "Moteur : conteneur $TRIVY_IMAGE (cache : volume $TRIVY_CACHE_VOL)"
  docker image inspect "$TRIVY_IMAGE" >/dev/null 2>&1 || docker pull -q "$TRIVY_IMAGE" >/dev/null \
    || { log "$ROUGE" "Impossible de télécharger $TRIVY_IMAGE"; exit 2; }
fi

# trivy_run ARGS... : exécute trivy ; en mode conteneur, le projet est monté
# en lecture seule sur /projet et les rapports sur /rapports.
trivy_run() {
  if [ "$MOTEUR" = "local" ]; then
    trivy "$@"
  else
    docker run --rm \
      -v "$TRIVY_CACHE_VOL:/root/.cache/" \
      -v "$RACINE_HOTE:/projet:ro" \
      -v "$RACINE_HOTE/$DOSSIER_RAPPORT:/rapports" \
      "$TRIVY_IMAGE" "$@"
  fi
}
# Chemins vus par trivy selon le moteur
chemin_projet()  { if [ "$MOTEUR" = "local" ]; then printf '%s' "$RACINE/$1"; else printf '/projet/%s' "$1"; fi; }
chemin_rapport() { if [ "$MOTEUR" = "local" ]; then printf '%s' "$RACINE/$DOSSIER_RAPPORT/$1"; else printf '/rapports/%s' "$1"; fi; }

# --- Liste des images --------------------------------------------------------
if [ "$#" -gt 0 ]; then
  IMAGES=("$@")
else
  mapfile -t IMAGES < <(docker compose --profile siem --profile demo config --images 2>/dev/null | tr -d '\r' | sort -u)
fi
if [ "${#IMAGES[@]}" -eq 0 ]; then
  log "$ROUGE" "Aucune image trouvée (docker compose config --images). Vérifier .env / COMPOSE_FILE."
  exit 2
fi

printf '\n'; log "$GRAS" "== 1. Vulnérabilités ($SEVERITE, corrigeables) — ${#IMAGES[@]} image(s) =="
NB_BLOQUEES=0; NB_ERREURS=0; NB_SAINES=0
for img in "${IMAGES[@]}"; do
  [ -n "$img" ] || continue
  nom_fichier="$(printf '%s' "$img" | tr '/:@' '___')"
  # Image présente localement ? sinon pull (images officielles) ; les images
  # construites localement doivent l'être avant : docker compose build
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    if ! docker pull -q "$img" >/dev/null 2>&1; then
      log "$JAUNE" "  [ERREUR]  $img : image introuvable (lancer « docker compose --profile siem --profile demo build » d'abord)"
      NB_ERREURS=$((NB_ERREURS + 1)); continue
    fi
  fi
  opts=(image --severity "$SEVERITE" --exit-code 1 --ignore-unfixed --scanners vuln
        --no-progress --format table --output "$(chemin_rapport "$nom_fichier.txt")")
  if [ "$MOTEUR" = "local" ]; then
    trivy_run "${opts[@]}" "$img" >/dev/null 2>"$DOSSIER_RAPPORT/$nom_fichier.err"; rc=$?
  else
    # Export de l'image en archive (pas de socket Docker dans le conteneur Trivy)
    archive="$DOSSIER_RAPPORT/.$nom_fichier.tar"
    if ! docker save -o "$archive" "$img" 2>/dev/null; then
      log "$JAUNE" "  [ERREUR]  $img : docker save impossible"; NB_ERREURS=$((NB_ERREURS + 1)); continue
    fi
    trivy_run "${opts[@]}" --input "/rapports/.$nom_fichier.tar" >/dev/null 2>"$DOSSIER_RAPPORT/$nom_fichier.err"; rc=$?
    rm -f "$archive"
  fi
  case "$rc" in
    0) log "$VERT"  "  [OK]      $img"; NB_SAINES=$((NB_SAINES + 1)); rm -f "$DOSSIER_RAPPORT/$nom_fichier.err" ;;
    1) n="$(grep -c '│ CRITICAL' "$DOSSIER_RAPPORT/$nom_fichier.txt" 2>/dev/null || true)"
       log "$ROUGE" "  [BLOQUÉ]  $img : ${n:-?} vulnérabilité(s) $SEVERITE — $DOSSIER_RAPPORT/$nom_fichier.txt"
       NB_BLOQUEES=$((NB_BLOQUEES + 1)) ;;
    *) log "$JAUNE" "  [ERREUR]  $img : code $rc — voir $DOSSIER_RAPPORT/$nom_fichier.err"
       NB_ERREURS=$((NB_ERREURS + 1)) ;;
  esac
done

# --- 2. Mauvaises configurations (Dockerfiles) -------------------------------
printf '\n'; log "$GRAS" "== 2. Mauvaises configurations (trivy config : services/, compose/) =="
RC_CONFIG=0
code_sortie_cfg=0; [ "$STRICT_CONFIG" = "1" ] && code_sortie_cfg=1
for cible in services compose; do
  [ -d "$cible" ] || { log "$GRIS" "  [IGNORÉ]  $cible/ absent"; continue; }
  trivy_run config --severity HIGH,CRITICAL --exit-code "$code_sortie_cfg" \
    --format table --output "$(chemin_rapport "config-$cible.txt")" \
    "$(chemin_projet "$cible")" >/dev/null 2>"$DOSSIER_RAPPORT/config-$cible.err"; rc=$?
  case "$rc" in
    0) log "$VERT"  "  [OK]      $cible/ (rapport : $DOSSIER_RAPPORT/config-$cible.txt)"
       rm -f "$DOSSIER_RAPPORT/config-$cible.err" ;;
    1) log "$ROUGE" "  [BLOQUÉ]  $cible/ : mauvaise(s) configuration(s) HIGH/CRITICAL"; RC_CONFIG=1 ;;
    *) log "$JAUNE" "  [ERREUR]  $cible/ : code $rc — voir $DOSSIER_RAPPORT/config-$cible.err"; NB_ERREURS=$((NB_ERREURS + 1)) ;;
  esac
done
log "$GRIS" "  Note : Trivy analyse les Dockerfiles ; le format Compose est contrôlé ci-dessous."

# --- 3. Contrôles du compose fusionné (règles E12 du SPEC) -------------------
printf '\n'; log "$GRAS" "== 3. Durcissement déclaré dans le compose fusionné =="
RC_COMPOSE=0
if config="$(docker compose --profile siem --profile demo config 2>/dev/null | tr -d '\r')"; then
  # Images sans tag ou en « latest »
  sans_tag="$(printf '%s\n' "${IMAGES[@]}" | grep -Ev '@sha256:' | grep -E '(:latest$|^[^:]+$)' || true)"
  if [ -n "$sans_tag" ]; then
    log "$ROUGE" "  [BLOQUÉ]  image(s) sans version fixée : $(printf '%s ' $sans_tag)"; RC_COMPOSE=1
  else
    log "$VERT" "  [OK]      toutes les images ont un tag de version fixé"
  fi
  # Socket Docker monté ?
  if printf '%s\n' "$config" | grep -q 'docker.sock'; then
    log "$ROUGE" "  [BLOQUÉ]  /var/run/docker.sock est monté dans un conteneur"; RC_COMPOSE=1
  else
    log "$VERT" "  [OK]      socket Docker jamais monté"
  fi
  # Nombre de services vs nombre d'options no-new-privileges / limites mémoire
  nb_services="$(docker compose --profile siem --profile demo config --services 2>/dev/null | grep -c . || true)"
  nb_nnp="$(printf '%s\n' "$config" | grep -c 'no-new-privileges:true' || true)"
  nb_mem="$(printf '%s\n' "$config" | grep -cE '^\s+mem_limit:' || true)"
  nb_privileged="$(printf '%s\n' "$config" | grep -cE '^\s+privileged: true' || true)"
  if [ "$nb_nnp" -ge "$nb_services" ]; then log "$VERT" "  [OK]      no-new-privileges : $nb_nnp/$nb_services services"
  else log "$JAUNE" "  [AVERT]   no-new-privileges : $nb_nnp/$nb_services services"; fi
  if [ "$nb_mem" -ge "$nb_services" ]; then log "$VERT" "  [OK]      limites mémoire : $nb_mem/$nb_services services"
  else log "$JAUNE" "  [AVERT]   limites mémoire : $nb_mem/$nb_services services"; fi
  if [ "$nb_privileged" -eq 0 ]; then log "$VERT" "  [OK]      aucun conteneur privilégié"
  else log "$ROUGE" "  [BLOQUÉ]  $nb_privileged conteneur(s) en mode privileged"; RC_COMPOSE=1; fi
else
  log "$JAUNE" "  [ERREUR]  docker compose config a échoué (.env présent ?)"; NB_ERREURS=$((NB_ERREURS + 1))
fi

# --- Synthèse ----------------------------------------------------------------
printf '\n'; log "$GRAS" "== Synthèse =="
log "" "Images saines : $NB_SAINES — bloquées : $NB_BLOQUEES — erreurs : $NB_ERREURS"
log "" "Rapports : $DOSSIER_RAPPORT/"
if [ "$NB_BLOQUEES" -gt 0 ] || [ "$RC_CONFIG" -ne 0 ] || [ "$RC_COMPOSE" -ne 0 ]; then
  log "$ROUGE" "DÉPLOIEMENT BLOQUÉ (E12) : corriger (mise à jour du tag d'image) puis relancer."
  exit 1
fi
if [ "$NB_ERREURS" -gt 0 ]; then
  log "$JAUNE" "Scan incomplet : $NB_ERREURS erreur(s) d'exécution."
  exit 2
fi
log "$VERT" "Aucune vulnérabilité $SEVERITE corrigeable : déploiement autorisé."
exit 0
