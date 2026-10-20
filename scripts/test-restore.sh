#!/usr/bin/env bash
# =============================================================================
# OSTRAL — Tests de résilience de la maquette
# Lot F — Tests et documentation
#
# Mode par défaut : test mensuel de restauration (« 0 erreur » de la règle
#   3-2-1-1-0, E09 / E10). Lance dans le conteneur de sauvegarde (Z7) le
#   script fourni par le lot E :
#       docker compose exec backup /usr/local/bin/restore-test.sh
#   qui restaure la dernière sauvegarde de la base ERP dans un environnement
#   isolé et vérifie empreinte, tables et nombre de commandes.
#
# Mode --erp-down : simulation du risque R2 (coupure boutique <-> ERP) et du
#   RTO ERP de 8 h : la boutique doit continuer à vendre en mettant les
#   commandes en file d'attente (table « outbox » de boutique-db), puis la file
#   doit s'écouler au retour de l'ERP.
#     1. relevé de la file   2. docker compose stop odoo
#     3. passage d'une commande   4. vérification : la commande reste en file
#     5. docker compose start odoo   6. vérification de l'écoulement
#   La file se consulte avec :
#     docker compose exec boutique-db psql -U <utilisateur> -d <base> \
#       -c "select status,count(*) from outbox group by 1"
#
# Usage   : bash scripts/test-restore.sh [--erp-down]
# Options : RESTORE_SCRIPT=/usr/local/bin/restore-test.sh
#           COMMANDE_CMD='commande shell qui passe une commande'   (mode --erp-down)
#           COMMANDE_PATH=<route JSON éventuelle>   STATUT_ENVOYE=done   DELAI_ECOULEMENT=300
# Code de retour : 0 succès, 1 échec du test, 2 prérequis absents.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE" || exit 2
export MSYS_NO_PATHCONV=1

RESTORE_SCRIPT="${RESTORE_SCRIPT:-/usr/local/bin/restore-test.sh}"
STATUT_ENVOYE="${STATUT_ENVOYE:-done}"            # statut d'une commande transmise à l'ERP
DELAI_ECOULEMENT="${DELAI_ECOULEMENT:-300}"        # secondes max pour vider la file
DELAI_ODOO="${DELAI_ODOO:-240}"                    # secondes max de redémarrage d'Odoo
COMMANDE_PATH="${COMMANDE_PATH:-}"   # vide : la boutique n'a pas d'API JSON, commande via le navigateur

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  VERT=$'\e[32m'; ROUGE=$'\e[31m'; JAUNE=$'\e[33m'; GRIS=$'\e[90m'; GRAS=$'\e[1m'; RAZ=$'\e[0m'
else
  VERT=""; ROUGE=""; JAUNE=""; GRIS=""; GRAS=""; RAZ=""
fi
dc() { docker compose "$@"; }
etape() { printf '\n%s▶ %s%s\n' "$GRAS" "$1" "$RAZ"; }
ok()    { printf '%s[OK]%s %s\n' "$VERT" "$RAZ" "$1"; }
ko()    { printf '%s[KO]%s %s\n' "$ROUGE" "$RAZ" "$1"; }
info()  { printf '%s%s%s\n' "$GRIS" "$1" "$RAZ"; }

command -v docker >/dev/null 2>&1 || { ko "Docker est requis."; exit 2; }

en_marche() {
  local cid; cid="$(dc ps -q "$1" 2>/dev/null | head -n1)"
  [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" = "true" ]
}

# =============================================================================
# Mode 1 : test de restauration (mensuel)
# =============================================================================
test_restauration() {
  printf '%sOSTRAL — test de restauration de la sauvegarde ERP (%s)%s\n' "$GRAS" "$(date '+%Y-%m-%d %H:%M:%S')" "$RAZ"
  en_marche backup || { ko "le service « backup » n'est pas démarré"; exit 2; }
  etape "Exécution de $RESTORE_SCRIPT dans le conteneur backup (Z7)"
  local debut fin rc
  debut=$(date +%s)
  dc exec -T backup "$RESTORE_SCRIPT"; rc=$?
  fin=$(date +%s)
  printf '\n'
  if [ "$rc" -eq 0 ]; then
    ok "restauration vérifiée en $((fin - debut)) s (objectif RTO ERP : 8 h, RPO : 1 h)"
    info "Résultat attendu (calendrier mensuel) : base lisible, nombre de tables et de commandes cohérent."
    return 0
  fi
  ko "le test de restauration a échoué (code $rc) — voir le volume logs_backup"
  return 1
}

# =============================================================================
# Mode 2 : ERP arrêté -> file d'attente des commandes (R2)
# =============================================================================
sql_boutique() {
  # Utilise les variables POSTGRES_* du conteneur boutique-db (aucun secret ici)
  dc exec -T boutique-db sh -c \
    'psql -U "$POSTGRES_USER" -d "${POSTGRES_DB:-$POSTGRES_USER}" -Atc "$1"' sh "$1" 2>/dev/null | tr -d '\r'
}
en_attente() {
  local n
  n="$(sql_boutique "select count(*) from outbox where status <> '$STATUT_ENVOYE'")"
  printf '%s' "${n:-ERREUR}"
}
etat_file() {
  info "  file d'attente (status | nombre) :"
  sql_boutique "select status, count(*) from outbox group by 1 order by 1" | sed 's/^/    /'
}

passer_commande() {
  if [ -n "${COMMANDE_CMD:-}" ]; then
    info "  commande personnalisée : $COMMANDE_CMD"
    bash -c "$COMMANDE_CMD"; return $?
  fi
  # Hypothèse : la boutique (lot A) expose une API de création de commande
  # derrière le WAF. Le paiement passe par psp-mock (E02).
  if [ -z "$COMMANDE_PATH" ]; then
    # La boutique passe les commandes par formulaires (session + CSRF) puis par le PSP :
    # pas de création automatique, on demande une commande manuelle (ou COMMANDE_CMD).
    if [ -t 0 ]; then
      printf '%s  Passez une commande dans le navigateur (https://ostral.local, paiement de test via le PSP)
' "$JAUNE"
      printf '  puis appuyez sur Entrée.%s ' "$RAZ"
      read -r _
      return 0
    fi
    echo "  hors terminal : définir COMMANDE_CMD pour passer la commande de test" >&2
    return 1
  fi
  local cacert=(-k); [ -f certs/ca.crt ] && cacert=(--cacert certs/ca.crt)
  local ref="TEST-R2-$(date +%s)"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${cacert[@]}" \
          --resolve ostral.local:443:127.0.0.1 -X POST \
          -H 'Content-Type: application/json' \
          -d "{\"reference\":\"$ref\",\"email\":\"client.test@exemple.fr\",\"items\":[{\"sku\":\"OST-CHA-001\",\"qty\":1}]}" \
          "https://ostral.local$COMMANDE_PATH" 2>/dev/null || true)"
  info "  POST $COMMANDE_PATH -> HTTP $code (référence $ref)"
  case "$code" in 2??) return 0 ;; esac
  if [ -t 0 ]; then
    printf '%s  Création automatique impossible : passez une commande dans le navigateur\n' "$JAUNE"
    printf '  (https://ostral.local, paiement de test via le PSP) puis appuyez sur Entrée.%s ' "$RAZ"
    read -r _
    return 0
  fi
  return 1
}

attendre_odoo() {
  local t=0 cid etat
  cid="$(dc ps -q odoo 2>/dev/null | head -n1)"
  while [ "$t" -lt "$DELAI_ODOO" ]; do
    etat="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)"
    case "$etat" in healthy|running) [ "$etat" = "healthy" ] || sleep 10; return 0 ;; esac
    sleep 5; t=$((t + 5))
  done
  return 1
}

ODOO_ARRETE=0
remise_en_etat() {
  if [ "$ODOO_ARRETE" = "1" ]; then
    printf '\n%sInterruption : redémarrage d'"'"'Odoo...%s\n' "$JAUNE" "$RAZ"
    dc start odoo >/dev/null 2>&1
  fi
}

test_erp_arrete() {
  printf '%sOSTRAL — simulation R2 : ERP arrêté, commandes en file d'"'"'attente (%s)%s\n' "$GRAS" "$(date '+%Y-%m-%d %H:%M:%S')" "$RAZ"
  for s in boutique boutique-db odoo waf; do
    en_marche "$s" || { ko "le service « $s » doit être démarré"; exit 2; }
  done
  trap remise_en_etat EXIT INT TERM

  etape "1. État initial de la file (table outbox de boutique-db)"
  local avant
  avant="$(en_attente)"
  [ "$avant" = "ERREUR" ] && { ko "lecture de la table outbox impossible"; exit 2; }
  etat_file; info "  commandes non transmises : $avant"

  etape "2. Arrêt de l'ERP (docker compose stop odoo)"
  dc stop odoo >/dev/null 2>&1 && ODOO_ARRETE=1
  local t0; t0=$(date +%s)
  ok "Odoo arrêté — la boutique doit rester disponible"
  local code
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve ostral.local:443:127.0.0.1 https://ostral.local/ 2>/dev/null || true)"
  if [ "$code" = "200" ]; then ok "boutique toujours accessible (HTTP 200)"; else ko "boutique indisponible (HTTP $code)"; fi

  etape "3. Passage d'une commande pendant l'arrêt"
  if ! passer_commande; then ko "impossible de passer une commande (définir COMMANDE_CMD)"; exit 1; fi

  etape "4. La commande doit rester en file d'attente"
  sleep 10
  local pendant; pendant="$(en_attente)"
  etat_file
  if [ "$pendant" != "ERREUR" ] && [ "$pendant" -gt "$avant" ]; then
    ok "commande conservée en file d'attente ($avant -> $pendant non transmise(s))"
  else
    ko "aucune nouvelle commande en file d'attente ($avant -> $pendant)"; exit 1
  fi

  etape "5. Redémarrage de l'ERP (docker compose start odoo)"
  dc start odoo >/dev/null 2>&1; ODOO_ARRETE=0
  if attendre_odoo; then ok "Odoo redémarré"; else ko "Odoo n'est pas redevenu sain en ${DELAI_ODOO} s"; exit 1; fi

  etape "6. Écoulement de la file (worker de réémission de la boutique)"
  local t=0 restant="$pendant"
  while [ "$t" -lt "$DELAI_ECOULEMENT" ]; do
    restant="$(en_attente)"
    [ "$restant" != "ERREUR" ] && [ "$restant" -le "$avant" ] && break
    sleep 10; t=$((t + 10))
  done
  etat_file
  if [ "$restant" != "ERREUR" ] && [ "$restant" -le "$avant" ]; then
    ok "file écoulée : commandes transmises à l'ERP (durée totale d'indisponibilité ERP : $(( $(date +%s) - t0 )) s)"
    info "Vérification possible dans Odoo : Ventes > Commandes (dernière commande créée par api-boutique)."
    return 0
  fi
  ko "la file ne s'est pas écoulée en ${DELAI_ECOULEMENT} s ($restant commande(s) en attente)"
  return 1
}

case "${1:-}" in
  --erp-down) test_erp_arrete; exit $? ;;
  ""|--restore) test_restauration; exit $? ;;
  -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
  *) echo "Option inconnue : $1 (voir --help)" >&2; exit 2 ;;
esac
