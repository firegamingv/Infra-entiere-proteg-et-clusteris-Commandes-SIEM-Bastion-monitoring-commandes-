#!/usr/bin/env bash
# =============================================================================
# OSTRAL — Vérification de la matrice de flux (F01–F18) de la maquette Docker
# Lot F — Tests et documentation
#
# Principe : chaque flux de la matrice (dossier d'architecture, pages 6 et 14)
# est rejoué depuis le conteneur SOURCE vers l'adresse IP fixe de la
# DESTINATION (voir SPEC.md). On compare le résultat à l'attendu :
#   - AUTORISÉ : la connexion TCP (ou la requête HTTP) doit aboutir ;
#   - BLOQUÉ   : la connexion doit échouer (refus par défaut, E05) ;
#   - CIBLE    : blocage exigé par le dossier mais non garanti par la topologie
#                de la maquette (écart connu) : affiché en « ÉCART », ne fait
#                échouer le script qu'avec STRICT=1.
#
# Outils de test :
#   1. si le conteneur source dispose de `nc`, on l'utilise via
#      `docker compose exec -T <service> sh -c 'nc -z -w 3 IP PORT'` ;
#   2. sinon, conteneur éphémère qui PARTAGE l'espace réseau du conteneur
#      source (`docker run --network container:<id>`) : il voit exactement les
#      mêmes interfaces, routes et règles iptables que la source (y compris
#      celles du conteneur WireGuard). Aucun réseau supplémentaire n'est ouvert.
#   Les tests HTTP/mTLS utilisent toujours un conteneur éphémère curl.
#
# Usage :   bash scripts/test-flux.sh            (depuis la racine du projet)
# Options : MODE=sidecar   force le conteneur éphémère pour tous les tests TCP
#           STRICT=1       les écarts « CIBLE » comptent comme des échecs
#           NO_COLOR=1     désactive les couleurs
# Code de retour : 0 si la matrice est conforme, 1 sinon, 2 si prérequis absents.
# =============================================================================
set -uo pipefail

# --- Contexte ---------------------------------------------------------------
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE" || exit 2
# Git Bash (Windows) : empêcher la conversion automatique des chemins POSIX
export MSYS_NO_PATHCONV=1
# Chemin hôte utilisable par le démon Docker (C:/... sous Git Bash)
RACINE_HOTE="$(pwd -W 2>/dev/null || pwd)"

DELAI="${DELAI:-3}"                                   # secondes, nc -w / curl
MODE="${MODE:-auto}"                                  # auto | sidecar
STRICT="${STRICT:-0}"
IMG_NC="${IMG_NC:-alpine:3.20.3}"                     # busybox nc
IMG_CURL="${IMG_CURL:-curlimages/curl:8.22.0}"        # tests HTTP / mTLS
IP_INTERNET="${IP_INTERNET:-1.1.1.1}"                 # « Internet » pour F12/F13

# Toutes les commandes compose incluent le profil siem : `ps`/`exec` ne
# démarrent rien, cela permet seulement d'adresser les services Wazuh et bastion-demo.
dc() { docker compose --profile siem --profile demo "$@"; }

# --- Couleurs ---------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  VERT=$'\e[32m'; ROUGE=$'\e[31m'; JAUNE=$'\e[33m'; GRIS=$'\e[90m'; GRAS=$'\e[1m'; RAZ=$'\e[0m'
else
  VERT=""; ROUGE=""; JAUNE=""; GRIS=""; GRAS=""; RAZ=""
fi

NB_OK=0; NB_KO=0; NB_ECART=0; NB_IGNORE=0
LISTE_KO=()

# --- Prérequis --------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "${ROUGE}Docker introuvable : installer Docker Desktop (WSL2) ou Docker Engine.${RAZ}" >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "${ROUGE}Le plugin « docker compose » v2 est requis.${RAZ}" >&2
  exit 2
fi
if ! dc ps -q >/dev/null 2>&1 || [ -z "$(dc ps -q 2>/dev/null)" ]; then
  echo "${ROUGE}Aucun conteneur du projet « ostral » n'est démarré (docker compose up -d).${RAZ}" >&2
  exit 2
fi

# Pré-téléchargement des images d'outillage (silencieux si déjà présentes)
for img in "$IMG_NC" "$IMG_CURL"; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null 2>&1 \
    || echo "${JAUNE}Avertissement : impossible de télécharger $img${RAZ}" >&2
done

# --- Fonctions utilitaires --------------------------------------------------

# Identifiant du conteneur en cours d'exécution d'un service (vide sinon)
cid_de() {
  local cid
  cid="$(dc ps -q "$1" 2>/dev/null | head -n1)"
  [ -n "$cid" ] || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" = "true" ] || return 1
  printf '%s' "$cid"
}

# Test TCP depuis un service : 0 = port joignable, 1 = injoignable,
# 3 = source indisponible (conteneur arrêté / service absent)
sonde_tcp() {
  local svc="$1" ip="$2" port="$3" cid
  cid="$(cid_de "$svc")" || return 3
  if [ "$MODE" = "auto" ] && dc exec -T "$svc" sh -c 'command -v nc' >/dev/null 2>&1; then
    dc exec -T "$svc" sh -c "nc -z -w $DELAI $ip $port" >/dev/null 2>&1
    return $?
  fi
  docker run --rm --network "container:$cid" "$IMG_NC" \
    nc -z -w "$DELAI" "$ip" "$port" >/dev/null 2>&1
}

# Code HTTP obtenu depuis l'espace réseau d'un service (curl éphémère).
# Affiche « 000 » si la connexion / la négociation TLS échoue, « SRC » si la
# source est indisponible. Arguments supplémentaires transmis à curl.
code_http() {
  local svc="$1"; shift
  local cid
  cid="$(cid_de "$svc")" || { printf 'SRC'; return; }
  docker run --rm --network "container:$cid" -u 0 \
    -v "$RACINE_HOTE/certs:/certs:ro" "$IMG_CURL" \
    -s -o /dev/null -w '%{http_code}' --max-time $((DELAI + 5)) "$@" 2>/dev/null || true
}

# Affichage d'une ligne de résultat
# resultat ID SOURCE DESTINATION PORT ATTENDU OBTENU VERDICT(OK|KO|ECART|IGNORE) [note]
resultat() {
  local id="$1" src="$2" dst="$3" port="$4" att="$5" obt="$6" verdict="$7" note="${8:-}"
  local coul etiquette
  case "$verdict" in
    OK)     coul="$VERT";  etiquette="OK";     NB_OK=$((NB_OK + 1)) ;;
    KO)     coul="$ROUGE"; etiquette="KO";     NB_KO=$((NB_KO + 1)); LISTE_KO+=("$id $src -> $dst:$port") ;;
    ECART)  coul="$JAUNE"; etiquette="ÉCART";  NB_ECART=$((NB_ECART + 1))
            if [ "$STRICT" = "1" ]; then NB_KO=$((NB_KO + 1)); LISTE_KO+=("$id $src -> $dst:$port (écart)"); fi ;;
    *)      coul="$GRIS";  etiquette="IGNORÉ"; NB_IGNORE=$((NB_IGNORE + 1)) ;;
  esac
  printf '%-5s %-16s %-26s %-11s %-9s %-11s %s%-6s%s %s\n' \
    "$id" "$src" "$dst" "$port" "$att" "$obt" "$coul" "$etiquette" "$RAZ" "${note:+${GRIS}$note${RAZ}}"
}

# Test TCP générique avec comparaison à l'attendu
# flux ID SRC_SERVICE DEST_LIBELLE IP PORT ATTENDU(AUTORISE|BLOQUE|CIBLE) [note]
flux() {
  local id="$1" src="$2" dst="$3" ip="$4" port="$5" att="$6" note="${7:-}"
  local rc obtenu verdict libelle_att
  sonde_tcp "$src" "$ip" "$port"; rc=$?
  case "$att" in AUTORISE) libelle_att="AUTORISÉ" ;; *) libelle_att="BLOQUÉ" ;; esac
  if [ "$rc" -eq 3 ]; then
    resultat "$id" "$src" "$dst" "$port/tcp" "$libelle_att" "-" "IGNORE" "source « $src » non démarrée"
    return
  fi
  if [ "$rc" -eq 0 ]; then obtenu="ouvert"; else obtenu="fermé"; fi
  if   [ "$att" = "AUTORISE" ] && [ "$rc" -eq 0 ]; then verdict="OK"
  elif [ "$att" != "AUTORISE" ] && [ "$rc" -ne 0 ]; then verdict="OK"
  elif [ "$att" = "CIBLE" ]; then verdict="ECART"
  else verdict="KO"; fi
  resultat "$id" "$src" "$dst" "$port/tcp" "$libelle_att" "$obtenu" "$verdict" "$note"
}

# Test HTTP : verdict OK si le code obtenu correspond au motif attendu (regex)
# flux_http ID SRC DEST PORT LIBELLE_ATTENDU REGEX_CODE note -- args curl...
flux_http() {
  local id="$1" src="$2" dst="$3" port="$4" att="$5" motif="$6" note="$7"; shift 8
  local code
  code="$(code_http "$src" "$@")"
  if [ "$code" = "SRC" ]; then
    resultat "$id" "$src" "$dst" "$port" "$att" "-" "IGNORE" "source « $src » non démarrée"; return
  fi
  if printf '%s' "$code" | grep -Eq "^($motif)\$"; then
    resultat "$id" "$src" "$dst" "$port" "$att" "HTTP $code" "OK" "$note"
  else
    resultat "$id" "$src" "$dst" "$port" "$att" "HTTP $code" "KO" "$note"
  fi
}

section() { printf '\n%s== %s ==%s\n' "$GRAS" "$1" "$RAZ"; }

# Options curl communes pour l'API ERP (F04/F05) : SNI erp-api.ostral.internal
# résolu vers l'IP du WAF sur z1_cloud (10.10.1.10), AC interne OSTRAL.
API_ERP=(--resolve "erp-api.ostral.internal:9443:10.10.1.10" --cacert /certs/ca.crt)
CERT_CLIENT=(--cert /certs/boutique-client.crt --key /certs/boutique-client.key)
URL_API="https://erp-api.ostral.internal:9443"

# =============================================================================
printf '%sOSTRAL — test de la matrice de flux (%s)%s\n' "$GRAS" "$(date '+%Y-%m-%d %H:%M:%S')" "$RAZ"
printf 'Mode des sondes TCP : %s — délai : %ss — STRICT=%s\n' "$MODE" "$DELAI" "$STRICT"
printf '\n%-5s %-16s %-26s %-11s %-9s %-11s %s\n' "ID" "SOURCE" "DESTINATION" "PORT" "ATTENDU" "OBTENU" "VERDICT"
printf '%s\n' "------------------------------------------------------------------------------------------------"

# --- F01 : Internet (hôte) -> WAF 443 ----------------------------------------
section "Entrée publique (Z0 -> Z2)"
if command -v curl >/dev/null 2>&1; then
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve ostral.local:443:127.0.0.1 https://ostral.local/ 2>/dev/null || true)"
  if printf '%s' "$code" | grep -Eq '^(2|3)[0-9][0-9]$'; then v=OK; else v=KO; fi
  resultat "F01" "hote(Z0)" "waf ostral.local" "443/tcp" "AUTORISÉ" "HTTP $code" "$v" "TLS terminé au WAF (E03/E04)"
  # Négatifs : aucun autre service ne doit être publié sur l'hôte
  # Port 80 : redirection 301 vers https://ostral.local uniquement (aucun contenu en clair)
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: ostral.local' http://127.0.0.1:80/ 2>/dev/null || true)"
  if [ "$code" = "301" ] || [ "$code" = "308" ]; then v=OK; else v=KO; fi
  resultat "F01" "hote(Z0)" "waf (HTTP)" "80/tcp" "REDIRIGÉ" "HTTP $code" "$v" "redirection vers HTTPS"
  # PSP simulé : logiquement en Z0 (page de paiement hébergée), publié sur 127.0.0.1:4000
  if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/4000" 2>/dev/null; then v=OK; o="ouvert"; else v=KO; o="fermé"; fi
  resultat "F03" "hote(Z0)" "psp-mock (Z0)" "4000/tcp" "AUTORISÉ" "$o" "$v" "page de paiement du PSP (E02)"
  # Bastion : publié sur 127.0.0.1:8080 UNIQUEMENT avec le profil demo (bastion-demo)
  # Relais de scripts/demo-acces.sh (ostral-demo-<nom>) : contournement de démonstration assumé
  relais_demo() { docker ps -q --filter "name=^ostral-demo-$1\$" 2>/dev/null | grep -q .; }
  if cid_de bastion-demo >/dev/null || relais_demo bastion; then
    resultat "NEG" "hote(Z0)" "guacamole (publication)" "8080/tcp" "BLOQUÉ" "profil demo" "IGNORE" "relais de démo actif : contournement F09 assumé"
  elif timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/8080" 2>/dev/null; then
    resultat "NEG" "hote(Z0)" "guacamole (publication)" "8080/tcp" "BLOQUÉ" "ouvert" "KO" "bastion joignable par VPN seulement"
  else
    resultat "NEG" "hote(Z0)" "guacamole (publication)" "8080/tcp" "BLOQUÉ" "fermé" "OK" "bastion joignable par VPN seulement"
  fi
  for p in 3000:boutique 8069:odoo 5432:postgres 5601:wazuh-dashboard 9000:minio 9443:api-erp 3001:uptime-kuma; do
    port="${p%%:*}"; nom="${p#*:}"
    # Ouverture TCP brute via /dev/tcp (indépendant du protocole applicatif)
    case "$nom" in odoo) r=odoo ;; wazuh-dashboard) r=wazuh ;; uptime-kuma) r=uptime-kuma ;; *) r="" ;; esac
    if [ -n "$r" ] && relais_demo "$r"; then
      resultat "NEG" "hote(Z0)" "$nom (publication)" "$port/tcp" "BLOQUÉ" "relais démo" "IGNORE" "demo-acces.sh actif : contournement assumé"
      continue
    fi
    if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then v=KO; o="ouvert"; else v=OK; o="fermé"; fi
    resultat "NEG" "hote(Z0)" "$nom (publication)" "$port/tcp" "BLOQUÉ" "$o" "$v" "seuls F01 et F09 sont exposés"
  done
else
  resultat "F01" "hote(Z0)" "waf ostral.local" "443/tcp" "AUTORISÉ" "-" "IGNORE" "curl absent sur l'hôte"
fi
# F09 (partie exposée) : le seul autre port publié est UDP 51820 (WireGuard)
pub="$(dc port --protocol udp wireguard 51820 2>/dev/null | head -n1)"
if [ -n "$pub" ]; then
  resultat "F09" "hote(Z0)" "wireguard (FW1)" "51820/udp" "AUTORISÉ" "publié $pub" "OK" "point d'entrée VPN"
else
  resultat "F09" "hote(Z0)" "wireguard (FW1)" "51820/udp" "AUTORISÉ" "non publié" "KO" "conteneur arrêté ou port absent"
fi

# --- Z1 / Z2 : boutique, WAF, API ERP ----------------------------------------
section "Boutique et API ERP (Z1 <-> Z2 -> Z3)"
flux "F02" "waf"      "boutique"           10.10.1.20  3000 AUTORISE "WAF -> boutique (TLS terminé au WAF)"
flux "F03" "boutique" "psp-mock"           10.10.11.30 4000 AUTORISE "paiement externalisé (E02)"
flux "F04" "boutique" "waf (API ERP)"      10.10.1.10  9443 AUTORISE "port TCP de l'API mTLS"

flux_http "F04" "boutique" "waf API ERP +cert" "9443/mTLS" "AUTORISÉ" '2[0-9][0-9]' \
  "POST /jsonrpc avec certificat client" -- \
  "${API_ERP[@]}" "${CERT_CLIENT[@]}" -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{"service":"common","method":"version","args":[]}}' \
  "$URL_API/jsonrpc"
flux_http "F04" "boutique" "waf API ERP -cert" "9443/mTLS" "BLOQUÉ" '000|400|403|495|496' \
  "sans certificat client : refus TLS ou 400/403" -- \
  "${API_ERP[@]}" -X POST -H 'Content-Type: application/json' -d '{}' "$URL_API/jsonrpc"
flux_http "F05" "boutique" "odoo via WAF /web" "9443/mTLS" "BLOQUÉ" '403' \
  "interface web Odoo interdite (routes d'API seulement)" -- \
  "${API_ERP[@]}" "${CERT_CLIENT[@]}" "$URL_API/web/login"
flux_http "F05" "boutique" "odoo via WAF /odoo" "9443/mTLS" "BLOQUÉ" '403' \
  "toute route hors /jsonrpc et /xmlrpc/2/*" -- \
  "${API_ERP[@]}" "${CERT_CLIENT[@]}" "$URL_API/odoo"
flux "F05" "waf"      "odoo (z3_api)"      10.10.13.20 8069 AUTORISE "réseau dédié z3_api : waf + odoo seuls"
flux "NEG" "waf"      "odoo (z3_servers)"  10.10.3.20  8069 BLOQUE   "le WAF n'est pas sur z3_servers"

flux "NEG" "boutique" "odoo (direct)"      10.10.3.20  8069 BLOQUE   "E05 : jamais d'accès direct au SI"
flux "NEG" "boutique" "erp-db"             10.10.4.20  5432 BLOQUE   "E05"
flux "NEG" "boutique" "samba-ad"           10.10.5.10  389  BLOQUE   "E05"
flux "NEG" "boutique" "Internet"           "$IP_INTERNET" 443 BLOQUE "sortie limitée au PSP (F03)"
flux "NEG" "waf"      "boutique-db"        10.10.12.30 5432 BLOQUE   "base boutique réservée à la boutique"
flux "NEG" "psp-mock" "boutique-db"        10.10.12.30 5432 BLOQUE   "tiers sans accès aux données"

# --- Z3 / Z4 / Z5 : ERP, base, annuaire --------------------------------------
section "ERP, données, identité (Z3 -> Z4 / Z5)"
flux "F06" "odoo"     "erp-db"             10.10.4.20  5432 AUTORISE "seul accès à la base (E05)"
flux "F08" "odoo"     "samba-ad LDAP"      10.10.5.10  389  AUTORISE "LDAP + STARTTLS (dc1.ostral.local)"
# Odoo -> AD : LDAP 389 avec STARTTLS (dc1.ostral.local) ; 636 reste ouvert pour les postes
flux "NEG" "erp-db"   "Internet"           "$IP_INTERNET" 443 BLOQUE "Z4 sans aucune sortie (exfiltration)"
# odoo est aussi sur z4_data (10.10.4.10) pour F06 : la base peut techniquement
# l'atteindre -> écart signalé (CIBLE), à couvrir par un filtrage hôte en cible.
flux "NEG" "erp-db"   "odoo (z4_data)"     10.10.4.10  8069 CIBLE    "Z4 n'initie aucun flux (voir docs)"
flux "F12" "odoo"     "Internet (MAJ)"     "$IP_INTERNET" 443 BLOQUE "écart assumé : MAJ par reconstruction d'image"

# --- Z8 : postes ------------------------------------------------------------
section "Postes de travail (Z8)"
flux "F07" "poste"    "odoo"               10.10.8.20  8069 AUTORISE "usage métier"
for p in 53 88 389 636 445; do
  flux "F08" "poste" "samba-ad"            10.10.5.10  "$p" AUTORISE "ports d'authentification"
done
flux "F13" "poste"    "Internet"           "$IP_INTERNET" 443 BLOQUE "pas de sortie directe"
flux "F13" "poste"    "Internet DNS"       8.8.8.8     53   BLOQUE   "pas de résolution externe directe"
flux "F15" "poste"    "admin-target SSH"   10.10.3.30  22   BLOQUE   "administration via bastion (E06)"
flux "NEG" "poste"    "guacamole"          10.10.6.10  8080 BLOQUE   "bastion joignable par VPN seulement"
flux "NEG" "poste"    "erp-db"             10.10.4.20  5432 BLOQUE   "données sensibles (Z4)"
flux "NEG" "poste"    "wazuh-dashboard"    10.10.7.22  5601 BLOQUE   "console SIEM par VPN seulement"

# --- Z2 : DMZ ne sert pas de rebond (F14) ------------------------------------
section "DMZ sans rebond (F14)"
flux "F14" "waf"      "erp-db"             10.10.4.20  5432 BLOQUE   "DMZ -> Z4 interdit"
flux "F14" "waf"      "samba-ad LDAP"      10.10.5.10  389  BLOQUE   "DMZ -> Z5 interdit"
flux "F14" "waf"      "samba-ad SMB"       10.10.5.10  445  BLOQUE   "DMZ -> Z5 interdit"
flux "F14" "waf"      "guacamole"          10.10.6.10  8080 BLOQUE   "DMZ -> Z6 interdit"
flux "F14" "waf"      "poste/odoo Z8"      10.10.8.20  8069 BLOQUE   "DMZ -> Z8 interdit"
# F05 passe par le réseau dédié z3_api (waf 10.10.13.10, odoo 10.10.13.20) : le WAF
# n'a aucune interface sur z3_servers, donc ni SSH ni guacd ne lui sont joignables.
flux "F14" "waf"      "admin-target SSH"   10.10.3.30  22   BLOQUE   "WAF absent de z3_servers"
flux "F14" "waf"      "guacd"              10.10.3.11  4822 BLOQUE   "WAF absent de z3_servers"
flux "F14" "waf"      "guacd (z2_dmz)"     10.10.2.11  4822 BLOQUE   "guacd n'écoute que sur 10.10.6.11"

# --- Z6 : VPN, bastion ------------------------------------------------------
section "Administration (Z0 -> FW1/VPN -> Z6 -> serveurs)"
flux "F09" "wireguard" "guacamole"         10.10.6.10  8080 AUTORISE "VPN -> bastion (RESTREINT, TOTP)"
flux "NEG" "wireguard" "admin-target SSH"  10.10.3.30  22   BLOQUE   "pas de SSH direct depuis le VPN"
flux "NEG" "wireguard" "erp-db"            10.10.4.20  5432 BLOQUE   "pas d'accès direct aux données"
flux "INT" "guacamole" "guacd"             10.10.6.11  4822 AUTORISE "protocole interne du bastion"
flux "F10" "guacd"    "admin-target SSH"   10.10.3.30  22   AUTORISE "bastion -> serveurs (session enregistrée)"
flux "NEG" "guacamole" "admin-target SSH"  10.10.3.30  22   BLOQUE   "seul guacd sort vers les serveurs"
flux "NEG" "guacamole" "Internet"          "$IP_INTERNET" 443 BLOQUE "bastion sans sortie Internet"

# --- Z7 : SIEM, sauvegarde, supervision -------------------------------------
section "Supervision et sauvegarde (Z7)"
if cid_de wazuh-manager >/dev/null; then
  flux "F09" "wireguard" "wazuh-dashboard" 10.10.7.22  5601 AUTORISE "console SIEM via VPN"
  flux "F11" "backup"   "wazuh-manager"    10.10.7.20  1514 AUTORISE "réception des événements (agent)"
  flux "F11" "backup"   "wazuh-manager"    10.10.7.20  1515 AUTORISE "enrôlement des agents"
  # Équivalent maquette des agents : lecture des volumes logs_* en lecture seule
  montages="$(docker inspect -f '{{range .Mounts}}{{.Name}}:{{.RW}} {{end}}' "$(cid_de wazuh-manager)" 2>/dev/null)"
  for vol in logs_waf logs_boutique logs_odoo logs_erp_db logs_samba logs_guacamole logs_admin_target logs_backup logs_wireguard; do
    if printf '%s' "$montages" | grep -Eq "(^| )ostral_${vol}:false"; then
      resultat "F11" "$vol" "wazuh-manager" "volume" "AUTORISÉ" "monté RO" "OK" "collecte des journaux (E08)"
    elif printf '%s' "$montages" | grep -Eq "(^| )ostral_${vol}:true"; then
      resultat "F11" "$vol" "wazuh-manager" "volume" "AUTORISÉ" "monté RW" "KO" "doit être en lecture seule"
    else
      resultat "F11" "$vol" "wazuh-manager" "volume" "AUTORISÉ" "absent" "KO" "volume non monté"
    fi
  done
  flux "NEG" "poste"    "wazuh-manager"    10.10.7.20  1514 BLOQUE   "Z8 hors de Z7 (agents remplacés par volumes)"
else
  resultat "F11" "toutes zones" "wazuh-manager" "1514-1515" "AUTORISÉ" "-" "IGNORE" "profil siem non démarré"
fi
flux "F16" "backup"   "admin-target SSH"   10.10.3.30  22   AUTORISE "sauvegarde en mode pull (clé dédiée)"
flux "F16" "backup"   "erp-db (pg_dump)"   10.10.4.20  5432 AUTORISE "compte en lecture seule"
flux "F17" "backup"   "minio-offsite"      10.10.17.50 9000 AUTORISE "copie hors site verrouillée (E09)"
flux "NEG" "backup"   "Internet"           "$IP_INTERNET" 443 BLOQUE "aucune autre sortie"
flux "NEG" "minio-offsite" "erp-db"        10.10.4.20  5432 BLOQUE   "le stockage hors site n'initie rien"
flux "F18" "uptime-kuma" "waf (sonde externe)" 10.10.0.10 8443 AUTORISE "boutique vue d'Internet (E11)"
flux "F18" "uptime-kuma" "odoo"            10.10.3.20  8069 AUTORISE "contrôle de disponibilité ERP"
flux "NEG" "uptime-kuma" "erp-db"          10.10.4.20  5432 BLOQUE   "supervision sans accès aux données"

# =============================================================================
printf '\n%s== Résumé ==%s\n' "$GRAS" "$RAZ"
printf '%sOK : %d%s   %sKO : %d%s   %sÉcarts connus : %d%s   %sIgnorés : %d%s\n' \
  "$VERT" "$NB_OK" "$RAZ" "$ROUGE" "$NB_KO" "$RAZ" "$JAUNE" "$NB_ECART" "$RAZ" "$GRIS" "$NB_IGNORE" "$RAZ"
if [ "$NB_KO" -gt 0 ]; then
  printf '%sFlux non conformes à la matrice :%s\n' "$ROUGE" "$RAZ"
  for l in "${LISTE_KO[@]}"; do printf '  - %s\n' "$l"; done
  exit 1
fi
printf '%sMatrice de flux conforme.%s\n' "$VERT" "$RAZ"
exit 0
