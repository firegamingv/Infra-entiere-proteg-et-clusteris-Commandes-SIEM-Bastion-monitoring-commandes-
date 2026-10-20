#!/usr/bin/env bash
# =============================================================================
# OSTRAL — Tests du WAF / reverse proxy (Z2) depuis « Internet » (l'hôte)
# Lot F — Tests et documentation
#
# Vérifie, contre https://ostral.local (publié sur 127.0.0.1:443, F01) :
#   1. requête saine -> 200 ;
#   2. injection SQL, XSS, traversée de répertoire, scanner -> 403
#      (ModSecurity + OWASP CRS, E04 / SS2) ;
#   3. en-têtes de sécurité présents, version du serveur masquée ;
#   4. TLS 1.0 et 1.1 refusés, TLS 1.2 / 1.3 acceptés (E03) ;
#   5. rafale de 30 POST /login -> apparition de 429 (limitation de débit
#      10/min, rafale 5, sur POST /login et /register ; E04 / SS2) ;
#   6. routes réservées : /payment/notify -> 403 depuis Internet (la
#      notification du PSP arrive directement par z1_egress), /healthz -> 404
#      (réservé à 127.0.0.1), port 80 -> 301 vers HTTPS, SNI inconnu refusé.
#
# Usage   : bash scripts/test-waf.sh
# Options : CIBLE_IP=127.0.0.1  CIBLE_PORT=443  HOTE=ostral.local
#           LOGIN_PATH=/login   RAFALE=30   NO_COLOR=1
# Code de retour : 0 si tout est conforme, 1 sinon, 2 si prérequis absents.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE" || exit 2
export MSYS_NO_PATHCONV=1

HOTE="${HOTE:-ostral.local}"
CIBLE_IP="${CIBLE_IP:-127.0.0.1}"
CIBLE_PORT="${CIBLE_PORT:-443}"
LOGIN_PATH="${LOGIN_PATH:-/login}"
RAFALE="${RAFALE:-30}"
BASE="https://$HOTE:$CIBLE_PORT"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  VERT=$'\e[32m'; ROUGE=$'\e[31m'; JAUNE=$'\e[33m'; GRIS=$'\e[90m'; GRAS=$'\e[1m'; RAZ=$'\e[0m'
else
  VERT=""; ROUGE=""; JAUNE=""; GRIS=""; GRAS=""; RAZ=""
fi

command -v curl >/dev/null 2>&1 || { echo "${ROUGE}curl est requis.${RAZ}" >&2; exit 2; }

# Résolution forcée (pas besoin de l'entrée hosts) + AC interne si disponible
CURL=(curl -s --max-time 10 --resolve "$HOTE:$CIBLE_PORT:$CIBLE_IP")
# curl de Windows (Schannel) : le contrôle de révocation échoue pour l'AC interne OSTRAL
curl -V 2>/dev/null | grep -qi schannel && CURL+=(--ssl-no-revoke)
if [ -f certs/ca.crt ]; then
  CURL+=(--cacert certs/ca.crt)
  echo "${GRIS}Vérification du certificat avec certs/ca.crt${RAZ}"
else
  CURL+=(-k)
  echo "${JAUNE}certs/ca.crt absent : vérification du certificat désactivée (-k)${RAZ}"
fi

NB_OK=0; NB_KO=0; NB_IGN=0
ok()  { NB_OK=$((NB_OK + 1));  printf '  %s[OK]%s     %s\n' "$VERT"  "$RAZ" "$1"; }
ko()  { NB_KO=$((NB_KO + 1));  printf '  %s[KO]%s     %s\n' "$ROUGE" "$RAZ" "$1"; }
ign() { NB_IGN=$((NB_IGN + 1)); printf '  %s[IGNORÉ]%s %s\n' "$GRIS" "$RAZ" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$GRAS" "$1" "$RAZ"; }

# code_attendu LIBELLE CODE_ATTENDU CHEMIN [args curl...]
code_attendu() {
  local libelle="$1" attendu="$2" chemin="$3"; shift 3
  local code
  code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@" "$BASE$chemin" 2>/dev/null || true)"
  if [ "$code" = "$attendu" ]; then ok "$libelle -> $code"
  else ko "$libelle -> obtenu $code, attendu $attendu"; fi
}

printf '%sOSTRAL — tests du WAF (%s)%s\n' "$GRAS" "$(date '+%Y-%m-%d %H:%M:%S')" "$RAZ"
printf 'Cible : %s (résolu vers %s)\n' "$BASE" "$CIBLE_IP"

# --- 1. Trafic légitime ------------------------------------------------------
section "1. Trafic légitime (F01 -> F02)"
code_attendu "GET / (page d'accueil de la boutique)" 200 "/"

# --- 2. Attaques web : ModSecurity + OWASP CRS -------------------------------
section "2. Attaques applicatives bloquées (ModSecurity / OWASP CRS)"
code_attendu "Injection SQL (' OR '1'='1)"              403 "/?id=1%27%20OR%20%271%27%3D%271"
code_attendu "Injection SQL (UNION SELECT)"             403 "/?q=1%20UNION%20SELECT%20username,password%20FROM%20users--"
code_attendu "XSS (<script>)"                           403 "/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
code_attendu "XSS (onerror)"                            403 "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
code_attendu "Traversée de répertoire (../../etc/passwd)" 403 "/?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
code_attendu "Injection de commande (;cat /etc/passwd)" 403 "/?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"
code_attendu "Outil d'attaque identifié (User-Agent sqlmap)" 403 "/" -A "sqlmap/1.8.4#stable (https://sqlmap.org)"
# Cible « / » (et non /login) : sans WAF la boutique répondrait 404 ; un 403 prouve
# donc le blocage par ModSecurity et non par le contrôle CSRF de la boutique.
code_attendu "Injection SQL dans un corps POST"         403 "/" \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "email=admin%40ostral.local%27%20OR%201%3D1--&password=x"

# --- 2 bis. Routes réservées --------------------------------------------------
section "2 bis. Routes réservées et redirection"
code_attendu "POST /payment/notify depuis Internet (notification PSP forgée)" 403 "/payment/notify" \
  -X POST -H 'Content-Type: application/json' --data '{"status":"paid"}'
code_attendu "GET /healthz du WAF depuis Internet (réservé à 127.0.0.1)" 404 "/healthz"
# Code et en-tête Location lus dans les en-têtes (certains curl laissent %{redirect_url} vide)
code="$(curl -s -D - -o /dev/null --max-time 5 \
        -H "Host: $HOTE" "http://$CIBLE_IP:${HTTP_PORT:-80}/compte?x=1" 2>/dev/null | tr -d '\r' \
        | awk 'NR==1{c=$2} tolower($1)=="location:"{l=$2} END{print c" "l}' || true)"
case "$code" in
  "301 https://ostral.local/"*|"308 https://ostral.local/"*) ok "HTTP 80 -> redirection permanente vers HTTPS ($code)" ;;
  *) ko "HTTP 80 : obtenu « $code », attendu 301 vers https://ostral.local" ;;
esac

# --- 3. En-têtes de sécurité -------------------------------------------------
section "3. En-têtes de sécurité"
entetes="$("${CURL[@]}" -o /dev/null -D - "$BASE/" 2>/dev/null | tr -d '\r' || true)"
if [ -z "$entetes" ]; then
  ko "aucune réponse du WAF"
else
  for h in "Strict-Transport-Security" "X-Content-Type-Options" "Content-Security-Policy" "Referrer-Policy"; do
    if printf '%s\n' "$entetes" | grep -qi "^$h:"; then ok "$h présent"; else ko "$h absent"; fi
  done
  # Protection contre le clickjacking : X-Frame-Options OU CSP frame-ancestors
  if printf '%s\n' "$entetes" | grep -qiE '^x-frame-options:|^content-security-policy:.*frame-ancestors'; then
    ok "anti-clickjacking (X-Frame-Options ou frame-ancestors)"
  else
    ko "anti-clickjacking absent"
  fi
  srv="$(printf '%s\n' "$entetes" | grep -i '^server:' | head -n1)"
  if printf '%s' "$srv" | grep -Eq '[0-9]+\.[0-9]+'; then ko "version du serveur divulguée ($srv)"
  else ok "version du serveur masquée (${srv:-en-tête Server absent})"; fi
  if printf '%s\n' "$entetes" | grep -qi '^x-powered-by:'; then ko "X-Powered-By divulgué"
  else ok "X-Powered-By absent"; fi
fi

# --- 4. Versions TLS ---------------------------------------------------------
section "4. Versions TLS (E03)"
if command -v openssl >/dev/null 2>&1; then
  T=""; command -v timeout >/dev/null 2>&1 && T="timeout 10"
  # essai_tls OPTION -> 0 si la négociation aboutit
  essai_tls() {
    # SECLEVEL=0 : le client propose réellement les vieux protocoles ; un refus
    # vient donc bien du serveur et non de la politique locale d'OpenSSL.
    # Succès : « New, TLSv1.x, Cipher is XXX » ; échec : « Cipher is (NONE) ».
    local sortie
    # shellcheck disable=SC2086
    sortie="$($T openssl s_client -connect "$CIBLE_IP:$CIBLE_PORT" -servername "$HOTE" "$@" \
               </dev/null 2>/dev/null || true)"
    printf '%s\n' "$sortie" | grep -q 'Cipher is ' \
      && ! printf '%s\n' "$sortie" | grep -q 'Cipher is (NONE)'
  }
  for v in tls1 tls1_1; do
    if ! openssl s_client -help 2>&1 | grep -q -- "-$v"; then
      ign "openssl local ne supporte pas -$v"
    elif essai_tls "-$v" -cipher 'DEFAULT:@SECLEVEL=0'; then
      ko "$v accepté par le serveur (doit être refusé)"
    else
      ok "$v refusé"
    fi
  done
  if essai_tls -tls1_2; then ok "tls1_2 accepté"; else ko "tls1_2 refusé (doit être accepté)"; fi
  # SNI inconnu : le WAF refuse la poignée de main (ssl_reject_handshake on)
  sortie_sni="$($T openssl s_client -connect "$CIBLE_IP:$CIBLE_PORT" -servername inconnu.example \
                 </dev/null 2>/dev/null || true)"
  if printf '%s\n' "$sortie_sni" | grep -q 'Cipher is ' && ! printf '%s\n' "$sortie_sni" | grep -q 'Cipher is (NONE)'; then
    ko "SNI inconnu accepté (certificat présenté à un scan par IP)"
  else
    ok "SNI inconnu : poignée de main refusée"
  fi
  if openssl s_client -help 2>&1 | grep -q -- '-tls1_3'; then
    if essai_tls -tls1_3; then ok "tls1_3 accepté"; else ko "tls1_3 refusé (doit être accepté)"; fi
  else
    ign "openssl local ne supporte pas -tls1_3"
  fi
else
  ign "openssl absent : tests des versions TLS ignorés"
fi

# --- 5. Limitation de débit sur l'authentification ---------------------------
section "5. Bourrage d'identifiants : $RAFALE POST $LOGIN_PATH (limitation de débit)"
declare -A compte=()
for i in $(seq 1 "$RAFALE"); do
  c="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data "email=victime${i}%40exemple.fr&password=MotDePasseFuite${i}" \
        "$BASE$LOGIN_PATH" 2>/dev/null || true)"
  compte[$c]=$(( ${compte[$c]:-0} + 1 ))
done
repartition=""
for c in "${!compte[@]}"; do repartition+="$c×${compte[$c]} "; done
printf '  %sRépartition des codes : %s%s\n' "$GRIS" "$repartition" "$RAZ"
if [ "${compte[429]:-0}" -gt 0 ]; then
  ok "limitation active : ${compte[429]} réponse(s) 429 sur $RAFALE"
else
  ko "aucune réponse 429 sur $RAFALE tentatives"
fi
printf '  %sL'"'"'alerte correspondante est visible dans Wazuh (profil siem) : voir docs/demo.md.%s\n' "$GRIS" "$RAZ"

# --- Résumé ------------------------------------------------------------------
printf '\n%s== Résumé ==%s\n' "$GRAS" "$RAZ"
printf '%sOK : %d%s   %sKO : %d%s   %sIgnorés : %d%s\n' \
  "$VERT" "$NB_OK" "$RAZ" "$ROUGE" "$NB_KO" "$RAZ" "$GRIS" "$NB_IGN" "$RAZ"
[ "$NB_KO" -eq 0 ] && { echo "${VERT}WAF conforme.${RAZ}"; exit 0; }
echo "${ROUGE}WAF non conforme : voir les lignes KO ci-dessus.${RAZ}"
exit 1
