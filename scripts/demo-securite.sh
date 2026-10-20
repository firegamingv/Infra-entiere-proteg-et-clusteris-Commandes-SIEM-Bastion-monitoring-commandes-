#!/usr/bin/env bash
# OSTRAL — démonstration de soutenance : « un attaquant essaie, l'architecture l'arrête ».
#
#   bash scripts/demo-securite.sh          # pas à pas (Entrée entre chaque scène)
#   bash scripts/demo-securite.sh --auto   # d'une traite
#
# Chaque scène joue une attaque réaliste (scénarios SS1 à SS5 du dossier) et affiche
# la mesure qui la bloque. Aucune donnée n'est modifiée.
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

AUTO=0; [ "${1:-}" = "--auto" ] && AUTO=1
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  R=$'\e[31m'; V=$'\e[32m'; J=$'\e[33m'; B=$'\e[36m'; G=$'\e[1m'; Z=$'\e[0m'
else R=; V=; J=; B=; G=; Z=; fi

IMG_NC=alpine:3.24.2
IMG_CURL=curlimages/curl:8.22.0
CURL_WIN=(); curl -V 2>/dev/null | grep -qi schannel && CURL_WIN=(--ssl-no-revoke)
WEB=(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert certs/ca.crt "${CURL_WIN[@]}"
     --resolve ostral.local:443:127.0.0.1)
NB_BLOQUE=0; NB_ECHEC=0

scene() {
  printf '\n%s━━━ %s ━━━%s\n' "$G$B" "$1" "$Z"
  printf '%s%s%s\n' "$J" "$2" "$Z"
}
pause() { [ "$AUTO" = 1 ] || { printf '\n%s[Entrée pour continuer]%s ' "$B" "$Z"; read -r _; }; }
bloque() { NB_BLOQUE=$((NB_BLOQUE + 1)); printf '  %s✔ BLOQUÉ%s  %s\n' "$V" "$Z" "$1"; }
passe()  { printf '  %s→ autorisé%s %s\n' "$B" "$Z" "$1"; }
echec()  { NB_ECHEC=$((NB_ECHEC + 1)); printf '  %s✘ NON BLOQUÉ%s %s\n' "$R" "$Z" "$1"; }
# depuis SERVICE vers HÔTE:PORT, sans rien installer dans le conteneur ciblé
sonde() { docker run --rm --network "container:$(docker compose ps -q "$1")" "$IMG_NC" \
            nc -z -w 3 "$2" "$3" >/dev/null 2>&1; }
# depuis « Internet » (un conteneur attaquant posé sur Z0)
sonde_internet() { docker run --rm --network ostral_z0_internet "$IMG_NC" nc -z -w 3 "$1" "$2" >/dev/null 2>&1; }

DEBUT="$(date -u +%Y-%m-%dT%H:%M:%S)"   # alerts.json horodate en UTC (+0000)
printf '%sOSTRAL — démonstration de sécurité%s  (%s)\n' "$G" "$Z" "$(date '+%d/%m/%Y %H:%M')"
printf "Un attaquant tente 8 attaques réalistes. Pour chacune : la mesure qui l'arrête.\n"
docker compose ps -q waf >/dev/null 2>&1 || { echo "Maquette non démarrée (docker compose up -d)." >&2; exit 2; }
pause

# ---------------------------------------------------------------------------------------------
scene "1. Attaque web sur la boutique (injection SQL, XSS)" \
      "Mesure : WAF ModSecurity + règles OWASP CRS en DMZ (E04, F01)"
for a in "Injection SQL|/?id=1%27%20OR%20%271%27%3D%271" \
         "Vol de cookie par XSS|/?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E" \
         "Lecture de /etc/passwd|/?file=..%2F..%2F..%2Fetc%2Fpasswd"; do
  c="$("${WEB[@]}" "https://ostral.local${a#*|}")"
  [ "$c" = 403 ] && bloque "${a%%|*} → HTTP 403" || echec "${a%%|*} → HTTP $c"
done
passe "visiteur normal → HTTP $("${WEB[@]}" https://ostral.local/)"
pause

# ---------------------------------------------------------------------------------------------
scene "2. Piratage de comptes clients en masse (bourrage d'identifiants, SS2)" \
      "Mesure : limitation de débit du WAF (429) + verrouillage du compte côté boutique (E04)"
codes=""
for i in $(seq 1 15); do
  codes+="$("${WEB[@]}" -X POST -d "email=victime$i@exemple.fr&password=azerty$i" https://ostral.local/login) "
done
printf '  15 tentatives : %s\n' "$codes"
case "$codes" in *429*) bloque "le WAF coupe la rafale (HTTP 429) au-delà de quelques essais" ;;
  *) echec "aucun 429" ;; esac
pause

# ---------------------------------------------------------------------------------------------
scene "3. Fausse notification « commande payée » envoyée à la boutique" \
      "Mesure : notifications PSP signées HMAC, reçues uniquement par le canal privé F03 (E02)"
c="$("${WEB[@]}" -X POST -H 'Content-Type: application/json' -d '{"status":"paid","amount":1}' https://ostral.local/payment/notify)"
[ "$c" = 403 ] && bloque "notification forgée depuis Internet → HTTP 403" || echec "HTTP $c"
pause

# ---------------------------------------------------------------------------------------------
scene "4. Accès direct au système interne depuis Internet" \
      "Mesure : seuls le WAF (443) et le VPN (51820/udp) sont exposés (F01, F09) — DMZ entre deux pare-feux"
for t in "ERP Odoo|10.10.3.20|8069" "Base de données ERP|10.10.4.20|5432" "Annuaire AD|10.10.5.10|389" \
         "Bastion d'administration|10.10.6.10|8080" "SIEM Wazuh|10.10.7.22|5601"; do
  IFS='|' read -r nom ip port <<<"$t"
  sonde_internet "$ip" "$port" && echec "$nom ($ip:$port) joignable" || bloque "$nom ($ip:$port) injoignable depuis Internet"
done
pause

# ---------------------------------------------------------------------------------------------
scene "5. La boutique est compromise : l'attaquant tente de rebondir (SS3)" \
      "Mesure : cloisonnement — un seul chemin vers l'interne, l'API ERP en mTLS (E05, F04)"
for t in "base de données ERP|10.10.4.20|5432" "annuaire AD|10.10.5.10|389" "ERP Odoo en direct|10.10.3.20|8069" \
         "Internet (exfiltration)|1.1.1.1|443"; do
  IFS='|' read -r nom ip port <<<"$t"
  sonde boutique "$ip" "$port" && echec "$nom joignable" || bloque "$nom injoignable depuis la boutique"
done
api() { docker run --rm --network "container:$(docker compose ps -q boutique)" -v "$(pwd -W 2>/dev/null || pwd)/certs:/c:ro" \
          "$IMG_CURL" -s -o /dev/null -w '%{http_code}' --max-time 8 --cacert /c/ca.crt \
          --resolve erp-api.ostral.internal:9443:10.10.1.10 "$@" 2>/dev/null; }
c="$(api -X POST https://erp-api.ostral.internal:9443/jsonrpc)"
[ "$c" != 200 ] && bloque "API ERP sans certificat client → HTTP $c" || echec "API ERP sans certificat → 200"
c="$(api --cert /c/boutique-client.crt --key /c/boutique-client.key https://erp-api.ostral.internal:9443/web/login)"
[ "$c" = 403 ] && bloque "interface web d'Odoo via l'API, même avec certificat → HTTP 403" || echec "HTTP $c"
c="$(api --cert /c/boutique-client.crt --key /c/boutique-client.key -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"call","params":{"service":"db","method":"list","args":[]}}' \
      https://erp-api.ostral.internal:9443/jsonrpc)"
[ "$c" = 403 ] && bloque "liste/suppression des bases Odoo (service db) → HTTP 403" || echec "HTTP $c"
pause

# ---------------------------------------------------------------------------------------------
scene "6. Un poste de salarié est piégé par hameçonnage (SS1)" \
      "Mesure : postes isolés — pas d'Internet direct, pas d'administration hors bastion (F13, F15)"
sonde poste 10.10.8.20 8069 && passe "usage métier : le poste ouvre Odoo (F07)" || echec "Odoo injoignable"
sonde poste 10.10.3.30 22  && echec "SSH direct vers un serveur" || bloque "SSH direct vers un serveur (le bastion est obligatoire)"
sonde poste 10.10.4.20 5432 && echec "base ERP joignable" || bloque "base de données ERP injoignable"
sonde poste 1.1.1.1 443    && echec "Internet joignable" || bloque "Internet direct (téléchargement du rançongiciel, exfiltration)"
pause

# ---------------------------------------------------------------------------------------------
scene "7. Rançongiciel : l'attaquant veut détruire les sauvegardes" \
      "Mesure : copie hors site verrouillée 30 jours (Object Lock) + clé en écriture seule (E09, 3-2-1-1-0)"
sortie="$(docker compose exec -T backup sh -c 'export MC_HOST_offsite="http://$MINIO_BACKUP_ACCESS_KEY:$MINIO_BACKUP_SECRET_KEY@minio-offsite:9000"
  mcli rm --recursive --force offsite/ostral-backup-offsite/ 2>&1 | tail -1' 2>&1)"
case "$sortie" in *Denied*|*denied*|*permissions*) bloque "suppression de la copie hors site → « Access Denied »" ;;
  *) echec "suppression : $sortie" ;; esac
n="$(docker compose exec -T backup restic snapshots --json 2>/dev/null | grep -o '"short_id"' | wc -l | tr -d ' ')"
passe "sauvegardes restic disponibles : $n snapshot(s), restauration testée par scripts/test-restore.sh"
pause

# ---------------------------------------------------------------------------------------------
scene "8. Tout cela a-t-il été vu ? (détection, E08)" \
      "Mesure : SIEM Wazuh dans une zone dédiée, journaux de toutes les zones, alertes ≥ 10 = SMS astreinte"
if docker compose ps --status running --format '{{.Service}}' | grep -qx wazuh-manager; then
  sleep 5
  # Alertes OSTRAL émises depuis le début de la démonstration, regroupées par type
  docker compose exec -T wazuh-manager sh -c 'tail -n 5000 /var/ossec/logs/alerts/alerts.json' 2>/dev/null \
    | awk -v debut="$DEBUT" 'match($0, /"timestamp":"[^"]*"/) { if (substr($0, RSTART + 13, 19) >= debut) print }' \
    | grep -o '"rule":{"level":[0-9]*,"description":"OSTRAL[^"]*' \
    | sed -E 's/"rule":\{"level":([0-9]+),"description":"(.*)/\1|\2/' \
    | sed -E 's/ (depuis|pour|vers|de) ([0-9]{1,3}\.){3}[0-9]{1,3}.*//' | sort | uniq -c | sort -rn | head -8 \
    | while read -r nb reste; do
        printf '  %s%4s%s alerte(s)  niveau %-3s %s\n' "$G" "$nb" "$Z" "${reste%%|*}" "${reste#*|}"
      done
  printf '  → consultables dans Wazuh : Threat Hunting, recherche %srule.id:1002*%s\n' "$G" "$Z"
else
  printf '  (profil siem non démarré : relancer avec COMPOSE_PROFILES=siem)\n'
fi

# ---------------------------------------------------------------------------------------------
printf '\n%s━━━ Bilan ━━━%s\n' "$G$B" "$Z"
printf '  %s%d attaques bloquées%s, %s%d non bloquée(s)%s\n' "$V" "$NB_BLOQUE" "$Z" \
  "$([ "$NB_ECHEC" = 0 ] && echo "$V" || echo "$R")" "$NB_ECHEC" "$Z"
printf '  Défense en profondeur : WAF → DMZ → mTLS → cloisonnement en 9 zones → bastion MFA → SIEM → sauvegardes immuables.\n'
[ "$NB_ECHEC" = 0 ]
