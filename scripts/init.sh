#!/usr/bin/env bash
# OSTRAL — amorçage complet de la maquette, dans le bon ordre.
#
#   bash scripts/init.sh            # version légère (sans SIEM)
#   bash scripts/init.sh --siem     # avec Wazuh (profil siem, ~4,5 Go RAM de plus)
#   bash scripts/init.sh --demo     # ajoute l'accès local au bastion (127.0.0.1:8080, contourne F09)
#
# Étapes :
#   1. crée .env depuis .env.example en générant des secrets aléatoires (E12 : secrets hors images/dépôt) ;
#   2. génère la PKI interne (TLS public F01, mTLS boutique → ERP F04) ;
#   3. génère la clé SSH de sauvegarde (pull F16) et la reporte dans .env pour admin-target ;
#   4. (siem) génère les certificats Wazuh et les comptes locaux AVANT la création des conteneurs,
#      sinon Docker créerait des répertoires vides à la place des fichiers montés ;
#   5. construit et démarre la maquette.
# Git Bash (Windows) : ne pas réécrire les chemins POSIX passés à docker (/usr/local/bin…)
export MSYS_NO_PATHCONV=1
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILS=()
for a in "$@"; do
  case "$a" in
    --siem) PROFILS+=(siem) ;;
    --demo) PROFILS+=(demo) ;;
    -h|--help) sed -n 2,14p "$0"; exit 0 ;;
    *) echo "option inconnue : $a" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null || { echo "Docker est requis (Docker Desktop + WSL2 sous Windows)." >&2; exit 2; }
docker compose version >/dev/null || { echo "Docker Compose v2 est requis." >&2; exit 2; }

secret() { openssl rand -hex "${1:-16}"; }
# Mot de passe complexe : satisfait la politique AD (3 classes, 12+ car.) et celle de l'API Wazuh.
mot_de_passe() { printf 'Ost%s!9' "$(secret 12)"; }

# --- 1. .env -----------------------------------------------------------------------------
if [ ! -f .env ]; then
  echo "[1/5] Création de .env avec des secrets aléatoires"
  date_fin="$(date -d '+30 days' +%F 2>/dev/null || date -v+30d +%F)"
  ip_hote="${WG_SERVERURL:-127.0.0.1}"
  while IFS= read -r ligne; do
    if [[ "$ligne" =~ ^([A-Z0-9_]+)=CHANGEME ]]; then
      nom="${BASH_REMATCH[1]}"
      case "$nom" in
        SESSION_SECRET)          val="$(secret 32)" ;;
        WG_SERVERURL)            val="$ip_hote" ;;
        AGENCE_WEB_VALID_UNTIL)  val="$date_fin" ;;
        # comptes soumis à une politique de complexité (AD, bastion, Odoo web, Wazuh)
        SAMBA_*|GUAC_ADMIN*|GUAC_AGENCE*|ODOO_WEB_ADMIN_PASSWORD|API_PASSWORD|INDEXER_PASSWORD|DASHBOARD_PASSWORD)
                                 val="$(mot_de_passe)" ;;
        # autres secrets : hexadécimal, sans caractère spécial (URL, SQL, shell)
        *)                       val="$(secret 20)" ;;
      esac
      printf '%s=%s\n' "$nom" "$val"
    else
      printf '%s\n' "$ligne"
    fi
  done < .env.example > .env
  if [ ${#PROFILS[@]} -gt 0 ]; then
    p="$(IFS=,; echo "${PROFILS[*]}")"
    sed -i "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=$p/" .env
  fi
  chmod 600 .env 2>/dev/null || true
  echo "      WG_SERVERURL=$ip_hote (mettre l'IP LAN de l'hôte pour un client VPN externe)"
else
  echo "[1/5] .env existe déjà : conservé"
  if [ ${#PROFILS[@]} -gt 0 ]; then
    p="$(IFS=,; echo "${PROFILS[*]}")"
    sed -i "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=$p/" .env
  fi
fi
if grep -qE '^[A-Z0-9_]+=CHANGEME' .env; then
  echo "Des valeurs CHANGEME restent dans .env :" >&2
  grep -nE '^[A-Z0-9_]+=CHANGEME' .env >&2
  exit 1
fi

# --- 2. PKI --------------------------------------------------------------------------------
echo "[2/5] Certificats internes (F01, F04)"
bash scripts/gen-certs.sh

# --- 3. Clé de sauvegarde -------------------------------------------------------------------
echo "[3/5] Clé SSH de sauvegarde (F16, mode pull)"
docker compose build backup
if ! grep -qE '^BACKUP_SSH_PUBKEY="?ssh-' .env; then
  ligne="$(docker compose run --rm --no-deps backup show-pubkey | tr -d '\r' | grep '^BACKUP_SSH_PUBKEY=' || true)"
  if [ -n "$ligne" ]; then
    grep -v '^BACKUP_SSH_PUBKEY=' .env > .env.tmp && printf '%s\n' "$ligne" >> .env.tmp && mv .env.tmp .env
    echo "      clé reportée dans .env"
  else
    echo "      ATTENTION : clé non récupérée, voir services/backup/README.md" >&2
  fi
fi

# --- 4. SIEM ----------------------------------------------------------------------------------
if grep -qE '^COMPOSE_PROFILES=.*siem' .env; then
  echo "[4/5] Amorçage Wazuh (certificats, comptes locaux)"
  echo "      Rappel : vm.max_map_count=262144 requis (Docker Desktop : wsl -d docker-desktop sysctl -w vm.max_map_count=262144)"
  docker compose --profile siem run --rm wazuh-certs
  docker compose --profile siem run --rm wazuh-users-init
else
  echo "[4/5] SIEM non demandé (relancer avec --siem pour l'activer)"
fi

# --- 5. Démarrage ---------------------------------------------------------------------------
echo "[5/5] Construction et démarrage"
docker compose up -d --build

cat <<'FIN'

Maquette OSTRAL démarrée. Premier démarrage : Samba AD et Odoo prennent 2 à 5 minutes.
  - Ajouter au fichier hosts : 127.0.0.1 ostral.local
  - Boutique : https://ostral.local   (AC : certs/ca.crt)
  - État     : docker compose ps
  - Tests    : bash scripts/test-flux.sh ; bash scripts/test-waf.sh ; bash scripts/trivy-scan.sh
  - Démo     : docs/demo.md
FIN
