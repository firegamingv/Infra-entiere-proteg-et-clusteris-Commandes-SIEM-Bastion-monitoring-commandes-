#!/usr/bin/env bash
# =============================================================================
# OSTRAL — lot D — initialisation de la base du bastion Guacamole (guac-db)
#
# Exécuté UNE SEULE FOIS par l'entrypoint de l'image postgres (répertoire de données vide),
# monté dans /docker-entrypoint-initdb.d. Peut être "sourcé" ou exécuté : pas de `set -u`
# (ne pas modifier le comportement de l'entrypoint) ni de `return`.
#
#  1. Attend puis charge le schéma officiel généré par le service one-shot guac-initdb
#     (/opt/guacamole/bin/initdb.sh --postgresql) dans le volume guac_initdb_sql.
#  2. Charge /opt/ostral/sql/020-ostral-comptes.sql : comptes nominatifs, compte prestataire
#     temporaire, connexion SSH vers admin-target enregistrée, désactivation de guacadmin
#     (E06, E07, F10, SS5).
#
# NB : les variables d'environnement ne sont lues qu'à cette première initialisation ;
# toute modification ultérieure se fait dans l'interface d'administration du bastion.
# =============================================================================
set -Eeo pipefail

ostral_schema="/opt/ostral/initdb-gen/001-schema.sql"
ostral_comptes="/opt/ostral/sql/020-ostral-comptes.sql"
ostral_cle_privee="/opt/ostral/sshkey/guac_ssh_key"
ostral_cle_hote="/opt/ostral/sshkey/admin-target_host.pub"

ostral_attendre() { # ostral_attendre <fichier>
  local i
  for i in $(seq 1 60); do
    [ -s "$1" ] && return 0
    echo "[ostral-initdb] attente de $1 ($i/60)"
    sleep 2
  done
  echo "[ostral-initdb] ERREUR : $1 absent (services guac-init / guac-initdb ?)" >&2
  exit 1
}

ostral_attendre "$ostral_schema"
ostral_attendre "$ostral_cle_privee"
ostral_attendre "$ostral_cle_hote"

for ostral_var in GUAC_ADMIN_PASSWORD GUAC_ADMIN2_PASSWORD GUAC_AGENCE_WEB_PASSWORD AGENCE_WEB_VALID_UNTIL; do
  if [ -z "${!ostral_var:-}" ]; then
    echo "[ostral-initdb] ERREUR : variable $ostral_var vide" >&2
    exit 1
  fi
done

echo "[ostral-initdb] chargement du schéma Guacamole"
psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -f "$ostral_schema"

# Entrée known_hosts épinglée pour la connexion (paramètre host-key de Guacamole).
ostral_host_key="10.10.3.30 $(cut -d' ' -f1,2 "$ostral_cle_hote")"

echo "[ostral-initdb] création des comptes et connexions OSTRAL"
psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v admin1_password="$GUAC_ADMIN_PASSWORD" \
     -v admin2_password="$GUAC_ADMIN2_PASSWORD" \
     -v agence_web_password="$GUAC_AGENCE_WEB_PASSWORD" \
     -v agence_web_valid_until="$AGENCE_WEB_VALID_UNTIL" \
     -v agence_web_access_start="${AGENCE_WEB_ACCESS_START:-08:00}" \
     -v agence_web_access_end="${AGENCE_WEB_ACCESS_END:-19:00}" \
     -v fuseau="${OSTRAL_TZ:-Europe/Paris}" \
     -v ssh_private_key="$(cat "$ostral_cle_privee")" \
     -v ssh_host_key="$ostral_host_key" \
     -f "$ostral_comptes"

unset ostral_var ostral_host_key
echo "[ostral-initdb] terminé"
