#!/usr/bin/env bash
# OSTRAL — réinitialise un compte du bastion Guacamole (Z6) sur son mot de passe INITIAL du .env.
#
#   bash scripts/reset-bastion.sh admin1            # remet le mot de passe initial
#   bash scripts/reset-bastion.sh admin1 --totp     # idem + nouvel enrôlement TOTP (téléphone perdu)
#
# Comptes : admin1 (GUAC_ADMIN_PASSWORD), admin2 (GUAC_ADMIN2_PASSWORD),
#           agence-web (GUAC_AGENCE_WEB_PASSWORD).
# Pas de changement imposé (défaut Guacamole 1.6 avec TOTP, voir sql/020-ostral-comptes.sql) :
# changer le mot de passe dans Paramètres > Préférences après la connexion (E06).
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

compte="${1:-}"; totp="${2:-}"
case "$compte" in
  admin1)     var=GUAC_ADMIN_PASSWORD ;;
  admin2)     var=GUAC_ADMIN2_PASSWORD ;;
  agence-web) var=GUAC_AGENCE_WEB_PASSWORD ;;
  *) echo "usage : $0 admin1|admin2|agence-web [--totp]" >&2; exit 2 ;;
esac
mdp="$(grep "^$var=" .env | cut -d= -f2-)"
[ -n "$mdp" ] || { echo "$var absent de .env" >&2; exit 1; }

# Le mot de passe passe par l'environnement du conteneur, jamais par la ligne de commande.
docker compose exec -T -e OSTRAL_MDP="$mdp" -e OSTRAL_COMPTE="$compte" -e OSTRAL_TOTP="$totp" guac-db sh -c '
psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
     -v mdp="$OSTRAL_MDP" -v compte="$OSTRAL_COMPTE" -v totp="$OSTRAL_TOTP" <<"SQL"
WITH sel AS (SELECT sha256(convert_to(gen_random_uuid()::text || clock_timestamp()::text, '"'"'UTF8'"'"')) AS s)
UPDATE guacamole_user u
   SET password_salt = sel.s,
       password_hash = sha256(convert_to(:'"'"'mdp'"'"' || upper(encode(sel.s, '"'"'hex'"'"')), '"'"'UTF8'"'"')),
       password_date = now(), expired = false, disabled = false
  FROM sel, guacamole_entity e
 WHERE e.entity_id = u.entity_id AND e.name = :'"'"'compte'"'"' AND e.type = '"'"'USER'"'"';
SELECT CASE WHEN :'"'"'totp'"'"' = '"'"'--totp'"'"' THEN 1 ELSE 0 END AS reset_totp \gset
\if :reset_totp
DELETE FROM guacamole_user_attribute a USING guacamole_user u, guacamole_entity e
 WHERE a.user_id = u.user_id AND u.entity_id = e.entity_id AND e.name = :'"'"'compte'"'"'
   AND a.attribute_name LIKE '"'"'guac-totp-%'"'"';
\endif
SQL'
echo "Compte $compte réinitialisé : mot de passe initial ($var dans .env), à changer ensuite dans Paramètres > Préférences."
[ "$totp" = "--totp" ] && echo "TOTP réinitialisé : un nouveau QR code sera proposé."
echo "Rappel : 5 échecs = adresse bannie 5 min par le bastion (tous les accès VPN/démo partagent la même IP)."
