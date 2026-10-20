#!/bin/sh
# OSTRAL — Lot C — Initialisation de erp-db (Z4), exécutée UNE fois à la création du volume.
#  - F06 : compte de service applicatif `odoo` (sans superuser / CREATEDB / CREATEROLE),
#          propriétaire de la seule base `ostral` créée à l'avance (Odoo n'a pas besoin de CREATEDB).
#  - F16/E09 : rôle `backup_ro` en lecture seule (pg_read_all_data) pour la sauvegarde en mode pull.
#  - Moindre privilège : PUBLIC perd CONNECT/CREATE ; chaque rôle ne reçoit que ce qu'il lui faut.
# Les mots de passe sont passés en variables psql (:'var') : pas d'injection SQL possible.
set -eu

: "${ERP_DB_USER:=odoo}"
: "${ERP_DB_NAME:=ostral}"
: "${ERP_DB_PASSWORD:?ERP_DB_PASSWORD manquant}"
: "${ERP_DB_BACKUP_PASSWORD:?ERP_DB_BACKUP_PASSWORD manquant}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname postgres \
     -v app_user="$ERP_DB_USER" -v app_pw="$ERP_DB_PASSWORD" \
     -v app_db="$ERP_DB_NAME" -v bkp_pw="$ERP_DB_BACKUP_PASSWORD" <<'EOSQL'
SET password_encryption = 'scram-sha-256';

-- F06 : compte de service de l'ERP, privilèges minimaux
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64;

-- Base créée à l'avance, propriété du seul compte Odoo (paramètres attendus par Odoo)
CREATE DATABASE :"app_db" OWNER :"app_user" ENCODING 'UTF8'
  TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';

-- F16/E09 : sauvegarde en lecture seule
CREATE ROLE backup_ro LOGIN PASSWORD :'bkp_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
GRANT pg_read_all_data TO backup_ro;
ALTER ROLE backup_ro SET default_transaction_read_only = on;

-- Cloisonnement : PUBLIC ne peut plus se connecter aux bases ; droits explicites seulement
REVOKE CONNECT, TEMPORARY ON DATABASE :"app_db" FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"app_db" TO :"app_user";
GRANT CONNECT ON DATABASE :"app_db" TO backup_ro;
GRANT CONNECT ON DATABASE postgres TO :"app_user", backup_ro;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL

# Dans la base applicative : le schéma public appartient au propriétaire de la base (PG15+),
# on retire tout droit implicite à PUBLIC.
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "$ERP_DB_NAME" \
     -v app_user="$ERP_DB_USER" <<'EOSQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO :"app_user";
GRANT USAGE ON SCHEMA public TO backup_ro;
EOSQL

echo "[ostral/erp-db] rôles '$ERP_DB_USER' (propriétaire de '$ERP_DB_NAME') et 'backup_ro' créés."
