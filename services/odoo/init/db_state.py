#!/usr/bin/env python3
"""OSTRAL — Lot C — état de la base ERP pour l'initialisation idempotente.

Usage : db_state.py ping        -> 0 si la base `ostral` répond (compte de service odoo, F06)
        db_state.py modules-ok  -> 0 si tous les modules de ODOO_INIT_MODULES sont « installed »
Paramètres de connexion : ERP_DB_USER / ERP_DB_PASSWORD / ODOO_DB, hôte erp-db (Z4).
"""
import os
import sys

import psycopg2  # fourni par l'image officielle Odoo


def connect():
    return psycopg2.connect(
        host=os.environ.get("ERP_DB_HOST", "erp-db"),
        port=int(os.environ.get("ERP_DB_PORT", "5432")),
        user=os.environ.get("ERP_DB_USER", "odoo"),
        password=os.environ["ERP_DB_PASSWORD"],
        dbname=os.environ.get("ODOO_DB", "ostral"),
        connect_timeout=5,
    )


def modules_ok(cur):
    wanted = [m.strip() for m in os.environ.get(
        "ODOO_INIT_MODULES", "base,sale_management,stock,account,auth_ldap").split(",") if m.strip()]
    cur.execute("SELECT to_regclass('public.ir_module_module') IS NOT NULL")
    if not cur.fetchone()[0]:
        return False
    cur.execute("SELECT name FROM ir_module_module WHERE state = 'installed' AND name = ANY(%s)",
                (wanted,))
    installed = {row[0] for row in cur.fetchall()}
    missing = sorted(set(wanted) - installed)
    if missing:
        print(f"[ostral/odoo-init] modules manquants : {', '.join(missing)}")
    return not missing


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "ping"
    try:
        conn = connect()
    except psycopg2.Error as exc:
        print(f"[ostral/odoo-init] base indisponible : {exc}".strip(), file=sys.stderr)
        return 1
    try:
        with conn.cursor() as cur:
            if action == "ping":
                cur.execute("SELECT 1")
                return 0
            if action == "modules-ok":
                return 0 if modules_ok(cur) else 1
            print(f"action inconnue : {action}", file=sys.stderr)
            return 2
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
