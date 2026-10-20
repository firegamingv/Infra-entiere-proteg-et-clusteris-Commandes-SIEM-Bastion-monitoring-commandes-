#!/usr/bin/env python3
"""OSTRAL — Lot C — rendu de la configuration Odoo (Z3).

Lit le gabarit /opt/ostral/odoo.conf, remplace les ${VARIABLES} par l'environnement et écrit
/run/odoo/odoo.conf (tmpfs, mode 0600) : le conteneur reste en lecture seule (E12) et aucun
secret n'est stocké dans l'image.
 - admin_passwd (mot de passe maître, gestionnaire de bases) est haché en pbkdf2-sha512,
   format reconnu nativement par Odoo : le clair n'est jamais écrit sur disque.
 - Si /var/log/odoo n'est pas inscriptible, repli sur la sortie standard (avertissement).
"""
import os
import string
import sys

TEMPLATE = os.environ.get("ODOO_CONF_TEMPLATE", "/opt/ostral/odoo.conf")
TARGET = os.environ.get("ODOO_RC", "/run/odoo/odoo.conf")
LOGDIR = "/var/log/odoo"


def fail(msg):
    print(f"[ostral/odoo] ERREUR : {msg}", file=sys.stderr)
    sys.exit(1)


def require(name):
    val = os.environ.get(name, "")
    if not val:
        fail(f"variable {name} obligatoire absente")
    if "\n" in val or "\r" in val:
        fail(f"variable {name} : retour à la ligne interdit")
    return val


def main():
    from passlib.context import CryptContext  # fourni par l'image officielle Odoo

    admin_clear = require("ODOO_ADMIN_PASSWD")
    ctx = CryptContext(schemes=["pbkdf2_sha512"])
    values = {
        "ERP_DB_USER": os.environ.get("ERP_DB_USER", "odoo"),
        "ERP_DB_PASSWORD": require("ERP_DB_PASSWORD"),
        "ODOO_DB": os.environ.get("ODOO_DB", "ostral"),
        "ODOO_WORKERS": os.environ.get("ODOO_WORKERS", "2"),
        "ODOO_ADMIN_PASSWD_HASH": ctx.hash(admin_clear),
    }
    if not values["ODOO_WORKERS"].isdigit():
        fail("ODOO_WORKERS doit être un entier")

    if os.path.isdir(LOGDIR) and os.access(LOGDIR, os.W_OK):
        values["ODOO_LOGFILE"] = os.path.join(LOGDIR, "odoo.log")
    else:
        print(f"[ostral/odoo] AVERTISSEMENT : {LOGDIR} non inscriptible, journaux sur stdout",
              file=sys.stderr)
        values["ODOO_LOGFILE"] = ""

    with open(TEMPLATE, encoding="utf-8") as fh:
        rendered = string.Template(fh.read()).substitute(values)

    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    os.chmod(TARGET, 0o600)


if __name__ == "__main__":
    main()
