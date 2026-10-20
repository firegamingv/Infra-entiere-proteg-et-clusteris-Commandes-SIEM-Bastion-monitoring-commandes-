# OSTRAL — Lot C — configuration applicative de l'ERP, exécutée par `odoo shell` (variable `env`
# fournie par Odoo). Rejouable à volonté : chaque étape converge vers l'état voulu.
#   - compte web `admin` : mot de passe ODOO_WEB_ADMIN_PASSWORD (jamais « admin » par défaut) ;
#   - utilisateur technique ODOO_API_USER (api-boutique) : groupe « Ventes / Utilisateur : ses
#     documents » uniquement (moindre privilège, F05), sans mot de passe → seule la clé API permet
#     de s'authentifier, et uniquement en RPC (non interactif) ;
#   - clé API IMPOSÉE = ODOO_API_KEY : insérée hachée (pbkdf2-sha512, même format que Odoo) dans
#     res_users_apikeys, portée « rpc » ; toute ancienne clé de ce compte est révoquée (rotation) ;
#   - auth_ldap vers l'AD samba-ad (F07/F08) : STARTTLS sur 389 + vérification du certificat par
#     l'AC interne de l'AD (LDAPTLS_CACERT), compte de liaison svc-odoo-ldap, filtre limité au
#     groupe GG-ERP-Utilisateurs et aux comptes actifs.
# pylint: disable=undefined-variable
import os
import sys


def log(msg):
    print(f"[ostral/odoo-init] {msg}", flush=True)


def env_required(name):
    val = os.environ.get(name, "")
    if not val:
        log(f"ERREUR : variable {name} obligatoire absente")
        sys.exit(1)
    return val


API_LOGIN = os.environ.get("ODOO_API_USER", "api-boutique")
API_KEY = env_required("ODOO_API_KEY")
API_KEY_NAME = "boutique-ostral (ODOO_API_KEY, F04/F05)"
WEB_ADMIN_PASSWORD = env_required("ODOO_WEB_ADMIN_PASSWORD")
LDAP_BIND_PASSWORD = env_required("SAMBA_ODOO_BIND_PASSWORD")
LDAP_BASE = os.environ.get("ODOO_LDAP_BASE", "DC=ostral,DC=local")
LDAP_SERVER = os.environ.get("ODOO_LDAP_SERVER", "dc1.ostral.local")
LDAP_PORT = int(os.environ.get("ODOO_LDAP_PORT", "389"))
LDAP_BINDDN = os.environ.get(
    "ODOO_LDAP_BINDDN", f"CN=svc-odoo-ldap,OU=Comptes-Service,OU=OSTRAL,{LDAP_BASE}")
LDAP_GROUP_DN = os.environ.get(
    "ODOO_LDAP_GROUP_DN", f"CN=GG-ERP-Utilisateurs,OU=Groupes,OU=OSTRAL,{LDAP_BASE}")
# Compte AD actif (bit ACCOUNTDISABLE absent) + membre du groupe ERP ; %s = identifiant saisi
LDAP_FILTER = (
    "(&(objectClass=user)(objectCategory=person)(sAMAccountName=%s)"
    f"(memberOf={LDAP_GROUP_DN})"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
)

if len(API_KEY) < 20 or any(c.isspace() for c in API_KEY):
    log("ERREUR : ODOO_API_KEY doit faire au moins 20 caractères sans espace "
        "(recommandé : openssl rand -hex 20)")
    sys.exit(1)

Users = env["res.users"].sudo().with_context(active_test=False, no_reset_password=True)

# ------------------------------------------------------------------ 1. compte web admin
admin = env.ref("base.user_admin")
admin.sudo().write({"password": WEB_ADMIN_PASSWORD})
log("mot de passe du compte web 'admin' appliqué (ODOO_WEB_ADMIN_PASSWORD).")

# ------------------------------------------------------- 2. utilisateur technique API
grp_user = env.ref("base.group_user")
grp_sale = env.ref("sales_team.group_sale_salesman")
api_vals = {
    "name": "API Boutique (compte technique)",
    "login": API_LOGIN,
    "active": True,
    "groups_id": [(6, 0, [grp_user.id, grp_sale.id])],
    "tz": "Europe/Paris",
}
api_user = Users.search([("login", "=", API_LOGIN)], limit=1)
if api_user:
    api_user.write(api_vals)
    log(f"utilisateur '{API_LOGIN}' mis à jour (droits ventes uniquement).")
else:
    api_user = Users.create(api_vals)
    log(f"utilisateur '{API_LOGIN}' créé (id {api_user.id}, droits ventes uniquement).")
# Aucun mot de passe : connexion web impossible, clé API seulement
env.cr.execute("UPDATE res_users SET password = NULL WHERE id = %s", [api_user.id])

# Contrat : la boutique crée le partenaire s'il est absent → droit de création requis
Partner = env["res.partner"].with_user(api_user)
if not Partner.check_access_rights("create", raise_exception=False):
    api_user.write({"groups_id": [(4, env.ref("base.group_partner_manager").id)]})
    log("groupe « Création de contacts » ajouté (création de partenaires par la boutique).")
for model in ("sale.order", "res.partner"):
    ok = env[model].with_user(api_user).check_access_rights("create", raise_exception=False)
    log(f"contrôle droits {API_LOGIN} : create {model} = {ok}")
    if not ok:
        sys.exit(1)

# ------------------------------------------------------------ 3. clé API imposée (F05)
# Odoo 17 : res_users_apikeys(name, user_id, scope, "index", key) ; « index » = 8 premiers
# caractères en clair (recherche), « key » = hachage passlib pbkdf2-sha512 (KEY_CRYPT_CONTEXT).
# _generate() tire une clé aléatoire : on reproduit son INSERT avec la valeur imposée.
from odoo.addons.base.models import res_users as base_res_users  # noqa: E402

INDEX_SIZE = getattr(base_res_users, "INDEX_SIZE", 8)
_hash = getattr(base_res_users, "hash_api_key", None) or base_res_users.KEY_CRYPT_CONTEXT.hash
Keys = env["res.users.apikeys"].sudo()

env.cr.execute("SELECT count(*) FROM res_users_apikeys WHERE user_id = %s", [api_user.id])
nb_keys = env.cr.fetchone()[0]
if nb_keys == 1 and Keys._check_credentials(scope="rpc", key=API_KEY) == api_user.id:
    log("clé API déjà conforme à ODOO_API_KEY.")
else:
    env.cr.execute("DELETE FROM res_users_apikeys WHERE user_id = %s", [api_user.id])
    env.cr.execute(
        'INSERT INTO res_users_apikeys (name, user_id, scope, key, "index") '
        "VALUES (%s, %s, %s, %s, %s)",
        [API_KEY_NAME, api_user.id, "rpc", _hash(API_KEY), API_KEY[:INDEX_SIZE]],
    )
    if Keys._check_credentials(scope="rpc", key=API_KEY) != api_user.id:
        log("ERREUR : la clé API insérée n'est pas reconnue par Odoo")
        sys.exit(1)
    log(f"clé API de '{API_LOGIN}' fixée à ODOO_API_KEY ({nb_keys} ancienne(s) révoquée(s)).")

# --------------------------------------------- 3 bis. catalogue partagé avec la boutique
# Les 6 articles du catalogue boutique (default_code = SKU) sont pré-créés : api-boutique n'a ainsi
# besoin que de la LECTURE sur product.product (pas de droit « gestion des articles », moindre
# privilège). Prix TTC indicatifs en euros, poids en kg (repris du seed du lot A).
CATALOGUE = [
    ("OST-CHA-001", "Chaise Lune", 89.00, 5.5),
    ("OST-TAB-002", "Table Fjord 180", 649.00, 42.0),
    ("OST-CAN-003", "Canapé Brume 3 places", 1199.00, 68.0),
    ("OST-BIB-004", "Bibliothèque Strate", 349.00, 31.0),
    ("OST-LIT-005", "Lit Aube 160", 799.00, 55.0),
    ("OST-LAM-006", "Lampadaire Halo", 159.00, 9.0),
]
Product = env["product.product"].sudo().with_context(active_test=False)
type_field = "detailed_type" if "detailed_type" in Product._fields else "type"
for sku, name, price, weight in CATALOGUE:
    prod = Product.search([("default_code", "=", sku)], limit=1)
    if prod:
        prod.write({"active": True, "sale_ok": True})
        continue
    Product.create({
        "name": name,
        "default_code": sku,
        "list_price": price,
        "weight": weight,
        "sale_ok": True,
        "purchase_ok": True,
        type_field: "product",  # article stockable (module stock)
    })
    log(f"article créé : {sku} — {name}")

ApiProduct = env["product.product"].with_user(api_user)
if not ApiProduct.check_access_rights("read", raise_exception=False):
    log("ERREUR : api-boutique ne peut pas lire product.product")
    sys.exit(1)
log(f"contrôle droits {API_LOGIN} : read product.product = True ; create = "
    f"{ApiProduct.check_access_rights('create', raise_exception=False)} (articles pré-créés)")

# ---------------------------------------------------------------- 4. auth_ldap (F07)
# Modèle des salariés créés à la 1re connexion AD : ventes + stock (utilisateur), inactif.
grp_stock = env.ref("stock.group_stock_user")
tpl_vals = {
    "name": "Modèle salarié AD (ne pas activer)",
    "login": "modele-salarie-ad",
    "groups_id": [(6, 0, [grp_user.id, grp_sale.id, grp_stock.id])],
}
template = Users.search([("login", "=", "modele-salarie-ad")], limit=1)
if template:
    template.write(tpl_vals)
else:
    # Odoo 17 refuse la création directe d'un utilisateur inactif (archivage du contact lié) :
    # on le crée actif puis on l'archive aussitôt.
    template = Users.create(tpl_vals)
if template.active:
    template.write({"active": False})
env.cr.execute("UPDATE res_users SET password = NULL WHERE id = %s", [template.id])

company = env.ref("base.main_company")
ldap_vals = {
    "company": company.id,
    "sequence": 10,
    "ldap_server": LDAP_SERVER,
    "ldap_server_port": LDAP_PORT,
    "ldap_tls": True,  # STARTTLS : auth_ldap 17 construit une URI ldap:// (pas de ldaps://)
    "ldap_binddn": LDAP_BINDDN,
    "ldap_password": LDAP_BIND_PASSWORD,
    "ldap_base": LDAP_BASE,
    "ldap_filter": LDAP_FILTER,
    "create_user": True,
    "user": template.id,
}
Ldap = env["res.company.ldap"].sudo()
ldap_conf = Ldap.search([("company", "=", company.id), ("ldap_server", "=", LDAP_SERVER)], limit=1)
if ldap_conf:
    ldap_conf.write(ldap_vals)
    log(f"configuration LDAP mise à jour ({LDAP_SERVER}:{LDAP_PORT}, STARTTLS).")
else:
    Ldap.create(ldap_vals)
    log(f"configuration LDAP créée ({LDAP_SERVER}:{LDAP_PORT}, STARTTLS).")

env.cr.commit()  # `odoo shell` annule la transaction en sortie : validation explicite
log("configuration applicative validée.")
