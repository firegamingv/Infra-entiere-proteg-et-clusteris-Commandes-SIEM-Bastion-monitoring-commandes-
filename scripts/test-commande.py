#!/usr/bin/env python3
"""OSTRAL — test de bout en bout du parcours d'achat (E02, F01–F05, R2).

Inscription → connexion → commande → paiement sur la page hébergée du PSP (carte factice)
→ notification signée → file d'attente (outbox) → transmission à Odoo en mTLS via le WAF.

Usage :  python scripts/test-commande.py        (bibliothèque standard uniquement)
La vérification côté ERP se fait ensuite avec :
  docker compose exec -T boutique-db psql -U boutique -d boutique -c "select kind,status,attempts from outbox"
"""
import http.cookiejar, os, re, socket, ssl, sys, time, urllib.parse, urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # console Windows (cp1252)

HOTE, PSP = "ostral.local", os.environ.get("PSP_URL", "http://localhost:4000")
CA = os.path.join(os.path.dirname(__file__), "..", "certs", "ca.crt")

# Résolution forcée d'ostral.local vers l'hôte (inutile si le fichier hosts est déjà renseigné)
_orig = socket.getaddrinfo
socket.getaddrinfo = lambda h, *a, **k: _orig("127.0.0.1" if h == HOTE else h, *a, **k)

ctx = ssl.create_default_context(cafile=CA)
jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                  urllib.request.HTTPCookieProcessor(jar))


def appel(url, data=None):
    corps = urllib.parse.urlencode(data).encode() if data is not None else None
    with web.open(url if url.startswith("http") else f"https://{HOTE}{url}", corps, timeout=20) as r:
        return r.geturl(), r.read().decode("utf-8", "replace")


def champ(html, nom):
    m = re.search(rf'name="{nom}" value="([^"]+)"', html)
    if not m:
        sys.exit(f"champ {nom} introuvable dans la page")
    return m.group(1)


def etape(msg):
    print(f"[test-commande] {msg}")


email = f"client.{int(time.time())}@exemple.fr"
mdp = "Mobilier-Test-2026"

_, page = appel("/register")
url, page = appel("/register", {"_csrf": champ(page, "_csrf"), "full_name": "Client Test",
                                 "email": email, "address_line": "1 rue de la Paix",
                                 "postal_code": "69001", "city": "Lyon", "password": mdp})
etape(f"inscription de {email} → {urllib.parse.urlparse(url).path}")
if "/login" in urllib.parse.urlparse(url).path:
    url, page = appel("/login", {"_csrf": champ(page, "_csrf"), "email": email, "password": mdp})
    etape(f"connexion → {urllib.parse.urlparse(url).path}")

_, page = appel("/products/OST-CHA-001")
url, page = appel("/orders", {"_csrf": champ(page, "_csrf"), "sku": "OST-CHA-001", "quantity": "2"})
ref = urllib.parse.urlparse(url).path.rstrip("/").split("/")[-1]
etape(f"commande créée : {ref}")

url, page = appel(f"/orders/{ref}/pay", {"_csrf": champ(page, "_csrf")})
if not url.startswith(PSP):
    sys.exit(f"redirection PSP attendue, obtenu {url}")
etape(f"redirigé vers la page de paiement hébergée du PSP : {url}  (la boutique ne voit pas la carte, E02)")

url, page = appel(url, {"form_token": champ(page, "form_token"), "holder": "Client Test",
                        "pan": "4242 4242 4242 4242", "exp": "12/29", "cvc": "123", "action": "pay"})
etape(f"paiement validé, retour boutique : {urllib.parse.urlparse(url).path}")

for _ in range(12):
    _, page = appel(f"/orders/{ref}")
    if re.search(r"pay[ée]e|paid", page, re.I):
        etape("statut de la commande : payée (notification HMAC acceptée)")
        break
    time.sleep(2)
else:
    sys.exit("la commande n'est pas passée à l'état payé")
print(f"OK — référence {ref}. Le worker la transmet à Odoo (outbox) dans les secondes qui suivent.")
