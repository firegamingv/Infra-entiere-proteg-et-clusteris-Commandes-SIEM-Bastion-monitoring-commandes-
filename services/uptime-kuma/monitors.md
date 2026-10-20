# Uptime Kuma : sondes de disponibilité OSTRAL (E11, F18)

Uptime Kuma 1.23.17 (conteneur `uptime-kuma`), adresses 10.10.7.30 (Z7), 10.10.0.30 (sonde « Internet », Z0) et 10.10.3.40 (Z3).
Il n'est pas publié sur l'hôte. L'interface est accessible par le VPN d'administration à l'adresse `http://10.10.7.30:3001`.

## Import des sondes

L'API d'Uptime Kuma passe par socket.io et n'est pas une API REST simple. On importe donc un fichier de sauvegarde :

1. Ouvrir `http://10.10.7.30:3001`, puis créer le compte administrateur. C'est un compte local, indépendant de l'AD.
2. Aller dans **Paramètres > Sauvegarde > Importer**, choisir `services/uptime-kuma/monitors-backup.json`, cocher « Ignorer les existants », puis cliquer sur **Importer**.
3. Aller dans **Paramètres > Notifications** pour créer les canaux d'astreinte, puis les associer aux sondes (voir le tableau). Le fichier ne contient pas de notification, car il n'y a ni passerelle SMS ni SMTP dans la maquette.
4. Les jetons des sondes « push » (`OstralBackupHourly01`, `OstralBackupNightly01`) doivent correspondre aux URL du `.env` :
   `UPTIME_KUMA_PUSH_HOURLY=http://uptime-kuma:3001/api/push/OstralBackupHourly01`. Si vous changez un jeton dans l'interface, mettez aussi le `.env` à jour.

## Sondes et seuils (dossier p. 12)

| # | Sonde | Cible | Intervalle | Déclenchement | Alerte |
|---|-------|-------|-----------|---------------|--------|
| 1 | Boutique vue d'Internet | `https://ostral.local:8443/` (résolu en 10.10.0.10 par `extra_hosts`, TLS vérifié avec l'AC OSTRAL) | 60 s | 2 échecs consécutifs (`maxretries=1`). Détection en moins de 3 min, donc moins de 5 min (E11) | SMS à l'astreinte |
| 2 | Boutique : temps de réponse | même URL, délai d'attente 2 s | 60 s | 5 dépassements consécutifs, soit plus de 2 s pendant 5 min | e-mail |
| 3 | ERP Odoo | `http://odoo:8069/web/health` (mot-clé `pass`, z3_servers) | 60 s | 3 échecs | e-mail |
| 4 | WAF : entrée publique HTTPS | TCP 10.10.0.10:8443 | 60 s | 3 échecs | e-mail |
| 5 | admin-target SSH | TCP 10.10.3.30:22 | 120 s | 3 échecs | e-mail |
| 6 | Bastion Guacamole web | TCP 10.10.6.10:8080 | 120 s | 3 échecs | e-mail |
| 7 | VPN WireGuard | ping 10.10.7.5 | 120 s | 3 échecs | e-mail |
| 8 | Wazuh manager | TCP 10.10.7.20:1514 (profil `siem`) | 120 s | 3 échecs | e-mail |
| 9 | Wazuh dashboard | `https://10.10.7.22:5601/` (profil `siem`) | 120 s | 3 échecs | e-mail |
| 10 | Sauvegarde horaire | push depuis `backup` | 65 min | battement absent ou `status=down` | e-mail + ticket |
| 11 | Sauvegarde nocturne | push depuis `backup` | 25 h | battement absent ou `status=down` | e-mail + ticket |

## Écarts et limites

- **La sonde 1 ne vise pas `/healthz`.** Côté WAF, la route `/healthz` est réservée à 127.0.0.1 par le lot B et répond 404 depuis l'extérieur. La sonde externe vérifie donc la page d'accueil `/`, qui passe par la chaîne complète WAF puis boutique. Pour viser l'IP brute, on peut utiliser `https://10.10.0.10:8443/` avec l'en-tête `{"Host":"ostral.local"}` et « Ignorer TLS » (le SNI est alors l'IP), mais cette variante est moins stricte.
- **Uptime Kuma 1.23 n'a pas d'alerte sur le temps de réponse.** Le seuil « plus de 2 s pendant 5 min » est obtenu par un délai d'attente de 2 s et 4 nouvelles tentatives.
- **Erreurs 5xx supérieures à 2 % :** ce seuil n'est pas mesurable par Uptime Kuma. Il est couvert par la règle Wazuh 100206 (volume de 5xx dans `waf_access.json`).
- **Disque, mémoire et CPU supérieurs à 85 % :** ce seuil est hors périmètre d'Uptime Kuma. La règle Wazuh 100900 couvre le disque. Zabbix est envisagé si le parc grandit (p. 12).
- **Zones non couvertes :** les sondes ne couvrent que les zones auxquelles Uptime Kuma est relié (Z0, Z3, Z7), selon SPEC. Samba AD (Z5), les bases (Z4) et `minio-offsite` ne sont pas joignables depuis Uptime Kuma. Ils sont surveillés indirectement : par Odoo (base, LDAP) et par le journal de sauvegarde (hors site).
