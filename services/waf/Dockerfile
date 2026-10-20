# =============================================================================
# OSTRAL — Lot B : WAF / reverse proxy de la DMZ (Z2)
# nginx + ModSecurity v3 + OWASP CRS 4 (image officielle OWASP, tag daté immuable, E12).
#
# On ne fait qu'ajouter la configuration OSTRAL par-dessus l'image officielle :
#   - l'image génère sa configuration au démarrage depuis /etc/nginx/templates/*.template
#     (envsubst de l'image nginx officielle : seules les variables d'environnement
#     DÉFINIES sont substituées, les variables nginx en minuscules ($host…) sont intactes) ;
#   - nos templates remplacent nginx.conf, conf.d/default.conf et conf.d/logging.conf
#     de l'image et ajoutent les vhosts F01 (public) et F04/F05 (API ERP mTLS).
# L'image tourne déjà en utilisateur non-root « nginx » (uid 101) et écoute 8080/8443.
# =============================================================================
FROM owasp/modsecurity-crs:4.30.0-nginx-alpine-202610180210

# Valeurs par défaut des variables OSTRAL utilisées dans les templates (surchargées par
# compose/z2-dmz.yml) : garantit qu'aucun ${VAR} ne reste non substitué au démarrage.
ENV WAF_GLOBAL_RATE=20r/s \
    WAF_GLOBAL_BURST=40 \
    WAF_AUTH_RATE=10r/m \
    WAF_AUTH_BURST=5 \
    WAF_CONN_PER_IP=30 \
    WAF_MAX_BODY_SIZE=1m \
    WAF_HSTS_MAX_AGE=31536000

USER root

# Journaux (E08) : /var/log/nginx sera le volume nommé logs_waf. Docker initialise un
# volume neuf avec le contenu ET les droits du répertoire de l'image : on le rend donc
# accessible en écriture à nginx (uid 101) et lisible par le SIEM. Pas de chown -R : access.log / error.log de
# l'image sont des liens vers /dev/stdout et /dev/stderr qu'il ne faut pas suivre.
RUN set -eux; \
    mkdir -p /var/log/nginx; \
    chown nginx:nginx /var/log/nginx; \
    chmod 0755 /var/log/nginx

# Configuration OSTRAL (fusionnée avec les templates de l'image, mêmes noms = remplacement)
COPY --chown=root:root templates/ /etc/nginx/templates/

USER nginx
