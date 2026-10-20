# OSTRAL — Lot C — Contrôleur de domaine Active Directory OSTRAL.LOCAL (Z5, actif le plus critique S3)
# Base officielle Debian à tag fixé (E12) + paquets Samba de la distribution (mises à jour de
# sécurité Debian, maintenable). Le provisionnement est fait au premier démarrage (entrypoint).
FROM debian:12.15-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    SAMBA_TARGETDIR=/var/lib/samba/ad \
    KRB5_CONFIG=/var/lib/samba/ad/private/krb5.conf

# Paquets :
#  - samba-ad-dc / samba-ad-provision : démon « samba » en rôle DC et données de provisionnement ;
#  - winbind, libnss-winbind, libpam-winbind : résolution des identités du domaine ;
#  - krb5-user : outils Kerberos ; ldb-tools / ldap-utils / smbclient : diagnostic ;
#  - openssl : certificat LDAPS/STARTTLS ; tini : PID 1 (relais des signaux, zombies).
# Configuration par défaut supprimée : toute la configuration vit dans le volume (targetdir) ;
# les chemins standard pointent dessus pour que l'administration (samba-tool, via le bastion Z6)
# fonctionne sans option -s.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision \
      winbind libnss-winbind libpam-winbind krb5-user \
      ldb-tools ldap-utils smbclient openssl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/samba/smb.conf /etc/krb5.conf \
 && ln -s /var/lib/samba/ad/etc/smb.conf /etc/samba/smb.conf \
 && ln -s /var/lib/samba/ad/private/krb5.conf /etc/krb5.conf \
 && install -d -m 0750 /var/log/samba \
 && install -d -m 0755 /export/tls /etc/ostral

# Paramètres globaux durcis (F08, journaux d'audit pour le SIEM) inclus dans smb.conf
COPY --chmod=0644 ostral-global.conf /etc/ostral/ostral-global.conf
COPY --chmod=0755 entrypoint.sh /usr/local/sbin/ostral-samba-entrypoint.sh

# F08 : ports d'authentification uniquement (documentaire, rien n'est publié sur l'hôte)
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 636/tcp 445/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/sbin/ostral-samba-entrypoint.sh"]
