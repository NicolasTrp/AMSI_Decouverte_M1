FROM debian:trixie-slim

# fileshare — partage SMB « Licornia Parc » (LAN). Atteint par PIVOT depuis web01.
# Vulns découverte :
#   - partage SMB anonyme (recon)                         -> FLAG_FILES_RECON
#   - capture .pcap en clair sur le partage (forensique)  -> FLAG_DB_PIVOT
#   - secret caché dans une image (stégano)               -> FLAG_DB_ROOT
#   - backup de hash MD5 crackable (rockyou)              -> accès a.pommier
#   - cron root exécutant un script world-writable        -> FLAG_FILES_ROOT
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        samba samba-common-bin smbclient \
        openssh-server supervisor cron \
        python3 procps iproute2 \
        curl ca-certificates netcat-openbsd vim-tiny binutils \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/sshd /var/log/supervisor /opt/licornia /etc/licornia \
            /srv/public /srv/public/backup /srv/rh

# Groupe + comptes employés (UNIX = base SMB et SSH). Mots de passe posés au
# runtime (entrypoint) depuis l'env (réutilisés, crackables).
RUN set -eux; \
    groupadd employes; \
    for u in a.pommier f.delcroix r.thibault; do \
        useradd -m -s /bin/bash -g employes "$u"; \
    done

COPY src/generate_pcap.py /opt/licornia/generate_pcap.py
COPY assets/photo-poney.jpg /opt/licornia/photo-poney.jpg
COPY assets/id_admin /opt/licornia/id_admin
COPY smb/smb.conf /etc/samba/smb.conf
COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
