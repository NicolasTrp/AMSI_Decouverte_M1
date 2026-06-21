FROM debian:trixie-slim

# admin (service `workstation`) — poste d'administration de Camille Vasseur (LAN).
# Cible finale. Atteint par SSH (clé loot sur fileshare). Vulns découverte :
#   - binaire SUID `vault` : buffer overflow ret2win   -> root  (FLAG_WS_ROOT)
#   - binaire SUID `licornia-check` : reverse XOR       -> trophée (FLAG_FINAL)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-server supervisor cron \
        procps iproute2 ca-certificates vim-tiny \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/sshd /var/log/supervisor /opt/licornia /etc/licornia

# Compte de l'admin (login SSH par CLÉ uniquement).
RUN useradd -m -s /bin/bash c.vasseur

# Compilation des deux binaires SUID (gcc retiré ensuite pour alléger l'image).
COPY src/vault.c /tmp/vault.c
COPY src/licornia-check.c /tmp/licornia-check.c
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends gcc libc6-dev; \
    gcc -fno-stack-protector -no-pie -O0 -o /usr/local/bin/vault /tmp/vault.c; \
    gcc -no-pie -O0 -o /usr/local/bin/licornia-check /tmp/licornia-check.c; \
    rm -f /tmp/vault.c /tmp/licornia-check.c; \
    chown root:root /usr/local/bin/vault /usr/local/bin/licornia-check; \
    chmod 4755 /usr/local/bin/vault /usr/local/bin/licornia-check; \
    apt-get purge -y gcc libc6-dev; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

# Clé publique autorisée pour c.vasseur (la privée est lootée sur fileshare).
COPY src/authorized_keys /home/c.vasseur/.ssh/authorized_keys
RUN chown -R c.vasseur:c.vasseur /home/c.vasseur/.ssh \
 && chmod 700 /home/c.vasseur/.ssh \
 && chmod 600 /home/c.vasseur/.ssh/authorized_keys

COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
