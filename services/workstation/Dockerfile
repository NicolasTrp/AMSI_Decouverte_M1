FROM debian:trixie-slim

# admin (service `workstation`) — poste d'administration de Julien Martin (LAN).
# Cible finale. Atteint par SSH (clé loot sur fileshare). Vulns découverte :
#   - binaire SUID `vault` : buffer overflow ret2win      -> root  (FLAG_WS_ROOT)
#   - binaire SUID `backoffice-check` : reverse XOR        -> trophée (FLAG_FINAL)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-server supervisor cron \
        procps iproute2 ca-certificates vim-tiny \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/sshd /var/log/supervisor /opt/shopxpress /etc/shopxpress

# Compte de l'admin (login SSH par CLÉ uniquement).
RUN useradd -m -s /bin/bash j.martin

# SSH clé-only : pas de login par mot de passe, root par clé interdit aussi.
RUN sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config \
 && sed -ri 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Compilation des deux binaires SUID (gcc retiré ensuite pour alléger l'image).
COPY src/vault.c /tmp/vault.c
COPY src/backoffice-check.c /tmp/backoffice-check.c
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends gcc libc6-dev; \
    gcc -fno-stack-protector -no-pie -O0 -o /usr/local/bin/vault /tmp/vault.c; \
    gcc -no-pie -O0 -o /usr/local/bin/backoffice-check /tmp/backoffice-check.c; \
    rm -f /tmp/vault.c /tmp/backoffice-check.c; \
    chown root:root /usr/local/bin/vault /usr/local/bin/backoffice-check; \
    chmod 4755 /usr/local/bin/vault /usr/local/bin/backoffice-check; \
    apt-get purge -y gcc libc6-dev; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*

# Clé publique autorisée pour j.martin (la privée est lootée sur fileshare).
COPY src/authorized_keys /home/j.martin/.ssh/authorized_keys
RUN chown -R j.martin:j.martin /home/j.martin/.ssh \
 && chmod 700 /home/j.martin/.ssh \
 && chmod 600 /home/j.martin/.ssh/authorized_keys

COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
