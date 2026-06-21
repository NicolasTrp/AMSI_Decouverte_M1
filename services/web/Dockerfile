FROM debian:trixie-slim

# web — boutique en ligne « ShopXpress » (DMZ, point d'entrée).
# Init = supervisord (cron + sshd + Apache/PHP). 3 vulns web découverte :
#   - SQLi sur /connexion.php (auth bypass)            -> accès back-office gérant
#   - path traversal sur /telecharger.php (file read)  -> lecture de fichiers serveur
#   - upload PHP non filtré (/admin/upload.php)         -> webshell -> RCE www-data
#   + privesc : sudo NOPASSWD sur tar (GTFOBins)        -> root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        apache2 libapache2-mod-php php-cli php-sqlite3 \
        openssh-server supervisor cron sudo \
        iputils-ping iproute2 procps \
        curl ca-certificates netcat-openbsd vim-tiny \
        libimage-exiftool-perl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/sshd /var/log/supervisor

# ── VULN intentionnelle : sudo NOPASSWD sur tar (GTFOBins) pour www-data ─────
# Prétexte « réaliste » : script de déploiement/sauvegarde laissé par le dev.
# www-data -> root via :  sudo tar -cf /dev/null /dev/null --checkpoint=1 \
#                              --checkpoint-action=exec=/bin/sh
RUN set -eux; \
    printf '# Deploiement ShopXpress (laisse par l equipe dev - NE PAS commiter en prod)\nwww-data ALL=(root) NOPASSWD: /usr/bin/tar\n' \
        > /etc/sudoers.d/40-deploy; \
    chmod 0440 /etc/sudoers.d/40-deploy; \
    visudo -cf /etc/sudoers.d/40-deploy

# ── Application web ─────────────────────────────────────────────────────────
COPY app /var/www/app
RUN chown -R www-data:www-data /var/www/app

# ── Apache : DocumentRoot = app/public, port 8080 ───────────────────────────
# (mod_php exécute .php partout sous le docroot — y compris /uploads → RCE)
RUN set -eux; \
    sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf; \
    { echo '<VirtualHost *:8080>'; \
      echo '  DocumentRoot /var/www/app/public'; \
      echo '  <Directory /var/www/app/public>'; \
      echo '    AllowOverride None'; \
      echo '    Require all granted'; \
      echo '    Options -Indexes'; \
      echo '    DirectoryIndex index.php index.html'; \
      echo '  </Directory>'; \
      echo '  ErrorLog /var/log/apache2/error.log'; \
      echo '  CustomLog /var/log/apache2/access.log combined'; \
      echo '</VirtualHost>'; } > /etc/apache2/sites-available/shopxpress.conf; \
    a2dissite 000-default >/dev/null 2>&1 || true; \
    a2ensite shopxpress >/dev/null

COPY supervisord.conf /etc/supervisor/conf.d/ctf.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
