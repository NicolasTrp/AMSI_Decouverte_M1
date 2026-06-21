#!/bin/sh
# entrypoint web01 — matérialise flags/identité PER INSTANCE (depuis l'env),
# pose la route de pivot vers le LAN, puis lance supervisord.
# RESTART-SAFE : tout vient de l'env (figé par équipe), réécrit à l'identique.
set -eu

FLAG_WEB_RCE="${FLAG_WEB_RCE:-AMSI_dev_web_rce}"
FLAG_WEB_REVERSE="${FLAG_WEB_REVERSE:-AMSI_dev_web_reverse}"
FLAG_WEB_ROOT="${FLAG_WEB_ROOT:-AMSI_dev_web_root}"
A_POMMIER_PW="${A_POMMIER_PW:-applejack}"
LAN_SUBNET="${LAN_SUBNET:-172.31.20.0/24}"
FIREWALL_DMZ_IP="${FIREWALL_DMZ_IP:-172.31.10.2}"

mkdir -p /etc/licornia /var/log/supervisor /var/www/app/config

# --- 1. Route de PIVOT : web -> LAN via le firewall (NET_ADMIN) --------------
# Permet, depuis un shell sur web01, d'atteindre fileshare/admin (le LAN n'est
# pas publié : c'est tout l'intérêt du pivot). Idempotent.
ip route replace "${LAN_SUBNET}" via "${FIREWALL_DMZ_IP}" 2>/dev/null \
    && echo "[web] route pivot ${LAN_SUBNET} via ${FIREWALL_DMZ_IP} posée." \
    || echo "[web] (route pivot non posée — NET_ADMIN requis)."

# --- 2. [Encodage] identifiants base64 dans une conf laissée par un dev ------
# Lisible www-data après la RCE. Leçon : base64 = encodage, PAS chiffrement.
# Décodé -> 'a.pommier:<mdp>' = compte réutilisé sur le partage SMB (fileshare).
CREDS_B64="$(printf '%s' "a.pommier:${A_POMMIER_PW}" | base64 -w0 2>/dev/null || printf '%s' "a.pommier:${A_POMMIER_PW}" | base64)"
cat > /var/www/app/config/backup.inc.php <<EOF
<?php
// Sauvegarde du connecteur partage RH (Licornia Parc).
// TODO(theo): sortir ce secret du code avant la mise en prod...
// identifiant SMB (encodage base64) :
\$SMB_CREDENTIALS_B64 = '${CREDS_B64}';
// usage : echo \$SMB_CREDENTIALS_B64 | base64 -d   -> user:pass du partage \\\\files
EOF
chmod 640 /var/www/app/config/backup.inc.php
chown www-data:www-data /var/www/app/config/backup.inc.php

# --- 3. [Web] FLAG_WEB_RCE : lisible www-data (1er foothold via injection) ---
rm -f /var/www/flag_user.txt
printf '%s\n' "$FLAG_WEB_RCE" > /var/www/flag_user.txt
chmod 640 /var/www/flag_user.txt; chown www-data:www-data /var/www/flag_user.txt

# --- 4. [OSINT] FLAG_WEB_REVERSE : caché dans l'EXIF de la brochure publique -
# Le site « Notre équipe » donne la convention de login ; la brochure
# téléchargeable porte le flag + l'auteur (a.pommier) dans ses métadonnées.
BROCHURE=/var/www/app/public/brochure-licornia.jpg
if [ -f "$BROCHURE" ]; then
    exiftool -overwrite_original \
        -Artist="a.pommier" \
        -Author="Anais Pommier" \
        -Comment="Licornia Parc - usage interne. Note compo: ${FLAG_WEB_REVERSE}" \
        -XMP:Description="Brochure officielle - convention de login: premiere lettre du prenom + . + nom (ex: a.pommier)" \
        "$BROCHURE" >/dev/null 2>&1 || echo "[web] (exiftool EXIF non écrit)"
    chown www-data:www-data "$BROCHURE"
fi

# --- 5. [Privesc] FLAG_WEB_ROOT : root uniquement (après sudo tar GTFOBins) --
printf '%s\n' "$FLAG_WEB_ROOT" > /root/flag_root.txt
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt

# --- 6. SSH + comptes -------------------------------------------------------
ssh-keygen -A >/dev/null 2>&1 || true
# root VERROUILLÉ : pas de mot de passe → aucun `su root` / login root. La seule
# voie root prévue est sudo tar (GTFOBins). (Sécurité : ne JAMAIS poser un mot de
# passe root en clair ici — l'entrypoint est world-readable, ce serait un bypass.)
passwd -l root >/dev/null 2>&1 || true

echo "[web] Licornia Parc prêt — Apache:${WEB_APP_PORT:-8080}, flags posés, pivot armé."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
