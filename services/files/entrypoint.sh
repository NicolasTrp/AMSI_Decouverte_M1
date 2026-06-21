#!/bin/sh
# entrypoint fileshare — matérialise flags/identifiants PER INSTANCE, prépare les
# partages SMB, la capture forensique, la stégano, le backup MD5, le cron vulnérable,
# puis lance supervisord. RESTART-SAFE.
set -eu

A_POMMIER_PW="${A_POMMIER_PW:-applejack}"
F_DELCROIX_PW="${F_DELCROIX_PW:-fluttershy}"
R_THIBAULT_PW="${R_THIBAULT_PW:-rainbowdash}"
STEGO_SECRET="${STEGO_SECRET:-p0ney-cache}"
FLAG_FILES_RECON="${FLAG_FILES_RECON:-AMSI_dev_files_recon}"
FLAG_DB_PIVOT="${FLAG_DB_PIVOT:-AMSI_dev_db_pivot}"
FLAG_DB_ROOT="${FLAG_DB_ROOT:-AMSI_dev_db_root}"
FLAG_FILES_RCE="${FLAG_FILES_RCE:-AMSI_dev_files_rce}"
FLAG_FILES_ROOT="${FLAG_FILES_ROOT:-AMSI_dev_files_root}"

mkdir -p /etc/licornia /var/log/supervisor /srv/public/backup /srv/rh

# --- 1. Mots de passe UNIX (réutilisés / crackables) + SSH ------------------
echo "a.pommier:${A_POMMIER_PW}"  | chpasswd
echo "f.delcroix:${F_DELCROIX_PW}" | chpasswd
echo "r.thibault:${R_THIBAULT_PW}" | chpasswd
echo 'root:ctf-files-decouverte' | chpasswd

# --- 2. Comptes SMB (a.pommier : même mot de passe → accès partage [rh]) -----
( echo "${A_POMMIER_PW}"; echo "${A_POMMIER_PW}" ) | smbpasswd -s -a a.pommier >/dev/null 2>&1 || true

# --- 3. [Recon] partage public anonyme : note interne avec le flag de recon --
cat > /srv/public/LISEZMOI.txt <<EOF
Partage public Licornia Parc.
Merci de ne RIEN déposer de sensible ici (accessible à tout le personnel).
- capture.pcap : export du test de l'agent de sauvegarde (à archiver)
- photo-poney.jpg : visuel pour la nouvelle brochure
- backup/ : exports techniques
EOF
cat > /srv/public/note-interne.txt <<EOF
Note interne (visible de tous, oui on sait, à corriger) :
Le partage RH est réservé à a.pommier. Token de recon : ${FLAG_FILES_RECON}
EOF

# --- 4. [Forensique] capture .pcap en clair (login agent de sauvegarde) ------
python3 /opt/licornia/generate_pcap.py "${FLAG_DB_PIVOT}" /srv/public/capture.pcap >/dev/null 2>&1 || true

# --- 5. [Stégano] flag caché dans l'image (data appended ; strings/binwalk) --
cp -f /opt/licornia/photo-poney.jpg /srv/public/photo-poney.jpg
{
  printf '\n--- Licornia steg ---\n'
  printf 'passphrase: %s\n' "${STEGO_SECRET}"
  printf 'FLAG: %s\n' "${FLAG_DB_ROOT}"
} >> /srv/public/photo-poney.jpg

# --- 6. [Crypto] backup de hash MD5 (à craquer avec john/hashcat + rockyou) --
md5_of() { printf '%s' "$1" | md5sum | cut -d' ' -f1; }
cat > /srv/public/backup/hashes.txt <<EOF
# export annuaire (algo: md5) — Licornia Parc
a.pommier:$(md5_of "${A_POMMIER_PW}")
f.delcroix:$(md5_of "${F_DELCROIX_PW}")
r.thibault:$(md5_of "${R_THIBAULT_PW}")
EOF

# --- 7. [Crypto suite] flag RH lisible par a.pommier (après crack) -----------
rm -f /srv/rh/flag_rce.txt
printf 'Acces RH confirme. %s\n' "${FLAG_FILES_RCE}" > /srv/rh/flag_rce.txt
chmod 640 /srv/rh/flag_rce.txt; chown a.pommier:employes /srv/rh/flag_rce.txt
chmod 750 /srv/rh; chown root:employes /srv/rh

# Perms partage public (lisible par l'invité Samba = nobody)
chmod 755 /srv/public /srv/public/backup
chmod 644 /srv/public/*.txt /srv/public/*.pcap /srv/public/*.jpg /srv/public/backup/*.txt 2>/dev/null || true

# --- 8. [Privesc] cron root exécutant un script WORLD-WRITABLE ---------------
cat > /opt/licornia/maintenance.sh <<'EOF'
#!/bin/sh
# Maintenance Licornia (exécutée par cron en root). Script éditable par l'équipe.
echo "[maint] $(date) espace disque:" >> /var/log/licornia-maint.log
df -h / >> /var/log/licornia-maint.log 2>&1
EOF
chmod 666 /opt/licornia/maintenance.sh          # VULN : modifiable par tout le monde
cat > /etc/cron.d/licornia-maint <<'EOF'
# Maintenance disque toutes les minutes (root).
* * * * * root /bin/sh /opt/licornia/maintenance.sh
EOF
chmod 644 /etc/cron.d/licornia-maint
: > /var/log/licornia-maint.log; chmod 644 /var/log/licornia-maint.log

# --- 9. [Privesc] flag root + loot pour la machine admin ---------------------
printf '%s\n' "${FLAG_FILES_ROOT}" > /root/flag_root.txt
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt
# Clé SSH de l'admin Camille Vasseur (loot après root sur files).
cp -f /opt/licornia/id_admin /root/id_admin
chmod 600 /root/id_admin; chown root:root /root/id_admin
cat > /root/notes-admin.txt <<EOF
Pense-bête (Camille) :
Mon poste d'admin est sur le LAN (admin / workstation, 172.31.20.12).
J'y accède en SSH avec ma clé : ssh -i id_admin c.vasseur@172.31.20.12
EOF
chmod 600 /root/notes-admin.txt; chown root:root /root/notes-admin.txt

# --- 10. SSH host keys ------------------------------------------------------
ssh-keygen -A >/dev/null 2>&1 || true

echo "[files] fileshare prêt — SMB(public/rh), pcap+stégano+hashes, cron armé, flags posés."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
