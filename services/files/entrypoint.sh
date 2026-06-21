#!/bin/sh
# entrypoint fileshare — matérialise flags/identifiants PER INSTANCE, prépare les
# partages SMB, la capture forensique, la stégano, le backup MD5, le cron vulnérable,
# puis lance supervisord. RESTART-SAFE.
set -eu

S_MOREL_PW="${S_MOREL_PW:-superman}"
L_PETIT_PW="${L_PETIT_PW:-liverpool}"
N_ROUX_PW="${N_ROUX_PW:-chocolate}"
STEGO_SECRET="${STEGO_SECRET:-stock-backup-2024}"
FLAG_FILES_RECON="${FLAG_FILES_RECON:-AMSI_dev_files_recon}"
FLAG_DB_PIVOT="${FLAG_DB_PIVOT:-AMSI_dev_db_pivot}"
FLAG_DB_ROOT="${FLAG_DB_ROOT:-AMSI_dev_db_root}"
FLAG_FILES_RCE="${FLAG_FILES_RCE:-AMSI_dev_files_rce}"
FLAG_FILES_ROOT="${FLAG_FILES_ROOT:-AMSI_dev_files_root}"

mkdir -p /etc/shopxpress /var/log/supervisor /srv/public/backup /srv/stock

# --- 1. Mots de passe UNIX (réutilisés / crackables) + SSH ------------------
echo "s.morel:${S_MOREL_PW}" | chpasswd
echo "l.petit:${L_PETIT_PW}" | chpasswd
echo "n.roux:${N_ROUX_PW}"   | chpasswd
# root VERROUILLÉ : pas de `su root`. La seule voie root prévue est le cron
# world-writable. (Les mdp employés ci-dessus viennent de l'env — PAS en clair
# dans ce script ; root, lui, ne doit avoir AUCUN mot de passe.)
passwd -l root >/dev/null 2>&1 || true

# --- 2. Comptes SMB (s.morel : même mot de passe → accès partage [stock]) ----
( echo "${S_MOREL_PW}"; echo "${S_MOREL_PW}" ) | smbpasswd -s -a s.morel >/dev/null 2>&1 || true

# --- 3. [Recon] partage public anonyme : note interne avec le flag de recon --
cat > /srv/public/LISEZMOI.txt <<EOF
Partage public ShopXpress.
Merci de ne RIEN déposer de sensible ici (accessible à tout le personnel).
- capture.pcap : export du test du service de sauvegarde (à archiver)
- photo-produit.jpg : visuel pour la fiche produit
- backup/ : exports techniques
EOF
cat > /srv/public/note-interne.txt <<EOF
Note interne (visible de tous, oui on sait, à corriger) :
Le partage STOCK est réservé à s.morel. Token de recon : ${FLAG_FILES_RECON}
EOF

# --- 4. [Forensique] capture .pcap en clair (login service de sauvegarde) ----
python3 /opt/shopxpress/generate_pcap.py "${FLAG_DB_PIVOT}" /srv/public/capture.pcap >/dev/null 2>&1 || true

# --- 5. [Stégano] flag caché dans l'image (data appended ; strings/binwalk) --
cp -f /opt/shopxpress/photo-produit.jpg /srv/public/photo-produit.jpg
{
  printf '\n--- ShopXpress backup ---\n'
  printf 'passphrase: %s\n' "${STEGO_SECRET}"
  printf 'FLAG: %s\n' "${FLAG_DB_ROOT}"
} >> /srv/public/photo-produit.jpg

# --- 6. [Crypto] backup de hash MD5 (à craquer avec john/hashcat + rockyou) --
md5_of() { printf '%s' "$1" | md5sum | cut -d' ' -f1; }
cat > /srv/public/backup/hashes.txt <<EOF
# export annuaire (algo: md5) — ShopXpress
s.morel:$(md5_of "${S_MOREL_PW}")
l.petit:$(md5_of "${L_PETIT_PW}")
n.roux:$(md5_of "${N_ROUX_PW}")
EOF

# --- 7. [Crypto suite] flag STOCK lisible par s.morel (après crack) ----------
rm -f /srv/stock/flag_acces.txt
printf 'Acces STOCK confirme. %s\n' "${FLAG_FILES_RCE}" > /srv/stock/flag_acces.txt
# 600 (s.morel SEUL) : 640+groupe employes laissait l.petit/n.roux le lire aussi
# (même groupe primaire) → gating « s.morel spécifiquement » contourné.
# L'accès SMB //stock se fait en tant que s.morel (propriétaire) → inchangé.
chmod 600 /srv/stock/flag_acces.txt; chown s.morel:employes /srv/stock/flag_acces.txt
chmod 750 /srv/stock; chown root:employes /srv/stock

# Perms partage public (lisible par l'invité Samba = nobody)
chmod 755 /srv/public /srv/public/backup
chmod 644 /srv/public/*.txt /srv/public/*.pcap /srv/public/*.jpg /srv/public/backup/*.txt 2>/dev/null || true

# --- 8. [Privesc] cron root exécutant un script WORLD-WRITABLE ---------------
cat > /opt/shopxpress/maintenance.sh <<'EOF'
#!/bin/sh
# Maintenance ShopXpress (exécutée par cron en root). Script éditable par l'équipe.
echo "[maint] $(date) espace disque:" >> /var/log/shopxpress-maint.log
df -h / >> /var/log/shopxpress-maint.log 2>&1
EOF
chmod 666 /opt/shopxpress/maintenance.sh        # VULN : modifiable par tout le monde
cat > /etc/cron.d/shopxpress-maint <<'EOF'
# Maintenance disque toutes les minutes (root).
* * * * * root /bin/sh /opt/shopxpress/maintenance.sh
EOF
chmod 644 /etc/cron.d/shopxpress-maint
: > /var/log/shopxpress-maint.log; chmod 644 /var/log/shopxpress-maint.log

# --- 9. [Privesc] flag root + loot pour la machine admin ---------------------
printf '%s\n' "${FLAG_FILES_ROOT}" > /root/flag_root.txt
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt
# Clé SSH de l'admin Julien Martin (loot après root sur files).
cp -f /opt/shopxpress/id_admin /root/id_admin
chmod 600 /root/id_admin; chown root:root /root/id_admin
cat > /root/notes-admin.txt <<EOF
Pense-bête (Julien) :
Mon poste d'admin est sur le LAN (admin / workstation, 172.31.20.12).
J'y accède en SSH avec ma clé : ssh -i id_admin j.martin@172.31.20.12
EOF
chmod 600 /root/notes-admin.txt; chown root:root /root/notes-admin.txt

# --- 10. SSH host keys ------------------------------------------------------
ssh-keygen -A >/dev/null 2>&1 || true

echo "[files] fileshare prêt — SMB(public/stock), pcap+stégano+hashes, cron armé, flags posés."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
