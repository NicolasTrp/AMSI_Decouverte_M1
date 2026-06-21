#!/bin/sh
# entrypoint web — boutique « ShopXpress ». Matérialise PER INSTANCE (depuis l'env)
# la base SQLite, les factures, la conf (creds base64), les flags, l'EXIF du
# catalogue, pose la route de pivot, puis lance supervisord. RESTART-SAFE.
set -eu

FLAG_WEB_RCE="${FLAG_WEB_RCE:-AMSI_dev_web_rce}"
FLAG_WEB_REVERSE="${FLAG_WEB_REVERSE:-AMSI_dev_web_reverse}"
FLAG_WEB_ROOT="${FLAG_WEB_ROOT:-AMSI_dev_web_root}"
S_MOREL_PW="${S_MOREL_PW:-superman}"
LAN_SUBNET="${LAN_SUBNET:-172.31.20.0/24}"
FIREWALL_DMZ_IP="${FIREWALL_DMZ_IP:-172.31.10.2}"

mkdir -p /var/log/supervisor \
         /var/www/app/config /var/www/app/data /var/www/app/factures \
         /var/www/app/public/uploads /var/www/private

# --- 1. Route de PIVOT : web -> LAN via le firewall (NET_ADMIN) --------------
# Depuis un shell sur web (post-RCE), atteindre fileshare/admin (LAN non publié).
ip route replace "${LAN_SUBNET}" via "${FIREWALL_DMZ_IP}" 2>/dev/null \
    && echo "[web] route pivot ${LAN_SUBNET} via ${FIREWALL_DMZ_IP} posée." \
    || echo "[web] (route pivot non posée — NET_ADMIN requis)."

# --- 2. [Auth bypass] base SQLite du back-office (compte gérant) -------------
# Le mot de passe est stocké HASHÉ (sha256) → lire shop.db ne donne pas le mdp en
# clair ; la voie prévue est l'injection SQL sur /connexion.php (admin' -- ).
ADMIN_HASH="$(printf '%s' 'ShopXpress-DB-2024-x9k' | sha256sum | cut -d' ' -f1)"
rm -f /var/www/app/data/shop.db
ADMIN_HASH="$ADMIN_HASH" php -r '
$p=getenv("ADMIN_HASH");
$db=new SQLite3("/var/www/app/data/shop.db");
$db->exec("DROP TABLE IF EXISTS users");
$db->exec("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
$st=$db->prepare("INSERT INTO users(username,password,role) VALUES (?,?,?)");
$st->bindValue(1,"admin"); $st->bindValue(2,$p); $st->bindValue(3,"gerant"); $st->execute();
$db->close();
' 2>/dev/null || echo "[web] (seed SQLite échoué — php-sqlite3 ?)"

# --- 3. [Encodage] creds base64 du connecteur STOCK dans la conf -------------
# Lisible via la lecture de fichiers (traversal) ou après la RCE. Leçon : base64
# = encodage, PAS chiffrement. Décodé -> 's.morel:<mdp>' = compte SMB (fileshare).
CREDS_B64="$(printf '%s' "s.morel:${S_MOREL_PW}" | base64 -w0 2>/dev/null || printf '%s' "s.morel:${S_MOREL_PW}" | base64)"
cat > /var/www/app/config/config.php <<EOF
<?php
// Configuration ShopXpress — back-office
\$DB_PATH = '/var/www/app/data/shop.db';

// Connecteur partage STOCK (montage SMB \\\\files\\stock)
// TODO(k.dubois): sortir ce secret du code avant la mise en prod...
// identifiant SMB (encodage base64) :
\$SMB_CREDENTIALS_B64 = '${CREDS_B64}';
// usage : echo \$SMB_CREDENTIALS_B64 | base64 -d   -> user:pass du partage \\\\files\\stock
EOF

# --- 4. Factures factices (contexte du /telecharger.php?facture=) ------------
cat > /var/www/app/factures/facture-2024-0142.txt <<'EOF'
ShopXpress — Facture n°2024-0142
Client : Dupont SARL    Montant : 1 249,90 €    Statut : payée
EOF
cat > /var/www/app/factures/facture-2024-0187.txt <<'EOF'
ShopXpress — Facture n°2024-0187
Client : Martin & Fils  Montant : 389,00 €      Statut : en attente
EOF

# --- 5. [File read] FLAG_WEB_REVERSE : fichier protégé HORS docroot ----------
# Atteignable UNIQUEMENT par le path traversal de /telecharger.php
# (?facture=../../private/rapport-ventes.txt). Lu par www-data (process Apache).
rm -f /var/www/private/rapport-ventes.txt
cat > /var/www/private/rapport-ventes.txt <<EOF
RAPPORT DE VENTES — CONFIDENTIEL (ne pas diffuser)
Total trimestre : 184 200 €
Note interne : ${FLAG_WEB_REVERSE}
EOF

# --- 6. [RCE] FLAG_WEB_RCE : dans l'ENV du serveur (gate par EXÉCUTION) -------
# PAS écrit sur disque : sinon la path traversal (lecture www-data) le donnerait
# SANS la RCE. Il reste dans l'environnement du process serveur (injecté par
# compose) → seul un webshell qui EXÉCUTE une commande l'obtient (env / printenv /
# cat /proc/self/environ). flag_user.txt ne contient qu'un INDICE : c'est la leçon
# « une lecture de fichier ≠ une exécution de code ».
export FLAG_WEB_RCE
rm -f /var/www/flag_user.txt
cat > /var/www/flag_user.txt <<'EOF'
Jeton de l'etape RCE : il n'est PAS stocke sur le disque.
Une LECTURE de fichier (ex. via /telecharger.php) ne suffit pas : il faut EXECUTER
une commande (RCE). Le jeton est dans l'environnement du serveur :
    env | grep AMSI        (ou: printenv FLAG_WEB_RCE)
EOF

# --- 7. [Privesc] FLAG_WEB_ROOT : root uniquement (après sudo tar GTFOBins) ---
printf '%s\n' "$FLAG_WEB_ROOT" > /root/flag_root.txt

# --- 8. EXIF du catalogue (recon, PAS un flag) ------------------------------
CATALOGUE=/var/www/app/public/catalogue.jpg
if [ -f "$CATALOGUE" ]; then
    exiftool -overwrite_original \
        -Artist="k.dubois" \
        -Author="Karim Dubois" \
        -Comment="ShopXpress - catalogue interne. Espace gerant: /connexion.php" \
        -XMP:Description="Comptes du personnel: premiere lettre du prenom + . + nom (ex: s.morel)" \
        "$CATALOGUE" >/dev/null 2>&1 || echo "[web] (exiftool EXIF non écrit)"
fi

# --- 9. Permissions (chmod AVANT chown : DAC_OVERRIDE sans FOWNER) -----------
chmod 640 /var/www/app/config/config.php
chmod 750 /var/www/private
chmod 640 /var/www/private/rapport-ventes.txt
chmod 640 /var/www/flag_user.txt
chmod 644 /var/www/app/factures/*.txt
chmod 755 /var/www/app/public/uploads
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt
chown -R www-data:www-data /var/www/app/config /var/www/app/data \
        /var/www/app/factures /var/www/app/public/uploads \
        /var/www/private /var/www/flag_user.txt "$CATALOGUE" 2>/dev/null || true

# --- 10. SSH + comptes ------------------------------------------------------
ssh-keygen -A >/dev/null 2>&1 || true
# root VERROUILLÉ : pas de mot de passe → aucun `su root` / login root. La seule
# voie root prévue est sudo tar (GTFOBins). (Sécurité : ne JAMAIS poser un mot de
# passe root en clair ici — l'entrypoint est world-readable, ce serait un bypass.)
passwd -l root >/dev/null 2>&1 || true

# --- 11. Durcissement : NE PAS exposer REVERSE/ROOT ni les creds dans l'env des
# services. Sinon un webshell www-data ferait `printenv FLAG_WEB_ROOT` pour sauter
# la privesc, ou `printenv S_MOREL_PW` pour sauter le crack. Seul FLAG_WEB_RCE
# reste (= la récompense voulue de la RCE). `docker exec` conserve l'env complet du
# conteneur (verify-chain lit donc toujours les valeurs attendues).
unset FLAG_WEB_REVERSE FLAG_WEB_ROOT S_MOREL_PW

echo "[web] ShopXpress prêt — Apache:${WEB_APP_PORT:-8080}, SQLi+traversal+upload armés, flags posés."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
