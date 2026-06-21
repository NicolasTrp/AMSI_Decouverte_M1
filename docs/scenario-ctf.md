# Scénario & guide d'animation — lab découverte « Licornia Parc » (M1)

> **Document staff / encadrant.** À ne PAS distribuer aux étudiants : il contient
> le lore complet, la cartographie des flags, les **indices progressifs** et les
> mécanismes de chaque vulnérabilité. L'énoncé public est dans `docs/enonce.md` ;
> le corrigé pas-à-pas dans `docs/walkthrough.md` ; la topo dans `docs/topology.md`.

---

## 1. Lore — « Licornia Parc »

Le **Licornia Parc** est le parc à licornes préféré de la région : spectacles
arc-en-ciel, balades enchantées et goûters à la paillette. Derrière la façade
féérique, le système d'information a été monté à la va-vite par une petite équipe,
et la sécurité… a galopé loin devant tout le monde.

**Le personnel** (visible sur la page « Notre équipe » du site vitrine) :

| Personne | Rôle | Compte | Mot de passe | Rôle dans le scénario |
|---|---|---|---|---|
| **Camille Vasseur** | Directrice / Admin SI | `c.vasseur` | *(clé SSH only)* | Détient le « domaine » ; sa clé SSH et son poste admin sont la cible finale. |
| **Anaïs Pommier** | Écuries & maintenance | `a.pommier` | `applejack` | Compte réutilisé partout (web → SMB → SSH) : le maillon faible. |
| **Fanny Delcroix** | Vétérinaire | `f.delcroix` | `fluttershy` | Hash présent dans le backup (diversion / entraînement au crack). |
| **Rémi Thibault** | Logistique | `r.thibault` | `rainbowdash` | Idem : hash crackable, compte secondaire. |
| **Théo Berger** | Développeur / IT | `t.berger` | — | **Le coupable** : c'est lui qui a laissé traîner les identifiants en base64 dans une conf de sauvegarde (« TODO: sortir ce secret du code avant la prod… »). |

> 🦄 **Clin d'œil** : tous les mots de passe sont des poneys de *My Little Pony*
> (`applejack`, `fluttershy`, `rainbowdash`, et le mot de passe maître final
> `twilight-sparkle-42`). C'est volontaire : ce sont des mots du dictionnaire
> `rockyou`, donc **crackables**, et ça dédramatise l'exercice.

**Le fil rouge.** Un développeur négligent (Théo) sème un secret encodé sur le
site public. Ce secret ouvre un compte (Anaïs) **réutilisé** sur le partage de
fichiers, où dorment une capture réseau en clair, une image piégée et un backup
de hashs. De fil en aiguille — réutilisation de mot de passe, cron mal fichu, clé
SSH oubliée — l'attaquant rebondit jusqu'au **poste de la directrice** et s'empare
du **mot de passe maître de l'annuaire** : c'est la **prise du domaine**. Morale :
une seule négligence (un secret encodé ≠ chiffré) suffit à dérouler toute la pelote.

---

## 2. Objectifs pédagogiques (M1 — niveau découverte)

À la fin de la séance, l'étudiant doit avoir :

1. **Fait le tour des outils de base** d'un pentest : `nmap`, `whatweb`/`nikto`,
   `gobuster`/`ffuf`, `curl`, `nc`, `exiftool`, `base64`, `sudo -l`/GTFOBins,
   `ssh`/`scp` (`-J`, `-D`), `proxychains`/`chisel`, `smbclient`, `tshark`/Wireshark,
   `strings`/`binwalk`/`steghide`, `john`/`hashcat` + `rockyou`, `objdump`/`gdb`/Ghidra,
   un exploit `python3`/`pwntools`.
2. **Compris une chaîne de compromission réaliste** : foothold → escalade locale →
   mouvement latéral → cible finale ; chaque étape **débloque** la suivante.
3. **Saisi la notion de segmentation & de pivot** : un seul service est exposé ;
   on n'entre dans le réseau interne qu'**en pivotant** par la machine compromise.
4. **Distingué encodage / hachage / chiffrement** : base64 (réversible sans clé),
   MD5 (empreinte → crack par dictionnaire), XOR (chiffrement « jouet » réversible).
5. **Manipulé des permissions UNIX** : SUID, `sudo NOPASSWD`, fichier world-writable,
   clé privée mal rangée — autant de fautes de conf qui mènent à `root`.

**Posture.** Lab **intentionnellement vulnérable**, **isolé**, à usage **pédagogique
autorisé** uniquement. Rien de ce qui est ici ne doit sortir du périmètre du lab.

---

## 3. Cartographie des catégories CTF → 10 flags

Le lab couvre **les 11 catégories** classiques (Recon, Web, OSINT, Encodage,
Forensique, Stéganographie, Crypto/Cracking, Réseau/Pivot, Privesc, Pwn, Reverse)
sous leur **forme débutant**, réparties sur les 10 flags figés du contrat de scoring.

| # | Flag (env) | Catégorie | Machine | Utilisateur cible | Objectif d'apprentissage |
|---|---|---|---|---|---|
| 1 | `FLAG_WEB_RCE`     | **Web** (injection de commande) | web | `www-data` | Comprendre qu'une saisie concaténée dans un shell = RCE ; obtenir un premier *foothold*. |
| 2 | `FLAG_WEB_REVERSE` | **OSINT** (métadonnées EXIF)    | web | `admin`* | Les fichiers publics parlent : EXIF d'une brochure + convention de login. *(bonus)* |
| 3 | `FLAG_WEB_ROOT`    | **Encodage + Privesc**          | web | `root` | base64 ≠ chiffrement ; `sudo -l` + GTFOBins (`tar`) → root. |
| 4 | `FLAG_FILES_RECON` | **Recon réseau / SMB**          | files | `invité` | Énumérer un partage SMB **anonyme** après pivot. |
| 5 | `FLAG_DB_PIVOT`    | **Forensique réseau**           | files | — | Lire une capture `.pcap` : un login passe **en clair**. *(bonus)* |
| 6 | `FLAG_DB_ROOT`     | **Stéganographie**              | files | — | Données cachées **après** une image (`strings`/`binwalk`). *(bonus)* |
| 7 | `FLAG_FILES_RCE`   | **Crypto / Password-cracking**  | files | `a.pommier` | Casser un **hash MD5** au dictionnaire (`john` + `rockyou`). |
| 8 | `FLAG_FILES_ROOT`  | **Privesc système** (cron)      | files | `root` | Un **cron root** exécute un script **world-writable** → injection → root. |
| 9 | `FLAG_WS_ROOT`     | **Pwn** (buffer overflow)       | admin | `root` | BOF **ret2win** sur un SUID sans canari/PIE → root. |
| 10| `FLAG_FINAL`       | **Reverse engineering**         | admin | — | Dé-XOR d'un binaire → mot de passe maître → **prise du domaine**. |

\* Le slug interne du flag #2 (`web_reverse`/« admin ») est cosmétique, hérité du
contrat figé ; **pédagogiquement c'est un challenge OSINT.**

### Épine dorsale (spine) vs bonus

```
        [1]──▶[3]──▶[4]──▶[7]──▶[8]──▶[9]──▶[10]      ← SPINE (bloquante, linéaire)
  web RCE  web root  recon  crack  cron   pwn   final
                 │
        [2] OSINT │ [5] Forensique │ [6] Stégano       ← BONUS (non bloquants)
```

- **Spine (1→3→4→7→8→9→10)** : chaîne obligatoire, chaque flag **débloque** le suivant
  (prérequis CTFd). C'est le chemin minimal « point d'entrée → prise du domaine ».
- **Bonus (2, 5, 6)** : non bloquants, branchés sur la spine pour **couvrir** OSINT,
  Forensique et Stéganographie sans gêner la progression. Idéal pour différencier les
  rythmes : les rapides ramassent les bonus, les autres restent sur la spine.

---

## 4. Le pivot — l'idée centrale à faire passer

> « On ne **voit** que `web`. Tout le reste, il faut **entrer** pour le voir. »

- Un **seul** service est publié sur l'hôte (`web`, le point d'entrée). `files` et
  `admin` sont sur un réseau **interne** (`lan`, `internal: true`) : injoignables
  directement depuis la Kali de l'étudiant.
- Après avoir compromis `web`, l'étudiant dispose d'une machine qui, elle, **a une
  route vers le LAN** (posée par le firewall). Il doit donc **rebondir par `web`**.

**Trois voies, du plus simple au plus « outillé »** (à proposer selon le niveau) :

1. **`ssh -J` (ProxyJump)** — le plus simple si on a un shell SSH sur `web` :
   `ssh -J user@WEB c.vasseur@172.31.20.12`.
2. **`ssh -D` + `proxychains`** — tunnel SOCKS : `ssh -D 1080 user@WEB`, puis
   `proxychains nmap`/`smbclient`/`ssh` vers le LAN.
3. **`chisel`** — quand il n'y a pas de SSH exploitable : `chisel server` côté Kali,
   `chisel client` déposé sur `web`, reverse SOCKS.

> 💡 À l'oral, insister : la segmentation n'a pas disparu (un seul port exposé), elle
> est **franchie** parce que la machine de bordure a été prise. C'est exactement le
> mode opératoire d'une intrusion réelle.

---

## 5. Indices progressifs (à délivrer si un binôme bloque)

Donne **un cran à la fois**. Le niveau 3 est quasi la solution ; ne l'utilise qu'en
dernier recours. **Aucun indice ne révèle la valeur du flag** (elle est lue dans un
fichier une fois l'accès obtenu).

### #1 — `FLAG_WEB_RCE` · Web (injection de commande) · ★
- **I1 (orientation)** : « Le site a un *outil de diagnostic réseau*. Que fait-il
  vraiment côté serveur quand tu testes un hôte ? »
- **I2 (technique)** : « Ta saisie est **concaténée** dans une commande `ping -c 2 …`.
  Rien n'est filtré. Comment enchaîner une **deuxième** commande ? »
- **I3 (quasi-solution)** : « Champ `host` = `127.0.0.1;cat /var/www/flag_user.txt`
  (ou `| id`). Regarde le bloc *Résultat*. »

### #2 — `FLAG_WEB_REVERSE` · OSINT (EXIF) · ★ *(bonus)*
- **I1** : « La page *Notre équipe* propose un téléchargement. Un fichier *officiel*
  contient parfois plus que son image… »
- **I2** : « Récupère `brochure-licornia.jpg` et inspecte ses **métadonnées**. »
- **I3** : « `exiftool brochure-licornia.jpg` → champ *Comment*. Et la convention de
  login (`première lettre + . + nom`) est écrite noir sur blanc sur la page équipe. »

### #3 — `FLAG_WEB_ROOT` · Encodage + Privesc · ★★
- **I1** : « Une fois `www-data`, fouille les fichiers de **configuration / sauvegarde**
  de l'appli. Un dev a laissé un mot doux (`TODO`). »
- **I2** : « `config/backup.inc.php` contient une chaîne **base64**. base64 n'est PAS
  du chiffrement. Décode-la. Puis : qu'as-tu le droit de lancer en `sudo` ? »
- **I3** : « `echo <b64> | base64 -d` → `a.pommier:applejack`. `sudo -l` montre `tar`
  en NOPASSWD → GTFOBins : `sudo tar -cf /dev/null /dev/null --checkpoint=1
  --checkpoint-action=exec=/bin/sh`. »

### #4 — `FLAG_FILES_RECON` · Recon SMB · ★★
- **I1** : « Tu es entré dans le LAN (pivot). Quelles machines, quels ports ? Pense
  **SMB**. »
- **I2** : « `files` (172.31.20.11) expose un partage **anonyme**. Liste-le sans creds. »
- **I3** : « `smbclient -N -L //172.31.20.11` puis `smbclient -N //172.31.20.11/public`,
  récupère `note-interne.txt`. »

### #5 — `FLAG_DB_PIVOT` · Forensique réseau · ★ *(bonus)*
- **I1** : « Le partage public contient un export de test de l'agent de sauvegarde.
  Un fichier `.pcap`… »
- **I2** : « Ouvre la capture. Le protocole utilisé fait passer l'authentification
  **en clair**. »
- **I3** : « `strings capture.pcap | grep -i -E 'user|pass|flag'` (ou Wireshark →
  *Follow TCP Stream*). »

### #6 — `FLAG_DB_ROOT` · Stéganographie · ★★ *(bonus)*
- **I1** : « L'image `photo-poney.jpg` du partage s'affiche normalement… mais pèse un
  peu lourd. Et après la fin de l'image ? »
- **I2** : « Des données sont **ajoutées à la suite** du JPEG. `strings`/`binwalk`. »
- **I3** : « `strings photo-poney.jpg | tail` → bloc `--- Licornia steg ---` avec une
  passphrase (`p0ney-cache`) et le flag. »

### #7 — `FLAG_FILES_RCE` · Crypto / Cracking · ★★
- **I1** : « Le partage public a un dossier `backup/`. Un export d'annuaire… avec des
  empreintes. »
- **I2** : « `hashes.txt` contient des **MD5**. Casse celui d'`a.pommier` au dictionnaire. »
- **I3** : « `john --format=Raw-MD5 --wordlist=rockyou.txt hashes.txt` → `applejack`.
  Ce compte ouvre le partage **`rh`** (`smbclient //…/rh -U a.pommier`) ou un SSH. »

### #8 — `FLAG_FILES_ROOT` · Privesc cron · ★★★
- **I1** : « Sur `files`, qu'est-ce qui tourne **en root** à intervalle régulier ?
  Regarde `/etc/cron.d`. »
- **I2** : « Le cron exécute `/opt/licornia/maintenance.sh`. Quels sont les **droits**
  de ce script ? »
- **I3** : « Il est `world-writable` (666). Ajoute une ligne (`cp /root/flag_root.txt
  /tmp/x; chmod 644 /tmp/x` ou un reverse shell), attends ~1 min (le tick cron). Pense
  à **looter `/root/id_admin`** : c'est la clé SSH de la directrice. »

### #9 — `FLAG_WS_ROOT` · Pwn (BOF ret2win) · ★★★
- **I1** : « Avec la clé `id_admin`, connecte-toi à `admin` en `c.vasseur`. Il y a un
  binaire **SUID** suspect : `vault`. »
- **I2** : « `vault` lit 256 octets dans un tampon de 64 → débordement. Pas de canari,
  pas de PIE (`checksec`). Une fonction `win()` fait le boulot ; il faut y **retourner**. »
- **I3** : « Offset = **72** (64 + 8 rbp). Adresse de `win` via `objdump -d vault`
  (≈ `0x401196`). Payload : `python3 -c 'import sys;sys.stdout.buffer.write(b"A"*72+
  (0x401196).to_bytes(8,"little"))'`, puis envoie tes commandes au shell root obtenu. »

### #10 — `FLAG_FINAL` · Reverse (XOR) · ★★★
- **I1** : « Toujours sur `admin`, un autre SUID : `licornia-check`. Il **vérifie** un
  mot de passe maître qui n'apparaît nulle part en clair. »
- **I2** : « Désassemble (`objdump`/Ghidra) ou `ltrace` : la saisie est **XORée** avec
  une clé constante avant comparaison à un tableau `enc[]`. »
- **I3** : « Clé = `0x5b`. Dé-XORe `enc[]` → `twilight-sparkle-42`. Donne-le à
  `licornia-check` → il lit le **trophée** (`/opt/licornia/trophy`) = prise du domaine. »

---

## 6. Durée & difficulté (repères pour un M1)

| Étape | Catégorie | Difficulté | Durée indicative |
|---|---|---|---|
| Recon initial (`nmap`, `whatweb`, `gobuster`) | Recon | ★ | 10–15 min |
| #1 Injection de commande | Web | ★ | 10 min |
| #2 OSINT EXIF *(bonus)* | OSINT | ★ | 5–10 min |
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

1. **Durcir la privesc `admin`** : remplacer le ret2win « pédagogique » par un
   ret2win avec une petite ROP (pop rdi) ou réactiver partiellement les protections,
   pour un public qui maîtrise déjà le BOF de base.
2. **Ajouter une brique réseau** : un service supplémentaire sur le LAN (ex. un
   petit serveur web interne d'annuaire) découvert au `nmap` post-pivot, pour muscler
   la phase de mouvement latéral — sans nouveau flag (recon pur) ou en recyclant un bonus.
3. **Varier la crypto** : proposer une 2ᵉ liste de hash (sel, ou `sha1`) pour
   travailler `hashcat` en plus de `john`, ou un mini-challenge de chiffrement César/
   Vigenère en amont du XOR pour graduer la difficulté du reverse.
4. **Forensique enrichie** : insérer dans la capture un second flux (HTTP basic auth,
   FTP) pour entraîner le *Follow Stream* et la lecture de protocoles variés.

> Garder la règle d'or : **noms de services et variables `.env` inchangés** (compat
> launcher/plugin), un seul service publié, entrypoints *restart-safe*. Toute
> nouvelle vuln se branche sur la spine ou en bonus sans toucher au plan de contrôle.
