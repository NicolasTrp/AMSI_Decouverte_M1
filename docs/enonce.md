# Énoncé — CTF découverte « ShopXpress » (M1 / AMSI)

> ⚠️ **Cadre pédagogique autorisé.** Cet environnement est un laboratoire **isolé**,
> **volontairement vulnérable**, créé pour l'apprentissage du test d'intrusion dans
> le cadre du Master 1 AMSI. Les techniques que vous y pratiquerez ne doivent **jamais**
> être employées hors de ce périmètre ni sur un système dont vous n'avez pas
> l'autorisation écrite. Toute utilisation en dehors de ce TP engage votre seule
> responsabilité. **Vous êtes ici dans un cadre légal de test mandaté.**

---

## 1. Mission

**ShopXpress** — une **boutique de vente en ligne** (high-tech & accessoires) — vous
**mandate pour un test d'intrusion** sur son infrastructure.

La boutique expose son **site marchand** sur sa **DMZ**. Derrière, un **réseau interne
(LAN)** héberge un **partage de fichiers** (stocks, sauvegardes) et le **poste
d'administration** du responsable e-commerce. Le réseau interne n'est **pas joignable
directement** : on n'y entre qu'**après** avoir compromis le site public, puis en
**pivotant** par lui.

**Votre objectif :** partir du seul site marchand et progresser, machine par machine,
jusqu'à la **prise complète du back-office ShopXpress**.

> *Une Kali et bonne chance.* Vous apportez **votre propre** machine d'attaque (Kali,
> Parrot, ou équivalent). On ne vous donne **qu'un point d'entrée** : à vous d'énumérer,
> de comprendre, et d'enchaîner.

---

## 2. Point d'entrée

On ne vous remet **rien d'autre** qu'une **adresse IP et un port** : ceux du site
marchand public (la seule chose exposée).

```
Point d'entrée :   http://<IP>:<PORT>
                   (en autonome : ${WEB_PUBLISH_IP}:${WEB_PUBLISH_PORT}, soit 8080 par défaut)
```

- En séance encadrée, l'IP et le port vous sont communiqués (ou affichés par la
  plateforme de scoring quand vous déployez votre instance).
- **Tout le reste est à découvrir.** Les autres machines (partage de fichiers, poste
  d'admin) n'ont **aucun port publié** : elles ne se gagnent que par compromission et
  **pivot** depuis le site marchand.

---

## 3. Règles du jeu

- **Format de flag :** `AMSI{...}`. Chaque flag récupéré atteste d'une étape franchie.
- **3 machines à compromettre en chaîne :** `web` → `files` → `admin`.
- **Pivot obligatoire :** le LAN ne s'atteint **que depuis une machine déjà compromise**.
  Le franchissement DMZ → LAN se fait avec des outils standards (tunnel, proxy, rebond SSH).
- **10 jalons (10 flags) :**
  - **Flags « spine » (colonne vertébrale)** : bloquants, ils se **débloquent les uns
    après les autres**. Sans eux, pas de progression : ils tracent le chemin principal.
  - **Flags « bonus »** : non bloquants. Ils récompensent l'exploration de catégories
    annexes (analyse de capture, image cachée…) sans verrouiller la suite.
- **Pas d'indice gratuit :** la plateforme n'affiche que **la catégorie**, **l'utilisateur
  cible** et la **machine** de chaque jalon. La technique, c'est vous qui la trouvez.

> 💡 On **ne vous donne aucune valeur de flag** ici : ce document est l'énoncé public.
> Le corrigé pas-à-pas existe (`walkthrough.md`) mais il est réservé à l'encadrement.

---

## 4. Catégories à explorer

Ce CTF est conçu pour vous faire **toucher toutes les grandes familles** d'un test
d'intrusion, chacune sous sa **forme débutant**. À vous d'identifier *où* et *comment*
chacune s'applique. Le **site marchand** concentre à lui seul **trois failles web**
classiques que tout pentester doit savoir reconnaître.

| Catégorie | Ce qu'on attend de vous (sans la solution) |
|---|---|
| **Recon / Énumération** | Cartographier les services exposés, deviner la techno, fouiller les chemins du site (pages, espace gérant, robots). |
| **Web — Injection SQL** | Repérer un formulaire d'authentification mal codé et **contourner la connexion** sans mot de passe valide. |
| **Web — Lecture de fichiers** | Détourner une fonctionnalité de téléchargement pour **lire des fichiers du serveur** auxquels vous ne devriez pas accéder. |
| **Web — Upload / RCE PHP** | Trouver un import de fichier non filtré et y déposer de quoi **exécuter vos commandes** sur le serveur. |
| **OSINT** | Faire parler les contenus publics : pages « à propos », fichiers téléchargeables, **métadonnées**. |
| **Encodage** | Reconnaître qu'une donnée « illisible » n'est qu'**encodée** (≠ chiffrée) et la rétablir. |
| **Crypto / Password-cracking** | Retrouver un mot de passe à partir de son empreinte avec un dictionnaire. |
| **Forensique réseau** | Analyser une capture de trafic et y retrouver une information sensible. |
| **Stéganographie** | Détecter qu'un fichier anodin **cache** autre chose et l'en extraire. |
| **Réseau / Pivot** | Rebondir depuis une machine compromise pour atteindre un réseau autrement injoignable. |
| **Reverse (binaire)** | Comprendre ce que fait un programme pour en déduire un secret qu'il ne livre pas en clair. |
| **Pwn (binaire)** | Exploiter un défaut mémoire d'un programme privilégié pour exécuter votre code. |
| **Privesc / Système** | Repérer une mauvaise configuration locale et passer simple utilisateur → `root`. |

---

## 5. Boîte à outils — « le tour des outils de base »

L'esprit du TP : faire **un tour des outils classiques** du pentest. Voici la trousse
suggérée (non exhaustive — la bonne pratique reste de comprendre *pourquoi* on lance
un outil, pas seulement *comment*).

| Étape | Outils usuels |
|---|---|
| Découverte réseau & services | `nmap -sV`, `nmap -sC` |
| Énumération web | `whatweb`, `nikto`, `gobuster` / `ffuf`, `curl`, **Burp Suite** |
| Injection SQL | charges manuelles (`' OR '1'='1' -- `), `sqlmap` |
| Lecture de fichiers / RCE web | `curl`, navigateur, webshell PHP (`<?php system($_GET['c']); ?>`) |
| Interaction / shells | `curl`, `nc` (netcat), shells PHP/bash |
| Métadonnées & encodage | `exiftool`, `strings`, `base64` |
| Élévation de privilèges | `sudo -l`, ressources **GTFOBins** |
| Pivot & tunneling | `ssh -J` / `ssh -D`, `proxychains`, `chisel` |
| Partages de fichiers | `smbclient`, `smbmap` |
| Forensique réseau | `wireshark`, `tshark`, `strings` |
| Stéganographie | `steghide`, `binwalk`, `strings`, `exiftool` |
| Cassage de mots de passe | `john`, `hashcat`, dictionnaire **rockyou** |
| Reverse / Pwn | `objdump`, `ltrace`, `gdb` (+`pwndbg`/`gef`), **Ghidra**, `python3` (`pwntools`) |
| Recherche d'exploits | `searchsploit` |

---

## 6. Méthode conseillée (pour bien démarrer)

1. **Énumérez avant d'exploiter.** Un `nmap -sV` sur le point d'entrée, puis une
   énumération web méthodique, vous donneront le fil à tirer.
2. **Lisez tout ce qui est public.** Une page « à propos », un fichier téléchargeable,
   un commentaire de configuration : l'information traîne souvent à la vue de tous.
3. **Notez tout** (identifiants, chemins, versions, hashes). Une info inutile à
   l'instant T débloque souvent une étape plus loin.
4. **Le pivot part de la machine compromise.** Une fois `web` à vous, c'est **depuis
   `web`** (qui voit le LAN) que vous atteindrez `files`, puis `admin`.
5. **Réutilisation = règle d'or.** Un identifiant trouvé quelque part vaut la peine
   d'être essayé ailleurs (autre service, autre machine).
6. **Un binaire qui refuse n'est pas une impasse.** S'il garde un secret, il est
   souvent possible de le **lire** (reverse) ou de le **forcer** (pwn).

---

## 7. Progression & barème

Le parcours compte **10 jalons** matérialisés par **10 flags**, regroupés sur les
trois machines :

| Machine | Jalons (utilisateur cible) | Familles dominantes |
|---|---|---|
| **web** (DMZ, point d'entrée) | *(lecture serveur)* → `www-data` → `root` | Injection SQL · Lecture de fichiers · Upload/RCE · Encodage · Privesc |
| **files** (LAN, via pivot) | invité → *(compte employé)* → `root` | Recon · Forensique · Stégano · Crypto · Privesc |
| **admin** (LAN, via clé SSH) | `root` → **prise du back-office** | Pivot · Pwn · Reverse |

- Chaque **flag spine valide débloque le jalon suivant** : la plateforme ouvre les
  défis au fur et à mesure de votre avancée.
- Les **flags bonus** rapportent des points sans être sur le chemin critique : pensez
  à explorer les pistes annexes (capture réseau, image cachée) une fois le pied posé
  sur une machine.
- L'objectif final : décrocher le flag de **prise du back-office ShopXpress** sur `admin`.

Bonne chance — et bon pentest. 🛒
