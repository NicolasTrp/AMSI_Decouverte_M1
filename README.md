<div align="center">

# 🛒 Lab CTF Découverte M1 — « ShopXpress »

### Boot2root **3 machines** segmenté DMZ/LAN, conteneurisé — initiation pentest

*Tour des outils de base · une chaîne d'attaque réaliste · toutes les catégories CTF*

</div>

---

> # ⚠️ ENVIRONNEMENT VOLONTAIREMENT VULNÉRABLE
>
> Ce dépôt déploie une infra **intentionnellement vulnérable**, conçue **uniquement**
> pour un **CTF pédagogique** en sécurité offensive.
>
> - ❌ **Ne JAMAIS** déployer en production ni exposer sur Internet.
> - ✅ À utiliser en **environnement isolé** et **cadre autorisé** (salle de TP, lab).
> - 🔒 Les techniques apprises ne s'utilisent **que** sur ce lab ou des systèmes
>   pour lesquels on a une **autorisation explicite** — sinon c'est illégal.

---

## 🎯 Objectif pédagogique

Boutique de vente en ligne **« ShopXpress »** volontairement vulnérable (niveau Master 1).
L'étudiant part du **seul point d'entrée** fourni (IP + port du site web) et doit
**compromettre 3 machines** en chaîne, en faisant le **tour des outils de base** et en
touchant **toutes les catégories classiques de CTF** (Web : SQLi/LFI/upload — Encodage,
Crypto, Forensique, Stégano, Réseau/Pivot, Reverse, Pwn, Privesc).

```
   Kali étudiant ──(IP:port)──►  web01 (DMZ)  ──pivot──►  fileshare (LAN)  ──►  admin (LAN)
                                 point d'entrée            partage SMB           cible finale
```

## 🗺️ Topologie

| Machine (service) | Réseau | Rôle | Publié ? |
|---|---|---|---|
| `web01` (`web`)        | DMZ `…10.0/24` | Boutique ShopXpress — **point d'entrée** | ✅ `WEB_PUBLISH_IP:PORT` |
| `firewall`            | DMZ + LAN      | Routeur/pare-feu (segmentation + pivot)     | ❌ interne |
| `fileshare` (`files`) | LAN `…20.0/24` | Partage SMB (stock, sauvegardes)            | ❌ interne (via pivot) |
| `admin` (`workstation`)| LAN `…20.0/24`| Poste d'administration — **cible finale**   | ❌ interne (via pivot) |

Seul `web01` est joignable depuis la Kali de l'étudiant. Le LAN (`fileshare`, `admin`)
n'est accessible **qu'en pivotant** par `web01` une fois compromis.

## 🧰 Prérequis hôte

- Linux avec **Docker** + **docker compose**.
- `make`, `bash` ; `sudo` pour le pré-requis réseau (`bridge-nf`, posé par `make up`).

## 🚀 Lancement (mono-instance, séance encadrée)

```bash
cp .env.example .env        # (make up le fait sinon)
make up                     # build + démarre, applique le pré-requis hôte
make ps                     # état des conteneurs
make test                   # vérifie la segmentation réseau (seul web publié)
```

Le **point d'entrée** à donner aux étudiants s'affiche en fin de `make up`
(`http://<WEB_PUBLISH_IP>:<WEB_PUBLISH_PORT>`). Arrêt : `make down`.

> Pour une salle : mets `WEB_PUBLISH_IP=0.0.0.0` (joignable depuis les Kali) et
> filtre le port au pare-feu de l'hôte pour n'autoriser que le réseau de la salle.

## 🧩 Catégories couvertes (sans spoiler)

| Machine | Catégories travaillées |
|---|---|
| web01 | Recon/Énum · **Web** (SQLi · lecture de fichiers · upload RCE) · **Encodage** · **Privesc** |
| fileshare | **Réseau/Pivot** · **Forensique** · **Stégano** · **Crypto/Cracking** · **Privesc** |
| admin | **Pwn** (exploitation binaire) · **Reverse** · trophée final |

10 flags `AMSI{...}`. Spine obligatoire (linéaire) + flags bonus (lecture de fichiers,
forensique, stégano). Détail réservé encadrant : [`docs/walkthrough.md`](docs/walkthrough.md).

## 🚩 Flags & scoring

- Format `AMSI{...}`, **régénérés par équipe** (jamais hardcodés) — cf. `.env`.
- **Validation simple** : [`scripts/verify-chain.sh`](scripts/verify-chain.sh) rejoue
  toute la chaîne et vérifie chaque flag (lab jetable).
- **Scoring CTFd multi-équipes** : l'infra **colle au plugin/launcher existant** du lab
  de référence (mêmes noms de services + `.env` + `FLAG_*`). Voir
  [`scoring/README.md`](scoring/README.md).

## 📁 Structure

```
lab-ctf-decouverte-m1/
├── docker-compose.yml          # web + firewall + files + workstation, réseaux dmz/lan
├── .env.example                # variables (compat launcher) + flags découverte
├── Makefile                    # up / down / test / test-chain / …
├── services/
│   ├── web/                    # Apache/PHP : SQLi, path traversal, upload RCE, base64, sudo tar
│   ├── firewall/               # routeur iptables (segmentation + pivot)
│   ├── files/                  # Samba : pcap, stégano, backup MD5, cron writable
│   └── workstation/            # admin : binaires SUID (pwn ret2win + reverse), trophée
├── scripts/                    # host-net.sh, verify-firewall.sh, verify-chain.sh
├── docs/                       # enonce / walkthrough / topology / scenario
└── scoring/                    # steps.py + seed_challenges.py + overrides.yml + launcher
```

## 📚 Documentation

- [`docs/enonce.md`](docs/enonce.md) — énoncé joueur (public).
- [`docs/walkthrough.md`](docs/walkthrough.md) — corrigé pas à pas (**encadrant**).
- [`docs/topology.md`](docs/topology.md) — réseau, flux, pivot.
- [`docs/scenario-ctf.md`](docs/scenario-ctf.md) — lore + indices progressifs.
