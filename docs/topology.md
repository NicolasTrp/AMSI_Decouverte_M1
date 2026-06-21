# Topologie — lab découverte « ShopXpress » (M1)

3 machines en chaîne + 1 routeur. **Seul `web` est publié** : c'est le **point
d'entrée** unique donné aux étudiants (une IP, un port). Tout le reste se gagne
par **compromission puis pivot**.

## Schéma

```
                       publie ${WEB_PUBLISH_IP}:${WEB_PUBLISH_PORT}  (point d'entrée)
                                     │
        Internet  ◄───egress───┐     ▼
            ▲                  │  ┌──────────┐
            │ relais proxy     └──┤   web    │  point d'entrée CTF (DMZ)
            │ (egress LAN)        │ .10      │  boutique ShopXpress (Apache/PHP)
            │                     │          │  SQLi · traversal · upload RCE → www-data
            │                     │          │  sudo tar (GTFOBins) → root
   ┌────────┼─────────────────────└────┬─────┘  route pivot vers le LAN (NET_ADMIN)
   │   dmz : 172.31.10.0/24             │
   │   (bridge, egress autorisé)   ┌────┴──────┐
   │   .2 (dmz) ───────────────────┤ firewall  │  NET_ADMIN, ip_forward=1
   └───────────────────────────────┤  .2(lan)  │  SEUL routeur dmz↔lan
   ┌────────────────────────────────┤ tinyproxy │  iptables conntrack :
   │   lan : 172.31.20.0/24         │  :8888    │    FORWARD policy DROP
   │   (bridge, internal:true,      └────┬──────┘    ESTABLISHED,RELATED (2 sens)
   │    PAS d'egress direct)             │           NEW autorisé DMZ→LAN **et** LAN→DMZ
   │                                     │           MASQUERADE bidirectionnel
   │              ┌──────────┐     ┌─────┴──────┐
   │              │  files   │     │   admin    │
   │              │ .11      │     │ .12        │
   │              │ smbd     │     │ (workstation)
   │              │ +cron    │     │ sshd       │
   │              │ +sshd    │     │ vault (pwn)│
   │              └──────────┘     │ backoffice-│
   │                   │           │ check (rev)│
   │                   └───clé SSH─┴────────────┘
   │        http_proxy → firewall:8888 (SEULE sortie internet du LAN)
   └──────────────────────────────────────────────────────────────────
```

## Subnets et adresses (valeurs autonomes ; réécrites par le launcher)

| Réseau | Subnet           | Egress internet                       | Hôtes                                              |
|--------|------------------|---------------------------------------|----------------------------------------------------|
| `dmz`  | 172.31.10.0/24   | OUI (direct)                          | web (.10), firewall (.2), gw (.1)                  |
| `lan`  | 172.31.20.0/24   | OUI **uniquement via proxy firewall** | files (.11), admin/workstation (.12), firewall (.2), gw (.1) |

> En autonome (`make up`) on utilise `172.31.x` pour ne pas entrer en collision
> avec le lab avancé (`172.30.x`). Sous le launcher CTFd, les subnets/port sont
> **réécrits par équipe** (`172.30.<octet>.x`, port hôte unique) — c'est pour cela
> que **tous les noms de variables sont identiques** au lab de référence : le lab
> est entièrement paramétré par l'env, rien n'est en dur. (cf. `scoring/README.md`.)

Le firewall est **multi-homed** : `.2` sur la DMZ et `.2` sur le LAN. C'est le seul
élément possédant une patte sur les deux réseaux — donc le seul chemin L3 entre eux,
**et** le seul relais d'egress internet pour le LAN.

## Différence clé avec le lab avancé : le pivot est OUVERT

| | Lab avancé | **Lab découverte (ce lab)** |
|---|---|---|
| DMZ → LAN | ❌ DROP (callback HMAC inversé, niveau expert) | ✅ **NEW autorisé** (pivot débutant) |
| LAN → DMZ | ✅ NEW autorisé | ✅ NEW autorisé |
| Leçon de segmentation | « le LAN ne joint pas le LAN sans rebond » | « **seul `web` est publié** : on n'entre dans le LAN qu'**après** avoir compromis `web`, en pivotant par lui » |

La segmentation reste donc bien réelle (un seul service exposé), mais le franchissement
DMZ→LAN se fait avec des **outils standards** depuis le shell www-data obtenu sur
`web` (tunnel `chisel`/SOCKS + `proxychains`), à la portée d'un M1. `web` n'expose
aucun compte SSH : on pivote par le **shell déjà obtenu**, pas par un `ssh -J ...@web`.

## Matrice de flux

| Source ↓ \ Dest → | web (DMZ)        | files/admin (LAN)        | Internet (direct) | Internet (via proxy) |
|-------------------|------------------|--------------------------|-------------------|----------------------|
| **web (DMZ)**     | —                | ✅ NEW autorisé (PIVOT)  | ✅ (egress DMZ)   | n/a                  |
| **files/admin**   | ✅ NEW autorisé  | ✅ (même bridge)         | ❌ pas de route   | ✅ firewall:8888     |
| **Internet**      | ✅ via port pub. | ❌                       | —                 | —                    |

- **DMZ→LAN** : `NEW` accepté par le firewall (règle `(c)`), retour via conntrack +
  MASQUERADE. C'est le **pivot**. `web` pose une route statique `172.31.20.0/24 via
  firewall(.2 dmz)` (capability `NET_ADMIN`) pour l'emprunter.
- **LAN→DMZ** : `NEW` accepté (règle `(b)`), retour via conntrack.
- **LAN→Internet** : pas de default route + bridge `internal` → **aucun egress direct**.
  Seule sortie = proxy **tinyproxy** sur la patte LAN du firewall (`172.31.20.2:8888`),
  qui filtre (Allow = subnet LAN) et journalise.

## Le pivot, pas à pas (intention pédagogique)

1. L'étudiant ne voit QUE `web` (point d'entrée publié).
2. Il compromet `web` (SQLi → upload PHP → www-data → `sudo tar` → root).
3. Depuis `web` (qui a la route LAN), il **pivote** par son shell : chisel/SOCKS + proxychains.
4. Il atteint `files` (SMB/SSH) puis, avec la **clé SSH lootée**, `admin`.

## Pourquoi un conteneur firewall (et pas l'isolation Docker) ?

- L'isolation inter-réseaux native de Docker est **symétrique** et n'a pas d'état :
  on ne peut ni router proprement DMZ↔LAN, ni centraliser/journaliser l'egress.
- Un routeur L3 avec conntrack (`firewall`) donne un NAT bidirectionnel **stateful**
  et le point idéal pour contrôler la sortie internet du LAN.

## Pré-requis hôte : `bridge-nf-call-iptables=0` (important)

Sur ce Docker, `internal: true` est matérialisé par une règle hôte
`DOCKER-ISOLATION-STAGE-1` qui, tant que `net.bridge.bridge-nf-call-iptables=1`,
s'applique **aussi aux trames bridgées** vers le firewall et **casse** le routage
LAN↔DMZ (donc le pivot). On pose `net.bridge.bridge-nf-call-iptables=0`
(`make host-setup` / `scripts/host-net.sh`). Ce réglage ne diminue pas la posture
anti-escape : le trafic réellement **routé** entre ponts reste filtré normalement.

## Détection des interfaces

`firewall.sh` ne se fie pas aux noms `eth0/eth1` (non garantis) : il identifie les
interfaces **par subnet** (`ip -o -4 addr`, match du préfixe `172.31.10.` vs `172.31.20.`).

## Posture de sécurité (hôte)

`privileged: false`, pas de `docker.sock` monté, `cap_drop: [ALL]` + ajouts minimaux
par service (`NET_ADMIN` sur web/firewall pour les routes ; `CHOWN/SETUID/SETGID/
DAC_OVERRIDE/SYS_CHROOT` ailleurs). Un seul port publié (`web`). Les invariants sont
vérifiés par `scripts/verify-firewall.sh`.
