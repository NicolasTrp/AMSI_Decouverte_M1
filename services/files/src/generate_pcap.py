#!/usr/bin/env python3
# Génère une petite capture .pcap (Forensique réseau) : un échange HTTP EN CLAIR
# entre un poste et le service de sauvegarde, avec identifiants en clair + un flag
# dans la réponse serveur. Lisible via Wireshark (Suivre > Flux TCP) ou `strings`.
#
# Usage : generate_pcap.py <flag> <sortie.pcap>
import os, struct, sys, time

FLAG = sys.argv[1] if len(sys.argv) > 1 else "AMSI{pcap_clear_login_dev}"
OUT = sys.argv[2] if len(sys.argv) > 2 else "capture.pcap"

CLIENT_IP, SERVER_IP = "172.31.20.50", "172.31.20.11"
CLIENT_MAC = bytes.fromhex("02420ac01432")
SERVER_MAC = bytes.fromhex("02420ac0140b")
CLIENT_PORT, SERVER_PORT = 44017, 80

req = (
    "POST /backup/login HTTP/1.1\r\n"
    "Host: files.licornia.lan\r\n"
    "User-Agent: licornia-backup-agent/1.0\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 41\r\n\r\n"
    "user=svc-backup&password=B@ckup-Licornia-2026"
).encode()

resp = (
    "HTTP/1.1 200 OK\r\n"
    "Server: licornia-backup/1.0\r\n"
    "Content-Type: text/plain\r\n\r\n"
    "Sauvegarde OK. Note interne (NE PAS diffuser): " + FLAG + "\r\n"
).encode()


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src, dst, payload, ident):
    ver_ihl = 0x45
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident, 0x4000,
                      64, 6, 0,
                      bytes(map(int, src.split("."))),
                      bytes(map(int, dst.split("."))))
    chk = csum(hdr)
    hdr = hdr[:10] + struct.pack("!H", chk) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags, src_ip, dst_ip, payload):
    off = (5 << 4)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags,
                      64240, 0, 0)
    pseudo = (bytes(map(int, src_ip.split("."))) +
              bytes(map(int, dst_ip.split("."))) +
              struct.pack("!BBH", 0, 6, len(hdr) + len(payload)))
    chk = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", chk) + hdr[18:]
    return hdr + payload


def eth(dst_mac, src_mac, payload):
    return dst_mac + src_mac + b"\x08\x00" + payload


def frame(client_to_server, seq, ack, flags, body, ident):
    if client_to_server:
        ip = ipv4(CLIENT_IP, SERVER_IP,
                  tcp(CLIENT_PORT, SERVER_PORT, seq, ack, flags,
                      CLIENT_IP, SERVER_IP, body), ident)
        return eth(SERVER_MAC, CLIENT_MAC, ip)
    ip = ipv4(SERVER_IP, CLIENT_IP,
              tcp(SERVER_PORT, CLIENT_PORT, seq, ack, flags,
                  SERVER_IP, CLIENT_IP, body), ident)
    return eth(CLIENT_MAC, SERVER_MAC, ip)


# PSH+ACK = 0x18, ACK = 0x10
pkts = [
    frame(True, 1, 1, 0x18, req, 0x1000),
    frame(False, 1, 1 + len(req), 0x18, resp, 0x2000),
]

with open(OUT, "wb") as f:
    # Global header pcap : magic, v2.4, thiszone, sigfigs, snaplen, linktype=1
    f.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    t0 = 1718900000
    for i, p in enumerate(pkts):
        f.write(struct.pack("!IIII", t0 + i, i * 1000, len(p), len(p)))
        f.write(p)
print("[pcap] %s écrit (%d paquets)." % (OUT, len(pkts)))
