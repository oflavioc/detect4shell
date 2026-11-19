#!/usr/bin/env python3
"""
Detect4Shell — gerador de PCAP SEM dependencias (so stdlib) para o tier on-the-wire.

Por que nao scapy: scapy exige `pip install` (rede) e e lento. Aqui montamos o quadro
Ethernet/IP/TCP na mao, com handshake TCP de 3 vias E checksums IP+TCP corretos, para
o Suricata reassemblar o fluxo e rodar o parser HTTP de verdade (http.header / http.uri).
Sem handshake, o Suricata trata o fluxo como mid-stream e `flow:established` nao casa.

Escreve, no diretorio passado em argv[1]:
  trigger.pcap      POST /login com Authorization: Basic <GATILHO>   -> deve disparar sid 2026114950 (http.header)
  trigger_uri.pcap  GET /r?token=<GATILHO>=&n=1                      -> deve disparar sid 2026114951 (http.uri)
  benign.pcap       GET /app com Authorization: Basic <BASE64 VALIDO> -> NAO deve disparar nada

GATILHO = corpo quad-alinhado de 64 chars de UM alfabeto base64 + '=' numa fronteira nao-base64
          (a FORMA do Base64 malformado do Java4Shell; ver regras/README.md).
BASE64 VALIDO = base64.b64encode de bytes aleatorios: termina em '==' mas o trecho antes do '='
          NAO e quad-alinhado, entao a regra (que exige quad + '=') nao casa. E a prova, no fio,
          de que a exclusao de falso-positivo funciona — nao so que strings curtas passam.

Isto prova que a regra DISPARA em trafego reassemblado; NAO prova explorabilidade do CVE.
"""
import base64
import os
import struct
import sys

CLIENT_IP = "203.0.113.10"   # TEST-NET-3 (RFC 5737) -> cai em EXTERNAL_NET
SERVER_IP = "10.0.0.5"       # 10.0.0.0/8 -> HOME_NET padrao do Suricata
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CPORT = 44444
SPORT = 80

FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


def ip2b(s):
    return bytes(int(x) for x in s.split("."))


def cksum(data):
    """Checksum de internet (ones-complement 16-bit) para IP e TCP."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src, dst, payload, ident):
    ver_ihl, tos, total, flags_frag, ttl, proto = 0x45, 0, 20 + len(payload), 0x4000, 64, 6
    base = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident, flags_frag, ttl, proto, 0, ip2b(src), ip2b(dst))
    chk = cksum(base)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ident, flags_frag, ttl, proto, chk, ip2b(src), ip2b(dst)) + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    off, win = (5 << 4), 64240
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 6, 20 + len(payload))
    base = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, 0, 0)
    chk = cksum(pseudo + base + payload)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, chk, 0) + payload


def eth(src_mac, dst_mac, payload):
    return dst_mac + src_mac + b"\x08\x00" + payload


def frame(c2s, l4, ident):
    if c2s:
        pkt = eth(CLIENT_MAC, SERVER_MAC, ipv4(CLIENT_IP, SERVER_IP, l4, ident))
    else:
        pkt = eth(SERVER_MAC, CLIENT_MAC, ipv4(SERVER_IP, CLIENT_IP, l4, ident))
    return struct.pack("!IIII", 1, 0, len(pkt), len(pkt)) + pkt


def write_pcap(path, http_request):
    req = http_request.encode()
    cseq, sseq = 1000, 5000
    pkts = [
        frame(True,  tcp(CLIENT_IP, SERVER_IP, CPORT, SPORT, cseq, 0, SYN), 10),
        frame(False, tcp(SERVER_IP, CLIENT_IP, SPORT, CPORT, sseq, cseq + 1, SYN | ACK), 11),
        frame(True,  tcp(CLIENT_IP, SERVER_IP, CPORT, SPORT, cseq + 1, sseq + 1, ACK), 12),
        frame(True,  tcp(CLIENT_IP, SERVER_IP, CPORT, SPORT, cseq + 1, sseq + 1, PSH | ACK, req), 13),
        frame(False, tcp(SERVER_IP, CLIENT_IP, SPORT, CPORT, sseq + 1, cseq + 1 + len(req), ACK), 14),
    ]
    with open(path, "wb") as f:
        # cabecalho global libpcap: magic, v2.4, thiszone, sigfigs, snaplen, linktype=1 (Ethernet)
        f.write(struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for p in pkts:
            f.write(p)


# GATILHO: 64 chars do alfabeto base64 padrao (nao-'A', para provar que nao depende de 'A') + '='
TRIG = ("Zm9vYmFy" * 8)[:64] + "="
# BASE64 VALIDO (benigno): termina em '==' mas NAO quad-alinhado antes do pad -> regra nao casa
VALID = base64.b64encode(os.urandom(49)).decode()
assert len(TRIG) == 65 and TRIG.endswith("=")
assert len(VALID) == 68 and VALID.endswith("==")

REQS = {
    "trigger.pcap": (
        "POST /login HTTP/1.1\r\n"
        "Host: idp.internal\r\n"
        f"Authorization: Basic {TRIG}\r\n"
        "Content-Length: 0\r\n\r\n"
    ),
    "trigger_uri.pcap": (
        f"GET /r?token={TRIG}&n=1 HTTP/1.1\r\n"
        "Host: idp.internal\r\n\r\n"
    ),
    "benign.pcap": (
        "GET /app HTTP/1.1\r\n"
        "Host: idp.internal\r\n"
        f"Authorization: Basic {VALID}\r\n\r\n"
    ),
}


def main():
    if len(sys.argv) < 2:
        print("uso: gen_pcaps.py <dir_saida>", file=sys.stderr)
        return 2
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, req in REQS.items():
        write_pcap(os.path.join(out, name), req)
    print(f"GATILHO (header/uri): {TRIG}")
    print(f"BASE64 VALIDO (benigno): {VALID}")
    print(f"pcaps escritos em {out}: {', '.join(REQS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
