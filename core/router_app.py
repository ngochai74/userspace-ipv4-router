
from scapy.all import (
    sniff, sendp, srp1, Ether, IP, ARP, Raw,
    get_if_hwaddr, get_if_addr
)

from core.ip_decoder import decode_ip, encode_ip, decrease_ttl
from core.checksum import verify_checksum
from routing.trie import RoutingTrie
from icmp.icmp_handler import ICMPHandler


INTERFACES = ["r1-eth0", "r1-eth1"]

routing = RoutingTrie()
routing.insert("10.0.1.0/24", "DIRECT", "r1-eth0")
routing.insert("10.0.2.0/24", "DIRECT", "r1-eth1")

arp_cache = {}
router_macs = {}
router_ips = {}


def resolve_mac(ip, interface):
    key = (ip, interface)

    if key not in arp_cache:
        response = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=interface,
            timeout=2,
            verbose=False
        )

        if response is None or ARP not in response:
            raise RuntimeError(f"Khong tim thay MAC: {ip}")

        arp_cache[key] = response[ARP].hwsrc

    return arp_cache[key]


def send_icmp_error(frame, packet, raw_ip, icmp_type, icmp_code):
    interface = getattr(frame, "sniffed_on", None)

    if interface not in INTERFACES:
        return

    if packet.fragment_offset != 0:
        return

    if (
        packet.protocol == 1
        and packet.payload
        and packet.payload[0] in (3, 4, 5, 11, 12)
    ):
        return

    response = ICMPHandler.build_icmp_response_packet(
        router_ips[interface],
        packet,
        raw_ip,
        icmp_type,
        icmp_code
    )

    outgoing = (
        Ether(
            src=router_macs[interface],
            dst=frame[Ether].src,
            type=0x0800
        ) / Raw(load=response)
    )

    sendp(outgoing, iface=interface, verbose=False)

    print("Da gui ICMP")
    print("Type:", icmp_type)
    print("Code:", icmp_code)


def handle_packet(frame):
    if Ether not in frame or IP not in frame:
        return

    if frame[Ether].src.lower() in router_macs.values():
        return

    try:
        raw_ip = bytes(frame[IP])

        if not verify_checksum(raw_ip):
            print("Checksum khong hop le")
            return

        packet = decode_ip(raw_ip)

        print(f"\nNhan: {packet.source_ip} -> {packet.dest_ip}")

        new_packet, expired = decrease_ttl(packet)

        if expired:
            send_icmp_error(
                frame, packet, raw_ip,
                ICMPHandler.TYPE_TIME_EXCEEDED,
                ICMPHandler.CODE_TTL_EXCEEDED
            )
            return

        next_hop, out_interface = routing.lookup(packet.dest_ip)

        if next_hop is None or out_interface is None:
            send_icmp_error(
                frame, packet, raw_ip,
                ICMPHandler.TYPE_DEST_UNREACHABLE,
                ICMPHandler.CODE_NET_UNREACHABLE
            )
            return

        if out_interface not in INTERFACES:
            print("Interface khong hop le")
            return

        new_raw = encode_ip(new_packet)

        arp_ip = packet.dest_ip if next_hop == "DIRECT" else next_hop

        dest_mac = resolve_mac(arp_ip, out_interface)

        outgoing = (
            Ether(
                src=router_macs[out_interface],
                dst=dest_mac,
                type=0x0800
            ) / Raw(load=new_raw)
        )

        sendp(outgoing, iface=out_interface, verbose=False)

        print("Chuyen tiep thanh cong")
        print("Next Hop:", arp_ip)
        print("Interface:", out_interface)
        print("TTL moi:", new_packet.ttl)

    except Exception as error:
        print("Loi:", error)


if __name__ == "__main__":
    router_macs = {
        iface: get_if_hwaddr(iface).lower()
        for iface in INTERFACES
    }

    router_ips = {
        iface: get_if_addr(iface)
        for iface in INTERFACES
    }

    print("Python Router dang hoat dong")
    print("Interfaces:", INTERFACES)

    sniff(
        iface=INTERFACES,
        prn=handle_packet,
        store=False,
        lfilter=lambda p: Ether in p and IP in p
    )
