
from scapy.all import sniff, sendp, srp1, Ether, IP, ARP, Raw, get_if_hwaddr

from core.ip_decoder import decode_ip, encode_ip, decrease_ttl
from core.checksum import verify_checksum
from routing.trie import RoutingTrie


INTERFACES = ["r1-eth0", "r1-eth1"]

routing = RoutingTrie()
routing.insert("10.0.1.0/24", "DIRECT", "r1-eth0")
routing.insert("10.0.2.0/24", "DIRECT", "r1-eth1")

arp_cache = {}
router_macs = {}


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

        next_hop, out_interface = routing.lookup(packet.dest_ip)

        if next_hop is None:
            print("Khong tim thay Route")
            return

        if out_interface not in INTERFACES:
            print("Interface khong hop le")
            return

        new_packet, expired = decrease_ttl(packet)

        if expired:
            print("TTL het han")
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

    print("Python Router dang hoat dong")
    print("Interfaces:", INTERFACES)

    sniff(
        iface=INTERFACES,
        prn=handle_packet,
        store=False,
        lfilter=lambda p: Ether in p and IP in p
    )
