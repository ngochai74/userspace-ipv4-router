import socket
import struct
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from routing.parser import load_routing_table, load_arp_table
from core.ip_decoder import decode_ip, encode_ip, decrease_ttl


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


def get_interface_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address", "r") as f:
        mac_str = f.read().strip()
    return mac_to_bytes(mac_str)


def main():
    print("Starting Router...")

    route_file = "config/routes.txt"
    arp_file = "config/arp_table.txt"

    if not os.path.exists(route_file):
        print("Loi: Khong tim thay file routes.txt")
        return

    trie = load_routing_table(route_file)
    arp_table = load_arp_table(arp_file)
    print("Load routing table & ARP table done!")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except Exception as e:
        print("Chay bang sudo di ban oi:", e)
        sys.exit(1)

    print("Dang nghe IPv4 tren cac interface...")
    print("-" * 40)

    while True:
        try:
            data, addr = sock.recvfrom(65535)

            # Bỏ qua gói tin do chính Router vừa gửi ra để tránh lặp vô hạn
            if addr[2] == socket.PACKET_OUTGOING:
                continue

            ip_data = data[14:]
            try:
                pkt = decode_ip(ip_data)
            except ValueError:
                continue

            # 1. Tra cứu Longest Prefix Match (TV2)
            nhop, out_port = trie.lookup(pkt.dest_ip)
            if nhop is None:
                print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (ko co route)")
                # TODO (TV3): Gửi ICMP Destination Unreachable
                continue

            # 2. Giảm TTL & kiểm tra hết hạn (TV1)
            new_pkt, drop_flag = decrease_ttl(pkt)
            if drop_flag:
                print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (het TTL)")
                # TODO (TV3): Gửi ICMP Time Exceeded
                continue

            # 3. Phân giải MAC đích từ bảng ARP (TV2)
            target_ip = pkt.dest_ip if nhop == "0.0.0.0" else nhop
            dest_mac_str = arp_table.get(target_ip)
            if not dest_mac_str:
                print(f"Drop: Khong tim thay MAC cho {target_ip} trong arp_table.txt")
                continue

            # 4. Đóng gói Layer 2 (Ethernet Header) và chuyển tiếp gói tin
            dest_mac = mac_to_bytes(dest_mac_str)
            src_mac = get_interface_mac(out_port)
            eth_header = struct.pack("!6s6sH", dest_mac, src_mac, 0x0800)

            final_frame = eth_header + encode_ip(new_pkt)
            sock.sendto(final_frame, (out_port, 0))

            print(f"FWD: {pkt.source_ip} -> {pkt.dest_ip} | Port: {out_port} | NextMAC: {dest_mac_str}")

        except KeyboardInterrupt:
            print("\nTat router.")
            break
        except Exception as e:
            print("Loi roi:", e)


if __name__ == "__main__":
    main()
