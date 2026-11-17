import socket
import struct
import fcntl
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from routing.parser import load_routing_table, load_arp_table
from core.ip_decoder import decode_ip, encode_ip, decrease_ttl
from core.checksum import verify_checksum
from icmp.icmp_handler import ICMPHandler


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


def get_interface_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address", "r") as f:
        mac_str = f.read().strip()
    return mac_to_bytes(mac_str)


def get_interface_ip(iface: str) -> str | None:
    """Lấy địa chỉ IPv4 hiện tại của một card mạng trên Linux (SIOCGIFADDR)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", iface[:15].encode("utf-8"))
        )
        return socket.inet_ntoa(info[20:24])
    except OSError:
        return None
    finally:
        s.close()


def get_all_router_ips() -> set[str]:
    """Quét toàn bộ IPv4 đang gắn trên các card mạng của Router"""
    ips = set()
    for iface in os.listdir("/sys/class/net"):
        if iface == "lo":
            continue
        ip = get_interface_ip(iface)
        if ip:
            ips.add(ip)
    return ips


def send_ip_packet(sock: socket.socket, raw_ip: bytes, dest_ip: str, trie, arp_table: dict) -> bool:
    """Tra cứu tuyến đường, đóng gói Ethernet Frame và đẩy gói IP ra card mạng"""
    nhop, out_port = trie.lookup(dest_ip)
    if nhop is None:
        return False

    target_ip = dest_ip if nhop == "0.0.0.0" else nhop
    dest_mac_str = arp_table.get(target_ip)
    if not dest_mac_str:
        print(f"Drop: Khong tim thay MAC cho {target_ip} trong arp_table.txt")
        return False

    dest_mac = mac_to_bytes(dest_mac_str)
    src_mac = get_interface_mac(out_port)
    eth_header = struct.pack("!6s6sH", dest_mac, src_mac, 0x0800)

    sock.sendto(eth_header + raw_ip, (out_port, 0))
    return True


def is_icmp_error_packet(pkt) -> bool:
    """Kiểm tra xem gói tin có phải là ICMP báo lỗi không (tránh gửi lặp ICMP lỗi)"""
    if pkt.protocol == ICMPHandler.PROTOCOL_ICMP and len(pkt.payload) >= 1:
        icmp_type = pkt.payload[0]
        return icmp_type in (ICMPHandler.TYPE_DEST_UNREACHABLE, ICMPHandler.TYPE_TIME_EXCEEDED)
    return False


def main():
    print("Starting User-Space IPv4 Router...")

    route_file = "config/routes.txt"
    arp_file = "config/arp_table.txt"

    if not os.path.exists(route_file):
        print("Loi: Khong tim thay file routes.txt")
        return

    trie = load_routing_table(route_file)
    arp_table = load_arp_table(arp_file)
    router_ips = get_all_router_ips()

    print(f"Router IPs: {router_ips}")
    print("Load routing table & ARP table done!")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except Exception as e:
        print("Chay bang sudo di ban oi:", e)
        sys.exit(1)

    print("Dang nghe IPv4 tren cac interface...")
    print("-" * 45)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            in_iface = addr[0]

            # Bỏ qua gói tin do chính Router vừa phát ra
            if addr[2] == socket.PACKET_OUTGOING:
                continue

            ip_data = data[14:]

            # 1. Kiểm tra IP Checksum (TV1)
            if not verify_checksum(ip_data):
                continue

            try:
                pkt = decode_ip(ip_data)
            except ValueError:
                continue

            # 2. Nếu gói tin gửi tới chính IP của Router -> Xử lý Ping (TV3)
            if pkt.dest_ip in router_ips:
                if (
                    pkt.protocol == ICMPHandler.PROTOCOL_ICMP
                    and len(pkt.payload) >= 8
                    and pkt.payload[0] == ICMPHandler.TYPE_ECHO_REQUEST
                ):
                    reply_raw = ICMPHandler.build_icmp_response_packet(
                        router_ip=pkt.dest_ip,
                        original_packet=pkt,
                        original_raw_ip=ip_data,
                        icmp_type=ICMPHandler.TYPE_ECHO_REPLY
                    )
                    if send_ip_packet(sock, reply_raw, pkt.source_ip, trie, arp_table):
                        print(f"ICMP Echo Reply: {pkt.dest_ip} -> {pkt.source_ip}")
                continue

            # 3. Tra cứu định tuyến LPM (TV2)
            nhop, out_port = trie.lookup(pkt.dest_ip)
            if nhop is None:
                print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (ko co route)")
                if not is_icmp_error_packet(pkt):
                    router_src_ip = get_interface_ip(in_iface) or next(iter(router_ips), None)
                    if router_src_ip:
                        err_raw = ICMPHandler.build_icmp_response_packet(
                            router_ip=router_src_ip,
                            original_packet=pkt,
                            original_raw_ip=ip_data,
                            icmp_type=ICMPHandler.TYPE_DEST_UNREACHABLE,
                            icmp_code=ICMPHandler.CODE_NET_UNREACHABLE
                        )
                        send_ip_packet(sock, err_raw, pkt.source_ip, trie, arp_table)
                continue

            # 4. Giảm TTL & kiểm tra hết hạn (TV1 + TV3)
            new_pkt, drop_flag = decrease_ttl(pkt)
            if drop_flag:
                print(f"Drop: {pkt.source_ip} -> {pkt.dest_ip} (het TTL)")
                if not is_icmp_error_packet(pkt):
                    router_src_ip = get_interface_ip(in_iface) or next(iter(router_ips), None)
                    if router_src_ip:
                        err_raw = ICMPHandler.build_icmp_response_packet(
                            router_ip=router_src_ip,
                            original_packet=pkt,
                            original_raw_ip=ip_data,
                            icmp_type=ICMPHandler.TYPE_TIME_EXCEEDED,
                            icmp_code=ICMPHandler.CODE_TTL_EXCEEDED
                        )
                        send_ip_packet(sock, err_raw, pkt.source_ip, trie, arp_table)
                continue

            # 5. Đóng gói lại IP + Ethernet và chuyển tiếp gói tin (TV1 + TV2)
            final_ip_raw = encode_ip(new_pkt)
            if send_ip_packet(sock, final_ip_raw, pkt.dest_ip, trie, arp_table):
                print(f"FWD: {pkt.source_ip} -> {pkt.dest_ip} | Port: {out_port} | NextHop: {nhop}")

        except KeyboardInterrupt:
            print("\nTat router.")
            break
        except Exception as e:
            print("Loi roi:", e)


if __name__ == "__main__":
    main()
