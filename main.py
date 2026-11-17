import socket
import struct
import fcntl
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from routing.parser import load_routing_table, load_arp_table
from routing.arp_manager import ARPManager
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", iface[:15].encode("utf-8")))
        return socket.inet_ntoa(info[20:24])
    except OSError:
        return None
    finally:
        s.close()

def get_all_router_ips() -> set[str]:
    ips = set()
    for iface in os.listdir("/sys/class/net"):
        if iface == "lo": continue
        ip = get_interface_ip(iface)
        if ip: ips.add(ip)
    return ips

def is_icmp_error_packet(pkt) -> bool:
    if pkt.protocol == ICMPHandler.PROTOCOL_ICMP and len(pkt.payload) >= 1:
        return pkt.payload[0] in (ICMPHandler.TYPE_DEST_UNREACHABLE, ICMPHandler.TYPE_TIME_EXCEEDED)
    return False

def main():
    print("🚀 Bắt đầu khởi động User-Space IPv4 Router (Tuần 3 - Dynamic ARP & Traceroute)...")

    route_file = "config/routes.txt"
    arp_file = "config/arp_table.txt"

    trie = load_routing_table(route_file)
    static_arp = load_arp_table(arp_file)
    arp_manager = ARPManager(static_arp)
    router_ips = get_all_router_ips()

    # Thống kê
    stats = {"rx": 0, "fwd": 0, "drop": 0, "arp_req": 0, "arp_rep": 0}

    try:
        # ETH_P_ALL = 0x0003: Bắt cả ARP và IPv4
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except Exception as e:
        print("Lỗi: Cần quyền root (sudo)!", e)
        sys.exit(1)

    print("-" * 50)
    print(f"Router IPs: {router_ips}")
    print("Đang lắng nghe IPv4 và ARP...")
    print("-" * 50)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            if addr[2] == socket.PACKET_OUTGOING:
                continue

            in_iface = addr[0]
            eth_header = data[:14]
            dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', eth_header)

            # ==========================================
            # LUỒNG 1: XỬ LÝ ARP (0x0806)
            # ==========================================
            if eth_proto == 0x0806:
                arp_data = arp_manager.parse_arp_packet(data[14:])
                if not arp_data:
                    continue
                
                # Trả lời ARP Request nếu hỏi IP của Router
                if arp_data["opcode"] == ARPManager.ARP_OP_REQUEST and arp_data["target_ip"] in router_ips:
                    router_mac = get_interface_mac(in_iface)
                    reply_frame = ARPManager.build_arp_reply(
                        router_mac, arp_data["target_ip"], 
                        mac_to_bytes(arp_data["sender_mac"]), arp_data["sender_ip"]
                    )
                    sock.sendto(reply_frame, (in_iface, 0))
                    stats["arp_rep"] += 1
                    print(f"[*] ARP: Đã trả lời MAC của {arp_data['target_ip']} cho {arp_data['sender_ip']}")

                # Cập nhật cache nếu nhận được ARP Reply
                elif arp_data["opcode"] == ARPManager.ARP_OP_REPLY and arp_data["target_ip"] in router_ips:
                    arp_manager.update(arp_data["sender_ip"], arp_data["sender_mac"])
                    print(f"[*] ARP: Đã học được MAC của {arp_data['sender_ip']} -> {arp_data['sender_mac']}")
                    
                    # Giải phóng hàng đợi: Gửi các gói IP đang chờ MAC này
                    pending = arp_manager.pop_pending_packets(arp_data["sender_ip"])
                    for raw_ip, out_port in pending:
                        eth_hdr = struct.pack("!6s6sH", mac_to_bytes(arp_data["sender_mac"]), get_interface_mac(out_port), 0x0800)
                        sock.sendto(eth_hdr + raw_ip, (out_port, 0))
                        stats["fwd"] += 1
                        print(f"✅ Đã xả hàng đợi: FWD gói tin tới {arp_data['sender_ip']}")
                continue

            # ==========================================
            # LUỒNG 2: XỬ LÝ IPv4 (0x0800)
            # ==========================================
            if eth_proto != 0x0800:
                continue

            ip_data = data[14:]
            if not verify_checksum(ip_data):
                continue

            try:
                pkt = decode_ip(ip_data)
            except ValueError:
                continue

            stats["rx"] += 1

            # A. Gói tin gửi thẳng tới IP của Router
            if pkt.dest_ip in router_ips:
                # Trả lời ICMP Echo Request (Ping)
                if pkt.protocol == ICMPHandler.PROTOCOL_ICMP and len(pkt.payload) >= 8 and pkt.payload[0] == ICMPHandler.TYPE_ECHO_REQUEST:
                    reply_ip_raw = ICMPHandler.build_icmp_response_packet(
                        pkt.dest_ip, pkt, ip_data, ICMPHandler.TYPE_ECHO_REPLY
                    )
                    nhop, out_port = trie.lookup(pkt.source_ip)
                    if nhop and arp_manager.lookup(pkt.source_ip):
                        eth_hdr = struct.pack("!6s6sH", mac_to_bytes(arp_manager.lookup(pkt.source_ip)), get_interface_mac(out_port), 0x0800)
                        sock.sendto(eth_hdr + reply_ip_raw, (out_port, 0))
                        print(f"[*] Ping: Đã trả lời Echo Reply cho {pkt.source_ip}")
                
                # Trả lời ICMP Port Unreachable nếu là gói UDP (Traceroute support - Việc của TV3)
                elif pkt.protocol == ICMPHandler.PROTOCOL_UDP:
                    err_raw = ICMPHandler.build_icmp_response_packet(
                        pkt.dest_ip, pkt, ip_data, 
                        ICMPHandler.TYPE_DEST_UNREACHABLE, ICMPHandler.CODE_PORT_UNREACHABLE
                    )
                    nhop, out_port = trie.lookup(pkt.source_ip)
                    if nhop and arp_manager.lookup(pkt.source_ip):
                        eth_hdr = struct.pack("!6s6sH", mac_to_bytes(arp_manager.lookup(pkt.source_ip)), get_interface_mac(out_port), 0x0800)
                        sock.sendto(eth_hdr + err_raw, (out_port, 0))
                        print(f"[*] Traceroute: Đã gửi Port Unreachable về {pkt.source_ip}")
                continue

            # B. Định tuyến và chuyển tiếp (Gửi đi chỗ khác)
            nhop, out_port = trie.lookup(pkt.dest_ip)
            if nhop is None:
                stats["drop"] += 1
                if not is_icmp_error_packet(pkt):
                    router_src = get_interface_ip(in_iface) or next(iter(router_ips), None)
                    if router_src:
                        err_raw = ICMPHandler.build_icmp_response_packet(router_src, pkt, ip_data, ICMPHandler.TYPE_DEST_UNREACHABLE, 0)
                        nhop_err, out_port_err = trie.lookup(pkt.source_ip)
                        if nhop_err and arp_manager.lookup(pkt.source_ip):
                            eth_hdr = struct.pack("!6s6sH", mac_to_bytes(arp_manager.lookup(pkt.source_ip)), get_interface_mac(out_port_err), 0x0800)
                            sock.sendto(eth_hdr + err_raw, (out_port_err, 0))
                continue

            new_pkt, drop_flag = decrease_ttl(pkt)
            if drop_flag:
                stats["drop"] += 1
                print(f"❌ Drop: {pkt.source_ip} -> {pkt.dest_ip} (Hết TTL)")
                if not is_icmp_error_packet(pkt):
                    router_src = get_interface_ip(in_iface) or next(iter(router_ips), None)
                    if router_src:
                        err_raw = ICMPHandler.build_icmp_response_packet(router_src, pkt, ip_data, ICMPHandler.TYPE_TIME_EXCEEDED, 0)
                        nhop_err, out_port_err = trie.lookup(pkt.source_ip)
                        if nhop_err and arp_manager.lookup(pkt.source_ip):
                            eth_hdr = struct.pack("!6s6sH", mac_to_bytes(arp_manager.lookup(pkt.source_ip)), get_interface_mac(out_port_err), 0x0800)
                            sock.sendto(eth_hdr + err_raw, (out_port_err, 0))
                continue

            final_ip_raw = encode_ip(new_pkt)
            target_ip = pkt.dest_ip if nhop == "0.0.0.0" else nhop
            
            # C. Tra cứu ARP Động
            dest_mac_str = arp_manager.lookup(target_ip)
            
            if dest_mac_str:
                # Đã có MAC -> Gửi đi luôn
                dest_mac = mac_to_bytes(dest_mac_str)
                src_mac = get_interface_mac(out_port)
                eth_header = struct.pack("!6s6sH", dest_mac, src_mac, 0x0800)
                sock.sendto(eth_header + final_ip_raw, (out_port, 0))
                stats["fwd"] += 1
                print(f"✅ FWD: {pkt.source_ip} -> {pkt.dest_ip} | Port: {out_port}")
            else:
                # Chưa có MAC -> Đưa vào hàng đợi & Phát Broadcast ARP Request
                arp_manager.enqueue_packet(target_ip, final_ip_raw, out_port)
                req_frame = ARPManager.build_arp_request(get_interface_mac(out_port), get_interface_ip(out_port), target_ip)
                sock.sendto(req_frame, (out_port, 0))
                stats["arp_req"] += 1
                print(f"⏳ Tạm giữ IP: {pkt.source_ip}->{pkt.dest_ip}. Đang gửi ARP Request tìm {target_ip}...")

        except KeyboardInterrupt:
            print(f"\n🛑 Tắt Router. Thống kê: Nhận {stats['rx']} | Đã chuyển {stats['fwd']} | Đã drop {stats['drop']} | ARP Req {stats['arp_req']} | ARP Rep {stats['arp_rep']}")
            break
        except Exception as e:
            print("Lỗi hệ thống:", e)

if __name__ == "__main__":
    main()
