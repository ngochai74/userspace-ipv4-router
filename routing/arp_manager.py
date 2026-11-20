import socket
import struct
import time
from collections import defaultdict


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))


def bytes_to_mac(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


class ARPManager:
    ETH_P_ARP = 0x0806
    ARP_OP_REQUEST = 1
    ARP_OP_REPLY = 2
    CACHE_TTL = 300  # Thời gian sống của bản ghi ARP động (300 giây)

    def __init__(self, static_arp_table=None):
       
        self.cache = {}
        
        self.pending_queues = defaultdict(list)

        if static_arp_table:
            for ip, mac in static_arp_table.items():
                self.cache[ip] = (mac.lower(), None)

    def lookup(self, ip: str):
        """Tra cứu MAC từ ARP Cache, tự động xóa nếu bản ghi động đã hết hạn"""
        entry = self.cache.get(ip)
        if not entry:
            return None

        mac, expires_at = entry
        if expires_at is not None and time.time() > expires_at:
            del self.cache[ip]
            return None
        return mac

    def update(self, ip: str, mac: str):
        """Cập nhật bản ghi ARP động mới học được"""
        self.cache[ip] = (mac.lower(), time.time() + self.CACHE_TTL)

    def enqueue_packet(self, target_ip: str, raw_ip: bytes, out_port: str):
        """Đưa gói IP vào hàng đợi trong lúc chờ ARP Reply (giới hạn tối đa 10 gói/IP)"""
        queue = self.pending_queues[target_ip]
        if len(queue) < 10:
            queue.append((raw_ip, out_port, time.time()))

    def pop_pending_packets(self, target_ip: str):
        """Lấy toàn bộ gói tin đang chờ của target_ip ra để gửi đi ngay khi có MAC"""
        items = self.pending_queues.pop(target_ip, [])
        now = time.time()
        
        return [(raw_ip, out_port) for raw_ip, out_port, ts in items if now - ts <= 5.0]

    @classmethod
    def build_arp_request(cls, src_mac: bytes, src_ip: str, target_ip: str) -> bytes:
        """Tạo Ethernet Frame chứa bản tin ARP Request (Broadcast)"""
        eth_header = struct.pack("!6s6sH", b"\xff\xff\xff\xff\xff\xff", src_mac, cls.ETH_P_ARP)
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            1,                          # Hardware type: Ethernet (1)
            0x0800,                     # Protocol type: IPv4 (0x0800)
            6,                          # Hardware size: 6
            4,                          # Protocol size: 4
            cls.ARP_OP_REQUEST,         # Opcode: 1 (Request)
            src_mac,                    # Sender MAC
            socket.inet_aton(src_ip),   # Sender IP
            b"\x00\x00\x00\x00\x00\x00",# Target MAC (chưa biết)
            socket.inet_aton(target_ip) # Target IP
        )
        return eth_header + arp_payload

    @classmethod
    def build_arp_reply(cls, src_mac: bytes, src_ip: str, dst_mac: bytes, dst_ip: str) -> bytes:
        """Tạo Ethernet Frame chứa bản tin ARP Reply (Unicast)"""
        eth_header = struct.pack("!6s6sH", dst_mac, src_mac, cls.ETH_P_ARP)
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            cls.ARP_OP_REPLY,           # Opcode: 2 (Reply)
            src_mac,
            socket.inet_aton(src_ip),
            dst_mac,
            socket.inet_aton(dst_ip)
        )
        return eth_header + arp_payload

    @classmethod
    def parse_arp_packet(cls, raw_arp: bytes):
        """Phân tích 28 bytes ARP payload nhận được từ Raw Socket"""
        if len(raw_arp) < 28:
            return None

        htype, ptype, hlen, plen, opcode, sha, spa, tha, tpa = struct.unpack(
            "!HHBBH6s4s6s4s", raw_arp[:28]
        )
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
            return None

        return {
            "opcode": opcode,
            "sender_mac": bytes_to_mac(sha),
            "sender_ip": socket.inet_ntoa(spa),
            "target_mac": bytes_to_mac(tha),
            "target_ip": socket.inet_ntoa(tpa),
        }
