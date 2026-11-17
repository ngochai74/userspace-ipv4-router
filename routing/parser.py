import os
from .trie import RoutingTrie


def load_routing_table(config_file_path: str) -> RoutingTrie:
    """Nạp bảng định tuyến từ file txt vào Cây Trie"""
    trie = RoutingTrie()

    with open(config_file_path, 'r') as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) >= 3:
                cidr = parts[0]
                next_hop = parts[1]
                interface = parts[2]
                trie.insert(cidr, next_hop, interface)

    return trie


def load_arp_table(arp_file_path: str) -> dict:
    """Nạp bảng ARP tĩnh ánh xạ IP sang MAC từ file txt"""
    arp_table = {}
    if not os.path.exists(arp_file_path):
        print(f"Cảnh báo: Không tìm thấy {arp_file_path}")
        return arp_table

    with open(arp_file_path, 'r') as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                arp_table[ip] = mac

    return arp_table
