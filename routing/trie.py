import socket
import struct

class TrieNode:
    """Nút trong cây Trie nhị phân lưu trữ thông tin routing"""
    def __init__(self):
        self.children = {}  # Key: '0' hoặc '1'
        self.next_hop = None
        self.interface = None
        self.is_end = False

class RoutingTrie:
    """Cấu trúc dữ liệu Trie hỗ trợ tra cứu Longest-Prefix Match (LPM)"""
    def __init__(self):
        self.root = TrieNode()

    def _ip_to_bin(self, ip_str: str) -> str:
        """Chuyển đổi IP dạng chuỗi ('192.168.1.1') sang chuỗi 32 bit nhị phân"""
        packed_ip = socket.inet_aton(ip_str)
        ip_int = struct.unpack("!I", packed_ip)[0]
        return f"{ip_int:032b}"

    def insert(self, cidr_str: str, next_hop: str, interface: str):
        """
        Thêm một route vào cây Trie.
        Ví dụ: cidr_str = '192.168.1.0/24'
        """
        ip_part, prefix_len = cidr_str.split('/')
        prefix_len = int(prefix_len)
        bin_ip = self._ip_to_bin(ip_part)
        
        prefix_bits = bin_ip[:prefix_len]
        current = self.root
        for bit in prefix_bits:
            if bit not in current.children:
                current.children[bit] = TrieNode()
            current = current.children[bit]
            
        current.is_end = True
        current.next_hop = next_hop
        current.interface = interface

    def lookup(self, dest_ip: str):
        """
        Tra cứu địa chỉ IP đích theo nguyên tắc Longest-Prefix Match.
        Trả về: (next_hop, interface) hoặc (None, None)
        """
        bin_ip = self._ip_to_bin(dest_ip)
        current = self.root
        best_match = (None, None)

        for bit in bin_ip:
            if current.is_end:
                best_match = (current.next_hop, current.interface)
                
            if bit in current.children:
                current = current.children[bit]
            else:
                break
                
        if current.is_end:
            best_match = (current.next_hop, current.interface)

        return best_match
