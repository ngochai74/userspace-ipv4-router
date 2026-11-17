import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from routing.trie import RoutingTrie

class RouteForwarder:
    def __init__(self, routes_file: str, arp_file: str):
        self.trie = RoutingTrie()
        self.arp_table = {}
        
        self.load_routes(routes_file)
        self.load_arp(arp_file)

    def load_routes(self, filepath: str):
       
        if not os.path.exists(filepath):
            print(f"Lỗi: Không tìm thấy file {filepath}")
            return
            
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    self.trie.insert(parts[0], parts[1], parts[2])
                    
        print(f"Đã nạp bảng định tuyến từ {filepath}.")

    def load_arp(self, filepath: str):
        """Đọc bảng ARP tĩnh ánh xạ IP sang MAC"""
        if not os.path.exists(filepath):
            print(f"Lỗi: Không tìm thấy file {filepath}")
            return
            
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                parts = line.split()
                if len(parts) >= 2:
                    ip, mac = parts[0], parts[1]
                    self.arp_table[ip] = mac
                    
        print(f"Đã nạp bảng ARP từ {filepath}.")

    def get_forwarding_decision(self, dest_ip: str) -> tuple:
        """
        Nhận IP đích, trả về (Interface, Target IP, MAC Đích)
        """
        # 1. Tra cứu tuyến đường (LPM)
        route_node = self.trie.search(dest_ip)
        if not route_node:
            return None, None, None

        out_interface = route_node.interface
        next_hop = route_node.next_hop

        # 2. Quyết định IP cần lấy MAC
        target_ip = dest_ip if next_hop == "0.0.0.0" else next_hop

        # 3. Tra cứu MAC đích
        dest_mac = self.arp_table.get(target_ip)

        return out_interface, target_ip, dest_mac

if __name__ == "__main__":
    # Chạy thử nghiệm thu
    forwarder = RouteForwarder('../config/routes.txt', '../config/arp_table.txt')
    
    # Kịch bản 1: IP thuộc mạng kết nối trực tiếp (192.168.1.0/24)
    ip_test_1 = "192.168.1.10"
    iface, tgt_ip, mac = forwarder.get_forwarding_decision(ip_test_1)
    print(f"\n[Test 1] Tra cứu {ip_test_1}:")
    print(f" -> Cổng ra: {iface} | IP cần liên lạc: {tgt_ip} | MAC đích: {mac}")
    
    # Kịch bản 2: IP thuộc mạng cần qua Gateway (10.0.0.0/8 qua 192.168.1.254)
    ip_test_2 = "10.0.0.5"
    iface, tgt_ip, mac = forwarder.get_forwarding_decision(ip_test_2)
    print(f"\n[Test 2] Tra cứu {ip_test_2}:")
    print(f" -> Cổng ra: {iface} | IP cần liên lạc: {tgt_ip} | MAC đích: {mac}")
