import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from routing.trie import RoutingTrie 
class RouteForwarder:
    def __init__(self, routes_file: str):
        self.trie = RoutingTrie()
        self.load_routes(routes_file)

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
                    prefix = parts[0]
                    next_hop = parts[1]
                    interface = parts[2]
                    
                    # Nạp vào cây Trie
                    self.trie.insert(prefix, next_hop, interface)
                    
        print(f"Đã nạp bảng định tuyến từ {filepath} thành công.")

    def get_forwarding_decision(self, dest_ip: str) -> tuple:
        """
        Nhận IP đích, trả về (Interface đầu ra, IP trạm kế tiếp)
        """
        # Tra cứu Longest Prefix Match
        route_node = self.trie.search(dest_ip)
        if not route_node:
            return None, None 

        return route_node.interface, route_node.next_hop
