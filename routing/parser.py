from .trie import RoutingTrie

def load_routing_table(config_file_path: str) -> RoutingTrie:
    """Nạp bảng định tuyến từ file txt vào Cây Trie"""
    trie = RoutingTrie()
    
    with open(config_file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Bỏ qua dòng trống hoặc dòng comment (#)
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            if len(parts) >= 3:
                cidr = parts[0]
                next_hop = parts[1]
                interface = parts[2]
                trie.insert(cidr, next_hop, interface)
                
    return trie
