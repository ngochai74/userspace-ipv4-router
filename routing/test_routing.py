import sys
import os

# Thêm thư mục gốc vào PYTHONPATH để gọi được module routing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from routing.trie import RoutingTrie

def test_lpm_lookup():
    trie = RoutingTrie()
    
    # 1. Giả lập thêm dữ liệu mạng
    trie.insert("10.0.0.0/8", "10.0.0.1", "eth0")
    trie.insert("10.1.0.0/16", "10.1.0.1", "eth1")
    trie.insert("0.0.0.0/0", "192.168.1.254", "eth2") # Default route
    
    print("Bắt đầu kiểm thử Routing LPM...")
    
    # 2. Test 1: Khớp Longest-Prefix (Phải ưu tiên /16 ra eth1 chứ không phải /8)
    next_hop, iface = trie.lookup("10.1.5.20")
    print(f"[TEST 1] Tra cứu 10.1.5.20 -> Next Hop: {next_hop}, Interface: {iface}")
    assert iface == "eth1", "Lỗi Test 1: Phải ra eth1"

    # 3. Test 2: Khớp Default Route
    next_hop, iface = trie.lookup("8.8.8.8")
    print(f"[TEST 2] Tra cứu 8.8.8.8 -> Next Hop: {next_hop}, Interface: {iface}")
    assert iface == "eth2", "Lỗi Test 2: Phải ra eth2"

    print("✅ TẤT CẢ UNIT TEST ROUTING ĐÃ PASS!")

if __name__ == "__main__":
    test_lpm_lookup()
