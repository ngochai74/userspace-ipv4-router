from __future__ import annotations
import sys
import os

# Cấu hình đường dẫn để gọi được module trong thư mục core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ip_decoder import decode_ip, encode_ip, decrease_ttl
from core.checksum import calculate_checksum, verify_checksum

def test_ip_core():
    print("Bắt đầu kiểm thử Module IP Core...")

    # 1. Tạo một gói tin IPv4 Header mẫu (20 bytes) - Gói ICMP Echo Request
    # Nguồn: 192.168.1.10, Đích: 8.8.8.8, TTL: 64, Protocol: 1 (ICMP)
    raw_header = b'\x45\x00\x00\x54\x12\x34\x40\x00\x40\x01\x00\x00\xc0\xa8\x01\x0a\x08\x08\x08\x08'
    
    # Tính toán checksum chuẩn cho header này
    csum = calculate_checksum(raw_header)
    # Gắn checksum vào header (byte 10 và 11)
    valid_header = raw_header[:10] + csum.to_bytes(2, 'big') + raw_header[12:]
    
    # Payload giả lập (ICMP data)
    payload = b'helloworld'
    full_packet = valid_header + payload

    # 2. Kiểm thử Verify Checksum
    assert verify_checksum(valid_header) == True, "Lỗi: Hàm verify_checksum không nhận diện được header hợp lệ!"
    print("[TEST 1] Checksum Verification: PASS")

    # 3. Kiểm thử Decode IP
    packet = decode_ip(full_packet)
    assert packet.source_ip == "192.168.1.10", "Lỗi: Sai Source IP"
    assert packet.dest_ip == "8.8.8.8", "Lỗi: Sai Dest IP"
    assert packet.ttl == 64, "Lỗi: Sai TTL"
    assert packet.payload == payload, "Lỗi: Sai Payload"
    print("[TEST 2] IP Decoding: PASS")

    # 4. Kiểm thử Giảm TTL
    new_packet, is_dropped = decrease_ttl(packet)
    assert new_packet.ttl == 63, "Lỗi: TTL chưa được giảm"
    assert is_dropped == False, "Lỗi: Gói tin bị drop sai"
    print("[TEST 3] Decrease TTL: PASS")

    # 5. Kiểm thử Encode lại gói tin
    encoded_packet = encode_ip(new_packet)
    assert verify_checksum(encoded_packet[:20]) == True, "Lỗi: Checksum sai sau khi encode lại!"
    print("[TEST 4] IP Encoding & Recalculate Checksum: PASS")

    print("✅ TẤT CẢ UNIT TEST CORE ĐÃ PASS!")

if __name__ == "__main__":
    test_ip_core()
