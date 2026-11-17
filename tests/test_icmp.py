# -*- coding: utf-8 -*-
from __future__ import annotations
import sys
import os
import struct

# Thêm thư mục gốc vào PYTHONPATH để gọi được core và icmp
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ip_decoder import decode_ip, encode_ip, decrease_ttl, IPPacket
from core.checksum import calculate_checksum, verify_checksum
from icmp.icmp_handler import ICMPHandler


def create_sample_echo_request(ttl: int = 64, dest_ip: str = "192.168.2.10") -> bytes:
    """Hàm phụ trợ: Tạo một gói IPv4 kèm ICMP Echo Request mẫu để test"""
    # Tạo phần dữ liệu ICMP Echo Request (Type=8, Code=0, Checksum=0, ID=100, Seq=1) + Payload
    icmp_temp = struct.pack("!BBHHH", 8, 0, 0, 100, 1) + b"pingtest"
    icmp_csum = calculate_checksum(icmp_temp)
    icmp_raw = struct.pack("!BBHHH", 8, 0, icmp_csum, 100, 1) + b"pingtest"

    # Đóng gói vào IPv4 sử dụng hàm encode_ip của TV1
    ip_pkt = IPPacket(
        version=4, ihl=5, tos=0,
        total_length=20 + len(icmp_raw),
        identification=54321, flags=0, fragment_offset=0,
        ttl=ttl, protocol=1, checksum=0,
        source_ip="192.168.1.10",
        dest_ip=dest_ip,
        options=b"",
        payload=icmp_raw
    )
    return encode_ip(ip_pkt)


def test_icmp_engine():
    print("=== BẮT ĐẦU CHẠY UNIT TESTS CHO ICMP ENGINE ===")

    # -------------------------------------------------------------
    # TEST 1: Kiểm thử tạo gói ICMP Echo Reply (Type 0, Code 0)
    # -------------------------------------------------------------
    raw_req = create_sample_echo_request(ttl=64)
    decoded_req = decode_ip(raw_req)

    # Gọi hàm tạo Echo Reply từ payload của request
    reply_icmp = ICMPHandler.create_echo_reply(decoded_req.payload)
    r_type, r_code, _, r_id, r_seq = struct.unpack("!BBHHH", reply_icmp[:8])

    assert r_type == ICMPHandler.TYPE_ECHO_REPLY, "Lỗi: Echo Reply phải có Type = 0"
    assert r_code == 0, "Lỗi: Code phải bằng 0"
    assert r_id == 100 and r_seq == 1, "Lỗi: Identifier hoặc Sequence Number không được thay đổi"
    assert reply_icmp[8:] == b"pingtest", "Lỗi: Payload phản hồi phải khớp với payload gốc"
    assert calculate_checksum(reply_icmp) == 0, "Lỗi: ICMP Checksum tính toán không hợp lệ"
    print("[TEST 1] ICMP Echo Reply (Type 0): ✅ PASS")

    # -------------------------------------------------------------
    # TEST 2: Kiểm thử tạo gói ICMP Time Exceeded (Type 11, Code 0) khi TTL = 1 giảm về 0
    # -------------------------------------------------------------
    raw_ttl1 = create_sample_echo_request(ttl=1)
    decoded_ttl1 = decode_ip(raw_ttl1)
    _, is_expired = decrease_ttl(decoded_ttl1)
    assert is_expired is True, "Lỗi: TTL=1 khi giảm phải trả về trạng thái hết hạn (is_expired = True)"

    te_icmp = ICMPHandler.create_icmp_error(
        ICMPHandler.TYPE_TIME_EXCEEDED,
        ICMPHandler.CODE_TTL_EXCEEDED,
        raw_ttl1
    )
    te_type, te_code, _, te_unused = struct.unpack("!BBHI", te_icmp[:8])

    assert te_type == ICMPHandler.TYPE_TIME_EXCEEDED, "Lỗi: Time Exceeded phải có Type = 11"
    assert te_code == 0, "Lỗi: Code phải bằng 0"
    assert te_unused == 0, "Lỗi: 4 bytes Unused phải bằng 0"
    # Kiểm tra phần trích dẫn gói IP gốc phía sau phải khớp chính xác 28 bytes đầu của gói gốc
    assert te_icmp[8:] == raw_ttl1[:28], "Lỗi: Phần trích dẫn IP Header + 8B gốc không chính xác"
    assert calculate_checksum(te_icmp) == 0, "Lỗi: Checksum gói Time Exceeded không hợp lệ"
    print("[TEST 2] ICMP Time Exceeded (Type 11): ✅ PASS")

    # -------------------------------------------------------------
    # TEST 3: Kiểm thử tạo gói ICMP Destination Unreachable (Type 3, Code 0)
    # -------------------------------------------------------------
    du_icmp = ICMPHandler.create_icmp_error(
        ICMPHandler.TYPE_DEST_UNREACHABLE,
        ICMPHandler.CODE_NET_UNREACHABLE,
        raw_req
    )
    du_type, du_code, _, _ = struct.unpack("!BBHI", du_icmp[:8])

    assert du_type == ICMPHandler.TYPE_DEST_UNREACHABLE, "Lỗi: Dest Unreachable phải có Type = 3"
    assert du_code == 0, "Lỗi: Code phải bằng 0"
    assert calculate_checksum(du_icmp) == 0, "Lỗi: Checksum gói Destination Unreachable không hợp lệ"
    print("[TEST 3] ICMP Destination Unreachable (Type 3): ✅ PASS")

    # -------------------------------------------------------------
    # TEST 4: Kiểm thử hàm tích hợp bọc gói IPv4 + ICMP Response (`build_icmp_response_packet`)
    # -------------------------------------------------------------
    full_response_bytes = ICMPHandler.build_icmp_response_packet(
        router_ip="192.168.1.1",
        original_packet=decoded_ttl1,
        original_raw_ip=raw_ttl1,
        icmp_type=ICMPHandler.TYPE_TIME_EXCEEDED,
        icmp_code=ICMPHandler.CODE_TTL_EXCEEDED
    )

    # Kiểm tra checksum của lớp IP bên ngoài 
    assert verify_checksum(full_response_bytes[:20]) is True, "Lỗi: IP Header của gói phản hồi sai checksum"

    resp_packet = decode_ip(full_response_bytes)
    assert resp_packet.source_ip == "192.168.1.1", "Lỗi: IP nguồn của gói phản hồi phải là Router IP"
    assert resp_packet.dest_ip == "192.168.1.10", "Lỗi: IP đích phải là máy gửi ban đầu"
    assert resp_packet.protocol == 1, "Lỗi: Protocol phải là 1 (ICMP)"
    print("[TEST 4] Tích hợp bọc gói IPv4 + ICMP Response: ✅ PASS")

    print("\n🎉 TẤT CẢ UNIT TESTS ĐÃ VƯỢT QUA THÀNH CÔNG!")


if __name__ == "__main__":
    test_icmp_engine()