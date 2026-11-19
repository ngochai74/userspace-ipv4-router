from __future__ import annotations
import struct
from core.checksum import calculate_checksum
from core.ip_decoder import IPPacket, encode_ip


class ICMPHandler:
    # Các hằng số chuẩn RFC 792
    TYPE_ECHO_REPLY = 0
    TYPE_DEST_UNREACHABLE = 3
    TYPE_ECHO_REQUEST = 8
    TYPE_TIME_EXCEEDED = 11

    CODE_NET_UNREACHABLE = 0
    CODE_HOST_UNREACHABLE = 1
    CODE_PORT_UNREACHABLE = 3
    PROTOCOL_UDP = 17
    CODE_TTL_EXCEEDED = 0

    PROTOCOL_ICMP = 1

    @classmethod
    def create_echo_reply(cls, original_icmp_payload: bytes) -> bytes:
        """
        Tạo phần dữ liệu ICMP Echo Reply (Type 0, Code 0) từ ICMP Echo Request gốc.
        :param original_icmp_payload: packet.payload từ IPPacket của TV1
        :return: bytes của gói ICMP Echo Reply
        """
        if len(original_icmp_payload) < 8:
            raise ValueError("Gói tin ICMP Echo Request quá ngắn (dưới 8 bytes)")

        # Giữ nguyên Identifier (2B), Sequence (2B) và Data (từ byte thứ 8 trở đi)
        rest_of_header = original_icmp_payload[4:8]
        data = original_icmp_payload[8:]

        # Đóng gói tạm với checksum = 0 và tính checksum 
        temp_pkt = struct.pack("!BBH", cls.TYPE_ECHO_REPLY, 0, 0) + rest_of_header + data
        csum = calculate_checksum(temp_pkt)

        # Đóng gói hoàn chỉnh
        return struct.pack("!BBH", cls.TYPE_ECHO_REPLY, 0, csum) + rest_of_header + data

    @classmethod
    def create_icmp_error(cls, icmp_type: int, icmp_code: int, original_raw_ip: bytes) -> bytes:
        """
        Tạo phần dữ liệu ICMP báo lỗi (Time Exceeded hoặc Destination Unreachable).
        Theo chuẩn RFC 792: Payload của ICMP lỗi = IP Header gốc + 8 bytes đầu của payload gốc.
        :param icmp_type: 11 (Time Exceeded) hoặc 3 (Destination Unreachable)
        :param icmp_code: Mã lỗi chi tiết (thường là 0)
        :param original_raw_ip: Chuỗi bytes thô của toàn bộ gói IPv4 gốc gây lỗi
        :return: bytes của gói ICMP báo lỗi
        """
        if len(original_raw_ip) < 28:
            raise ValueError("Gói IP gốc phải dài ít nhất 28 bytes (20B IP Header + 8B Data)")

        # Lấy độ dài thực tế của IP Header gốc (tính cả Options nếu có)
        ihl_bytes = (original_raw_ip[0] & 0x0F) * 4
        quoted_data = original_raw_ip
        # 4 bytes Unused = 0
        temp_pkt = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0) + quoted_data
        csum = calculate_checksum(temp_pkt)

        return struct.pack("!BBHI", icmp_type, icmp_code, csum, 0) + quoted_data

    @classmethod
    def build_icmp_response_packet(
        cls,
        router_ip: str,
        original_packet: IPPacket,
        original_raw_ip: bytes,
        icmp_type: int,
        icmp_code: int = 0
    ) -> bytes:
        """
        Hàm tích hợp dành cho main.py: Tạo gói IPv4 hoàn chỉnh chứa thông điệp ICMP bên trong
        để Router gửi ngược lại cho người gửi ban đầu (original_packet.source_ip).
        """
        if icmp_type == cls.TYPE_ECHO_REPLY:
            icmp_bytes = cls.create_echo_reply(original_packet.payload)
        else:
            icmp_bytes = cls.create_icmp_error(icmp_type, icmp_code, original_raw_ip)

        # Tạo đối tượng IPPacket chuẩn theo cấu trúc dataclass của TV1
        reply_ip_pkt = IPPacket(
            version=4,
            ihl=5,
            tos=0,
            total_length=20 + len(icmp_bytes),
            identification=original_packet.identification,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=cls.PROTOCOL_ICMP,
            checksum=0,
            source_ip=router_ip,                  # IP của cổng Router gửi phản hồi
            dest_ip=original_packet.source_ip,    # Gửi ngược lại cho người gửi gốc
            options=b"",
            payload=icmp_bytes
        )

        # Dùng hàm encode_ip của TV1 để tự động tính IP Checksum và xuất ra bytes
        return encode_ip(reply_ip_pkt, recalculate_checksum=True)
