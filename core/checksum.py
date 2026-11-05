
import struct


def calculate_checksum(data: bytes) -> int:
    data = bytes(data)
    if len(data) % 2:
        data += b'\x00'

    total = sum(
        (data[i] << 8) | data[i + 1]
        for i in range(0, len(data), 2)
    )

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def verify_checksum(raw: bytes) -> bool:
    raw = bytes(raw)

    if len(raw) < 20:
        return False

    version, ihl = raw[0] >> 4, (raw[0] & 0x0F) * 4
    total = struct.unpack("!H", raw[2:4])[0]

    return (
        version == 4
        and 20 <= ihl <= 60
        and ihl <= total <= len(raw)
        and calculate_checksum(raw[:ihl]) == 0
    )
