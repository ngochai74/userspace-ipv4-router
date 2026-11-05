
import struct
import socket
from dataclasses import dataclass, replace
from core.checksum import calculate_checksum


@dataclass
class IPPacket:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    source_ip: str
    dest_ip: str
    options: bytes
    payload: bytes


def decode_ip(raw: bytes) -> IPPacket:
    if len(raw) < 20:
        raise ValueError("Goi tin qua ngan")

    vihl, tos, length, ident, frag, ttl, proto, csum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", raw[:20])

    version, ihl = vihl >> 4, vihl & 15
    hlen = ihl * 4

    if version != 4 or not 5 <= ihl <= 15:
        raise ValueError("IPv4 Header khong hop le")
    if not hlen <= length <= len(raw):
        raise ValueError("Total Length khong hop le")

    return IPPacket(
        version, ihl, tos, length, ident,
        frag >> 13, frag & 0x1FFF, ttl, proto, csum,
        socket.inet_ntoa(src), socket.inet_ntoa(dst),
        raw[20:hlen], raw[hlen:length]
    )


def encode_ip(p: IPPacket, recalculate_checksum=True) -> bytes:
    options = bytes(p.options)
    payload = bytes(p.payload)

    options += b'\x00' * (-len(options) % 4)
    ihl = 5 + len(options) // 4

    if p.version != 4 or ihl != p.ihl or ihl > 15:
        raise ValueError("IPv4 Header khong hop le")

    length = ihl * 4 + len(payload)
    if length > 65535:
        raise ValueError("Goi tin qua lon")

    frag = (p.flags << 13) | p.fragment_offset

    def pack(csum):
        return struct.pack(
            "!BBHHHBBH4s4s",
            (p.version << 4) | ihl, p.tos, length,
            p.identification, frag, p.ttl, p.protocol,
            csum, socket.inet_aton(p.source_ip),
            socket.inet_aton(p.dest_ip)
        ) + options

    header = pack(0)
    if recalculate_checksum:
        header = pack(calculate_checksum(header))
    else:
        header = pack(p.checksum)

    return header + payload


def decrease_ttl(p: IPPacket) -> tuple[IPPacket, bool]:
    if not 0 <= p.ttl <= 255:
        raise ValueError("TTL khong hop le")

    ttl = max(p.ttl - 1, 0)
    return replace(p, ttl=ttl, checksum=0), ttl == 0
