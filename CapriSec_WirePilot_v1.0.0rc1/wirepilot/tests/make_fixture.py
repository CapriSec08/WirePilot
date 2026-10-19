"""Generate synthetic PCAP bytes offline using only the standard library."""

import ipaddress
import struct
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ip_packet(source, destination, protocol, payload):
    source, destination = (
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0,
        64,
        protocol,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + payload


def tcp(source, destination, sport, dport, flags, seq=1, ack=0, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = (
        ipaddress.ip_address(source).packed
        + ipaddress.ip_address(destination).packed
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    header = (
        header[:16]
        + struct.pack("!H", checksum(pseudo + header + payload))
        + header[18:]
    )
    return ip_packet(source, destination, 6, header + payload)


def dns(response=False):
    name = (
        b"".join(
            bytes([len(label)]) + label.encode()
            for label in "missing.example.test".split(".")
        )
        + b"\0"
    )
    data = (
        struct.pack("!6H", 1, 0x8183 if response else 0x0100, 1, 0, 0, 0)
        + name
        + struct.pack("!HH", 1, 1)
    )
    ports = (53, 53000) if response else (53000, 53)
    return ip_packet(
        "10.0.0.53" if response else "10.0.0.10",
        "10.0.0.10" if response else "10.0.0.53",
        17,
        struct.pack("!HHHH", *ports, 8 + len(data), 0) + data,
    )


def arp(mac):
    hardware = bytes.fromhex(mac)
    return (
        b"\xff" * 6
        + hardware
        + b"\x08\x06"
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + hardware
        + ipaddress.ip_address("10.0.0.1").packed
        + b"\0" * 6
        + ipaddress.ip_address("10.0.0.10").packed
    )


def write_fixture(path):
    packets = [
        (0, dns()),
        (0.02, dns(True)),
        (1, tcp("10.0.0.10", "10.0.0.20", 40000, 443, 2, 10)),
        (1.01, tcp("10.0.0.20", "10.0.0.10", 443, 40000, 20, 0, 11)),
        (2, tcp("10.0.0.10", "10.0.0.30", 41000, 80, 2)),
        (2.01, tcp("10.0.0.30", "10.0.0.10", 80, 41000, 18, 100, 2)),
        (2.02, tcp("10.0.0.10", "10.0.0.30", 41000, 80, 16, 2, 101)),
    ]
    request = b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n"
    packets.extend(
        [
            (2.03, tcp("10.0.0.10", "10.0.0.30", 41000, 80, 24, 2, 101, request)),
            (
                2.04,
                tcp(
                    "10.0.0.30",
                    "10.0.0.10",
                    80,
                    41000,
                    24,
                    101,
                    2 + len(request),
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                ),
            ),
        ]
    )
    packets.extend(
        (3 + i * 0.1, tcp("10.0.0.40", "10.0.0.20", 42000 + i, 1000 + i, 2, i))
        for i in range(25)
    )
    packets.extend(
        (10 + i * 10, tcp("10.0.0.50", "192.0.2.10", 43000 + i, 443, 2, i))
        for i in range(8)
    )
    packets.extend([(81, arp("020000000001")), (82, arp("020000000002"))])
    with open(path, "wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for seconds, packet in sorted(packets):
            stream.write(
                struct.pack(
                    "<IIII",
                    1760000000 + int(seconds),
                    round((seconds % 1) * 1000000),
                    len(packet),
                    len(packet),
                )
            )
            stream.write(packet)


if __name__ == "__main__":
    target = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "synthetic-investigation.pcap"
    )
    target.parent.mkdir(exist_ok=True)
    write_fixture(target)
    print(target)
