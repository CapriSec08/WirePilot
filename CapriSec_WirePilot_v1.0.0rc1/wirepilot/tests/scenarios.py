"""Deterministic offline lab traffic. No sockets, no real credentials, no malware."""

import struct
from pathlib import Path
from make_fixture import tcp, checksum


def save_pcap(path, packets):
    with open(path, "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            output.write(
                struct.pack(
                    "<IIII",
                    1760000000 + index // 10,
                    (index % 10) * 100000,
                    len(packet),
                    len(packet),
                )
            )
            output.write(packet)


class Flow:
    def __init__(self, port=21, sport=50000):
        self.port, self.sport = port, sport
        self.c, self.s = 100, 1000
        self.packets = [
            tcp("10.0.0.10", "10.0.0.20", sport, port, 2, self.c),
            tcp("10.0.0.20", "10.0.0.10", port, sport, 18, self.s, self.c + 1),
            tcp("10.0.0.10", "10.0.0.20", sport, port, 16, self.c + 1, self.s + 1),
        ]
        self.c += 1
        self.s += 1

    def client(self, data):
        self.packets.append(
            tcp(
                "10.0.0.10",
                "10.0.0.20",
                self.sport,
                self.port,
                24,
                self.c,
                self.s,
                data,
            )
        )
        self.c += len(data)

    def server(self, data):
        self.packets.append(
            tcp(
                "10.0.0.20",
                "10.0.0.10",
                self.port,
                self.sport,
                24,
                self.s,
                self.c,
                data,
            )
        )
        self.s += len(data)


def ftp_capture(path, failures=5):
    flow = Flow()
    flow.server(b"220 Lab FTP ready\r\n")
    for index in range(failures):
        flow.client(b"USER analyst\r\n")
        flow.server(b"331 Password required\r\n")
        flow.client(b"PASS lab-only-password\r\n")
        flow.server(b"530 Login incorrect\r\n")
    flow.client(b"USER analyst\r\n")
    flow.server(b"331 Password required\r\n")
    flow.client(b"PASS lab-success-password\r\n")
    flow.server(b"230 Login successful\r\n")
    save_pcap(path, flow.packets)


def ctf_capture(path):
    flow = Flow(80)
    flow.client(
        b"GET /download HTTP/1.1\r\nHost: lab.example.test\r\nAuthorization: Basic bGFiOnRlc3Qtb25seQ==\r\n\r\n"
    )
    body = b"This is a harmless fixture. flag{wirepilot_stream_reassembly}"
    header = (
        b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="../../escape.sh"\r\nContent-Length: '
        + str(len(body)).encode()
        + b"\r\n\r\n"
    )
    cut = body.index(b"flag{") + 8
    flow.server(header + body[:cut])
    flow.server(body[cut:])
    save_pcap(path, flow.packets)


def smb_capture(path):
    flow = Flow(445)
    for index, status in enumerate([0xC000006D] * 5 + [0]):
        # NetBIOS session framing + SMB2 session-setup response; no passwords or malware.
        header = struct.pack(
            "<4sHHIHHIIQIIQ16s",
            b"\xfeSMB",
            64,
            0,
            status,
            1,
            1,
            1,
            0,
            index,
            0,
            0,
            1,
            b"\0" * 16,
        )
        body = struct.pack("<HHHH", 9, 0, 0, 0)
        data = header + body
        flow.server(bytes([0]) + len(data).to_bytes(3, "big") + data)
    save_pcap(path, flow.packets)


def ipv6_capture(path):
    import ipaddress

    source = ipaddress.ip_address("2001:db8::1").packed
    destination = ipaddress.ip_address("2001:db8::2").packed
    # ICMPv6 packet-too-big, advertised MTU 1280; quoted inner IPv6 header.
    quoted = struct.pack("!IHBB16s16s", 6 << 28, 0, 59, 64, destination, source)
    payload = struct.pack("!BBHI", 2, 0, 0, 1280) + quoted
    pseudo = source + destination + struct.pack("!I3xB", len(payload), 58)
    payload = payload[:2] + struct.pack("!H", checksum(pseudo + payload)) + payload[4:]
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), 58, 64, source, destination
    )
    save_pcap(path, [bytes.fromhex("02000000000202000000000186dd") + header + payload])


def pcapng_from_pcap(source, target):
    raw = Path(source).read_bytes()
    offset = 24
    packets = []

    def block(kind, body):
        body += b"\0" * ((-len(body)) % 4)
        size = len(body) + 12
        return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(
        1, struct.pack("<HHI", 1, 0, 65535)
    )
    while offset < len(raw):
        sec, usec, captured, original = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        data = raw[offset : offset + captured]
        offset += captured
        stamp = sec * 1000000 + usec
        out += block(
            6,
            struct.pack(
                "<IIIII", 0, stamp >> 32, stamp & 0xFFFFFFFF, captured, original
            )
            + data,
        )
    Path(target).write_bytes(out)


def smb_activity_capture(path):
    flow = Flow(445)
    for index in range(35):
        header = struct.pack(
            "<4sHHIHHIIQIIQ16s",
            b"\xfeSMB",
            64,
            0,
            0,
            9,
            1,
            0,
            0,
            index,
            0,
            0,
            1,
            b"\0" * 16,
        )
        body = (
            struct.pack("<HHIQ16sIIHHI", 49, 112, 1, index, b"\x01" * 16, 0, 0, 0, 0, 0)
            + b"X"
        )
        data = header + body
        flow.client(b"\0" + len(data).to_bytes(3, "big") + data)
    save_pcap(path, flow.packets)


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1] / "examples"
    for name, function in [
        ("lab-ftp-auth.pcap", ftp_capture),
        ("lab-ctf-http.pcap", ctf_capture),
        ("lab-smb-auth.pcap", smb_capture),
        ("lab-ipv6-mtu.pcap", ipv6_capture),
        ("lab-smb-activity.pcap", smb_activity_capture),
    ]:
        function(root / name)
    pcapng_from_pcap(root / "lab-ctf-http.pcap", root / "lab-ctf-http.pcapng")
