"""Fixed adapters for local tools. No arbitrary command or argument passthrough."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid

from .core import Store, run_bounded


TOOL_PURPOSES = {
    "tshark": "Packet decoding via Wireshark's command-line engine",
    "dumpcap": "Interface listing and bounded live capture",
    "tcpdump": "Offline summaries, interface listing and bounded live capture",
    "capinfos": "Full-file capture metadata",
    "dig": "DNS queries to a configured authorised resolver",
    "ping": "Bounded ICMP test to a configured authorised target",
    "traceroute": "Bounded Linux path probes to a configured authorised target",
    "tracert": "Bounded Windows path probes to a configured authorised target",
    "ip": "Linux interface, route and neighbour snapshot",
    "ss": "Linux socket snapshot",
    "ipconfig": "Windows interface snapshot",
    "route": "Windows route snapshot",
    "arp": "Windows/macOS neighbour snapshot",
    "netstat": "Windows/macOS socket or route snapshot",
    "ifconfig": "macOS interface snapshot",
    "wireshark": "GUI detection only; analysis uses TShark, no GUI control adapter",
}


class NetworkTools:
    def __init__(self, store: Store):
        self.store = store
        self.config = store.config
        self.capture_lock = threading.Lock()

    def executable(self, name, required=True):
        if name not in TOOL_PURPOSES:
            raise ValueError("Unsupported tool adapter.")
        configured = (
            self.config.tshark
            if name == "tshark"
            else os.environ.get("WIREPILOT_" + name.upper(), name)
        )
        value = shutil.which(configured)
        if required and not value:
            raise ValueError(
                f"{name} is missing; install it or set WIREPILOT_{name.upper()}."
            )
        return value

    def inventory(self):
        return {
            "tools": [
                {
                    "name": name,
                    "installed": bool(self.executable(name, False)),
                    "path": self.executable(name, False),
                    "purpose": purpose,
                    "adapter_implemented": name != "wireshark",
                }
                for name, purpose in TOOL_PURPOSES.items()
            ],
            "system": platform.system(),
            "vantage_point": "Machine/container running WirePilot",
            "capture_interfaces_allowed": list(self.config.capture_interfaces),
            "probe_cidrs_allowed": list(self.config.probe_cidrs),
            "note": "Executable presence does not prove permissions or platform compatibility. No tools are installed automatically. Snapshot tools use PATH.",
        }

    def interfaces(self, backend):
        if backend not in ("dumpcap", "tcpdump"):
            raise ValueError("backend must be dumpcap or tcpdump")
        output = run_bounded([self.executable(backend), "-D"], 10, 256 * 1024)
        return {
            "backend": backend,
            "output": output,
            "allowed": list(self.config.capture_interfaces),
            "note": "Listing does not grant capture permission; use a local interface explicitly configured at startup.",
        }

    def capture_metadata(self, capture_id):
        capture = self.store.capture(capture_id)
        output = run_bounded(
            [
                self.executable("capinfos"),
                "-t",
                "-E",
                "-c",
                "-s",
                "-d",
                "-u",
                "-a",
                "-e",
                capture["path"],
            ],
            30,
            256 * 1024,
        )
        self.store.audit("capinfos", capture_id)
        return {
            "capture_id": capture_id,
            "sha256": capture["sha256"],
            "scope": "Entire capture file, not the decoder prefix.",
            "output": output,
        }

    def tcpdump_summary(self, capture_id, limit):
        if not 1 <= limit <= 200:
            raise ValueError("limit must be 1–200")
        capture = self.store.capture(capture_id)
        output = run_bounded(
            [
                self.executable("tcpdump"),
                "-nn",
                "-q",
                "-tt",
                "-r",
                capture["path"],
                "-c",
                str(limit),
            ],
            30,
            1024 * 1024,
        )
        self.store.audit("tcpdump_summary", capture_id)
        return {
            "capture_id": capture_id,
            "sha256": capture["sha256"],
            "scope": f"First {limit} packets; full-file coverage not established.",
            "output": output,
            "content_is_untrusted": True,
        }

    def authorised_address(self, address):
        value = ipaddress.ip_address(address)
        if value.is_multicast or value.is_unspecified:
            raise ValueError("A unicast target address is required.")
        if not any(
            value in ipaddress.ip_network(cidr, strict=False)
            for cidr in self.config.probe_cidrs
        ):
            raise ValueError("Target is outside WIREPILOT_PROBE_CIDRS.")
        return str(value)

    def diagnostic_command(self, operation, address, name="", record_type="A"):
        address = self.authorised_address(address)
        system = platform.system()
        if operation == "dns":
            if record_type not in (
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "TXT",
                "NS",
                "SOA",
                "PTR",
            ):
                raise ValueError("Unsupported DNS record type.")
            labels = name.rstrip(".").split(".")
            if (
                len(name) > 253
                or not labels
                or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label
                    )
                    for label in labels
                )
            ):
                raise ValueError(
                    "Use a valid ASCII DNS name, without options or shell syntax."
                )
            return [
                self.executable("dig"),
                "@" + address,
                name,
                record_type,
                "+time=2",
                "+tries=1",
                "+noall",
                "+answer",
                "+comments",
                "+stats",
            ]
        if operation == "ping":
            if system == "Windows":
                return [self.executable("ping"), "-n", "3", "-w", "2000", address]
            if system == "Linux":
                return [self.executable("ping"), "-n", "-c", "3", "-W", "2", address]
            raise ValueError(
                "Active ping adapter currently supports Linux and Windows only."
            )
        if operation == "trace":
            if system == "Windows":
                return [
                    self.executable("tracert"),
                    "-d",
                    "-h",
                    "12",
                    "-w",
                    "1000",
                    address,
                ]
            if system == "Linux":
                return [
                    self.executable("traceroute"),
                    "-n",
                    "-m",
                    "12",
                    "-q",
                    "1",
                    "-w",
                    "1",
                    address,
                ]
            raise ValueError(
                "Path-trace adapter currently supports Linux and Windows only."
            )
        raise ValueError("Unsupported diagnostic operation.")

    def diagnostic(self, operation, address, name="", record_type="A"):
        args = self.diagnostic_command(operation, address, name, record_type)
        self.store.audit("diagnostic_" + operation, address)
        output = run_bounded(
            args,
            45 if operation == "trace" else 10,
            256 * 1024,
            accepted_returncodes=(0, 1) if operation == "ping" else (0,),
        )
        return {
            "operation": operation,
            "address": address,
            "output": output,
            "content_is_untrusted": True,
            "vantage_point": "WirePilot server host",
            "note": "Interpret tool output. ICMP filtering can mimic failure; a DNS answer or reachable hop does not establish application health.",
        }

    def capture_command(
        self,
        backend,
        interface,
        capture_filter,
        duration,
        packet_count,
        snaplen,
        output,
    ):
        if interface not in self.config.capture_interfaces:
            raise ValueError(
                "Interface is outside WIREPILOT_CAPTURE_INTERFACES; configure authorised local interfaces at startup."
            )
        if (
            not interface
            or interface.startswith(("-", "TCP@"))
            or "://" in interface
            or "pipe" in interface.lower()
            or any(c in interface for c in "\n\r\0")
        ):
            raise ValueError("Only local capture interfaces are accepted.")
        if (
            not capture_filter.strip()
            or len(capture_filter) > 1024
            or any(c in capture_filter for c in "\n\r\0")
        ):
            raise ValueError(
                "Provide a nonempty BPF capture filter of at most 1024 characters."
            )
        if (
            not 1 <= duration <= 30
            or not 1 <= packet_count <= 20000
            or not 64 <= snaplen <= 65535
        ):
            raise ValueError(
                "Bounds: duration 1–30 seconds, packets 1–20000, snaplen 64–65535."
            )
        if packet_count * (snaplen + 128) > 64 * 1024 * 1024:
            raise ValueError(
                "Requested packet/snaplen budget exceeds 64 MiB; reduce packet_count or snaplen."
            )
        if backend == "dumpcap":
            return [
                self.executable(backend),
                "-p",
                "-i",
                interface,
                "-s",
                str(snaplen),
                "-c",
                str(packet_count),
                "-a",
                f"duration:{duration}",
                "-a",
                "filesize:65536",
                "-w",
                str(output),
                "-f",
                capture_filter,
            ]
        if backend == "tcpdump":
            return [
                self.executable(backend),
                "-nn",
                "-p",
                "-U",
                "-i",
                interface,
                "-s",
                str(snaplen),
                "-c",
                str(packet_count),
                "-w",
                str(output),
                "--",
                capture_filter,
            ]
        raise ValueError("backend must be dumpcap or tcpdump")

    def capture_live(
        self,
        backend,
        interface,
        capture_filter,
        duration=10,
        packet_count=1000,
        snaplen=512,
    ):
        root = self.config.capture_root.resolve()
        output = root / (
            "live_"
            + uuid.uuid4().hex
            + (".pcapng" if backend == "dumpcap" else ".pcap")
        )
        args = self.capture_command(
            backend, interface, capture_filter, duration, packet_count, snaplen, output
        )
        if not self.capture_lock.acquire(blocking=False):
            raise ValueError("A live capture is already running in this server.")
        proc = None
        forced = False
        reason = "tool_completed"
        started = time.time()
        try:
            root.mkdir(parents=True, exist_ok=True)
            self.store.audit("capture_start", backend + ":" + interface)
            with tempfile.TemporaryFile() as log:
                proc = subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=log,
                )
                deadline = (
                    time.monotonic() + duration + (1 if backend == "dumpcap" else 0)
                )
                while proc.poll() is None:
                    if time.monotonic() >= deadline:
                        reason = "duration_limit"
                        break
                    if output.exists() and output.stat().st_size >= 64 * 1024 * 1024:
                        reason = "size_limit"
                        break
                    if os.fstat(log.fileno()).st_size >= 1024 * 1024:
                        reason = "diagnostic_output_limit"
                        break
                    time.sleep(0.05)
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        forced = True
                        proc.kill()
                        proc.wait(timeout=2)
                log.seek(0)
                diagnostic_output = log.read(16000).decode("utf-8", "replace")
            if (
                proc.returncode not in (0, -15)
                or forced
                or reason == "diagnostic_output_limit"
            ):
                raise ValueError(
                    f"Capture failed or required forced termination ({proc.returncode}); file may be incomplete: {output.name}. {diagnostic_output}"
                )
            result = self.store.register(str(output))
            result.update(
                backend=backend,
                interface=interface,
                capture_filter=capture_filter,
                requested_seconds=duration,
                elapsed_seconds=round(time.time() - started, 3),
                packet_limit=packet_count,
                snaplen=snaplen,
                stop_reason=reason,
                diagnostic_output=diagnostic_output,
                scope="Traffic visible at this interface and matching BPF during this interval. Snaplen may truncate packets.",
            )
            self.store.audit("capture_complete", result["capture_id"])
            return result
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            self.capture_lock.release()
