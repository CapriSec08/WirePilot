from __future__ import annotations

import csv
import hashlib
import io
import os
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
import math
import signal
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    capture_root: Path
    state_root: Path
    tshark: str = "tshark"
    packet_limit: int = 50000
    max_capture_bytes: int = 512 * 1024 * 1024
    timeout: int = 60
    allow_payload: bool = False
    probe_cidrs: tuple[str, ...] = ()
    capture_interfaces: tuple[str, ...] = ()
    import_root: Path | None = None

    @classmethod
    def from_env(cls):
        return cls(
            Path(os.environ.get("WIREPILOT_CAPTURE_ROOT", "./captures")).resolve(),
            Path(os.environ.get("WIREPILOT_STATE_ROOT", "./wirepilot-state")).resolve(),
            os.environ.get("WIREPILOT_TSHARK", "tshark"),
            min(250000, max(1, int(os.environ.get("WIREPILOT_PACKET_LIMIT", "50000")))),
            allow_payload=os.environ.get("WIREPILOT_ALLOW_PAYLOAD") == "1",
            probe_cidrs=tuple(
                x.strip()
                for x in os.environ.get("WIREPILOT_PROBE_CIDRS", "").split(",")
                if x.strip()
            ),
            capture_interfaces=tuple(
                x.strip()
                for x in os.environ.get("WIREPILOT_CAPTURE_INTERFACES", "").split(",")
                if x.strip()
            ),
            import_root=Path(os.environ["WIREPILOT_IMPORT_ROOT"]).resolve()
            if os.environ.get("WIREPILOT_IMPORT_ROOT")
            else None,
        )


def run_bounded(
    args: list[str],
    timeout: int = 60,
    max_bytes: int = 32 * 1024 * 1024,
    accepted_returncodes=(0,),
) -> str:
    """No shell; bound execution time and both output streams on Windows/Linux."""
    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()

    def stop():
        try:
            if os.name != "nt":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass

    def read(pipe, bucket, limit):
        while chunk := pipe.read(65536):
            if len(bucket) + len(chunk) > limit:
                exceeded.set()
                stop()
                break
            bucket.extend(chunk)
        pipe.close()

    threads = [
        threading.Thread(
            target=read, args=(proc.stdout, buffers[0], max_bytes), daemon=True
        ),
        threading.Thread(
            target=read, args=(proc.stderr, buffers[1], 1024 * 1024), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stop()
        proc.wait()
        raise ValueError("Command timed out; narrow the capture or query.") from exc
    except BaseException:
        stop()
        proc.wait()
        raise
    finally:
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            stop()
            for thread in threads:
                thread.join(timeout=2)
            raise ValueError(
                "Child output pipes did not close; subprocess group terminated where supported."
            )
    if exceeded.is_set():
        raise ValueError("Output limit exceeded; narrow the capture or query.")
    if proc.returncode not in accepted_returncodes:
        raise ValueError(
            "Command failed: " + buffers[1].decode("utf-8", "replace")[-2000:]
        )
    return buffers[0].decode("utf-8", "replace")


FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "tcp.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.zero_window",
    "tcp.analysis.ack_rtt",
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "dns.time",
    "http.request.method",
    "http.host",
    "http.response.code",
    "http.time",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.alert_message.desc",
    "icmp.type",
    "icmp.code",
    "icmpv6.type",
    "icmpv6.code",
    "arp.opcode",
    "arp.src.proto_ipv4",
    "arp.src.hw_mac",
    "dhcp.option.dhcp",
    "dhcp.id",
    "smb2.cmd",
    "smb2.nt_status",
    "smb2.flags.response",
    "smb2.msg_id",
    "smb2.sesid",
    "smb2.fid",
    "smb2.filename",
    "smb2.write_length",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
    "ntlmssp.auth.username",
    "ntlmssp.auth.domain",
    "kerberos.error_code",
    "kerberos.CNameString",
    "http.request.uri",
    "http.request_in",
    "http.response_in",
    "dns.response_in",
    "dns.response_to",
    "dns.a",
    "dns.aaaa",
    "tls.handshake.version",
    "tls.record.version",
    "ip.ttl",
    "ipv6.hlim",
    "ip.flags.df",
    "icmp.mtu",
    "icmpv6.mtu",
    "vlan.id",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.window_size_value",
    "udp.stream",
)


class Store:
    def __init__(self, config: Config):
        self.config = config
        config.state_root.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS captures(id TEXT PRIMARY KEY, path TEXT, sha256 TEXT, size INTEGER);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, title TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, case_id TEXT, text TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS evidence(case_id TEXT, capture_id TEXT, PRIMARY KEY(case_id,capture_id));
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, action TEXT, subject TEXT, created REAL);
            """)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.config.state_root / "wirepilot.sqlite3")
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def audit(self, action, subject):
        with self.db() as db:
            db.execute(
                "INSERT INTO audit(action,subject,created) VALUES(?,?,?)",
                (action, subject, time.time()),
            )

    def safe_capture(self, path: str) -> Path:
        root = self.config.capture_root.resolve()
        value = Path(path)
        candidate = (
            (root / value).resolve() if not value.is_absolute() else value.resolve()
        )
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise ValueError(
                "Capture must be a regular file inside WIREPILOT_CAPTURE_ROOT."
            )
        if candidate.stat().st_size > self.config.max_capture_bytes:
            raise ValueError("Capture exceeds the 512 MiB limit; split it first.")
        with candidate.open("rb") as stream:
            magic = stream.read(4)
        if magic not in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        ):
            raise ValueError("Expected an uncompressed PCAP or PCAPNG file.")
        return candidate

    @staticmethod
    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def register(self, path: str):
        candidate = self.safe_capture(path)
        digest = self.digest(candidate)
        capture_id = "cap_" + uuid.uuid4().hex[:16]
        with self.db() as db:
            db.execute(
                "INSERT INTO captures VALUES(?,?,?,?)",
                (capture_id, str(candidate), digest, candidate.stat().st_size),
            )
        self.audit("register_capture", capture_id)
        return {
            "capture_id": capture_id,
            "sha256": digest,
            "size_bytes": candidate.stat().st_size,
            "name": candidate.name,
            "status": "registered; decoding not yet validated",
        }

    def capture(self, capture_id):
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM captures WHERE id=?", (capture_id,)
            ).fetchone()
        if row is None:
            raise ValueError("Unknown capture_id; register a capture first.")
        path = self.safe_capture(row["path"])
        if self.digest(path) != row["sha256"]:
            raise ValueError(
                "Capture changed since registration. Register the new evidence separately."
            )
        return dict(row)


class Decoder:
    def __init__(self, store: Store):
        self.store = store
        self.config = store.config
        self._fields = None

    def executable(self):
        exe = shutil.which(self.config.tshark)
        if not exe:
            raise ValueError(
                "TShark is missing. Install Wireshark/TShark or set WIREPILOT_TSHARK."
            )
        return exe

    def available_fields(self):
        if self._fields is None:
            data = run_bounded(
                [self.executable(), "-G", "fields"],
                self.config.timeout,
                64 * 1024 * 1024,
            )
            self._fields = {
                line.split("\t")[2]
                for line in data.splitlines()
                if line.startswith("F\t") and len(line.split("\t")) > 2
            }
        return self._fields

    def packets(
        self,
        capture_id: str,
        display_filter: str = "",
        fields=FIELDS,
        start_frame: int = 1,
        frame_count: int | None = None,
        start_epoch: float | None = None,
        end_epoch: float | None = None,
    ):
        if len(display_filter) > 2048 or "\x00" in display_filter:
            raise ValueError("Invalid or oversized display filter.")
        capture = self.store.capture(capture_id)
        count = self.config.packet_limit if frame_count is None else frame_count
        if (
            not 1 <= count <= self.config.packet_limit
            or not 1 <= start_frame <= 10000000
            or start_frame + count > 10000001
        ):
            raise ValueError(
                "Invalid frame range; count must be within WIREPILOT_PACKET_LIMIT and final frame ≤ 10000000."
            )
        for epoch in (start_epoch, end_epoch):
            if epoch is not None and (not math.isfinite(epoch) or epoch < 0):
                raise ValueError(
                    "Timestamps must be finite, nonnegative epoch seconds."
                )
        if (
            start_epoch is not None
            and end_epoch is not None
            and start_epoch > end_epoch
        ):
            raise ValueError("start_epoch must not exceed end_epoch.")
        end_frame = start_frame + count - 1
        available = self.available_fields()
        selected = [field for field in fields if field in available]
        missing = [field for field in fields if field not in available]
        if not {"frame.number", "frame.time_epoch", "frame.len"}.issubset(selected):
            raise ValueError("TShark does not expose required frame fields.")
        args = [
            self.executable(),
            "-n",
            "-r",
            capture["path"],
            "-c",
            str(end_frame + 1),
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
            "-E",
            "escape=y",
        ]
        filters = [f"frame.number >= {start_frame}", f"frame.number <= {end_frame}"]
        if display_filter:
            filters.append(f"({display_filter})")
        if start_epoch is not None:
            filters.append(f"frame.time_epoch >= {start_epoch:.9f}")
        if end_epoch is not None:
            filters.append(f"frame.time_epoch <= {end_epoch:.9f}")
        # Emit an unfiltered sentinel, so even zero-match queries disclose whether more frames exist.
        args.extend(
            ["-Y", "(" + " && ".join(filters) + f") || frame.number == {end_frame + 1}"]
        )
        for field in selected:
            args.extend(["-e", field])
        output = run_bounded(args, self.config.timeout)
        self.store.capture(capture_id)
        rows = [
            dict(zip(selected, row))
            for row in csv.reader(io.StringIO(output), delimiter="\t", quotechar='"')
        ]
        for row in rows:
            # USER is useful metadata; PASS and other FTP arguments can contain secrets.
            if row.get("ftp.request.command", "").upper() != "USER":
                row.pop("ftp.request.arg", None)
        reached = any(
            int(row.get("frame.number", "0") or 0) > end_frame for row in rows
        )
        rows = [
            row
            for row in rows
            if start_frame <= int(row.get("frame.number", "0") or 0) <= end_frame
        ]
        self.store.audit("decode", capture_id)
        coverage = {
            "capture_id": capture_id,
            "sha256": capture["sha256"],
            "packet_prefix_limit": self.config.packet_limit,
            "start_frame": start_frame,
            "end_frame_requested": end_frame,
            "start_epoch": start_epoch,
            "end_epoch": end_epoch,
            "next_start_frame": end_frame + 1 if reached else None,
            "reached_end_of_capture": not reached,
            "whole_capture": start_frame == 1
            and not reached
            and not display_filter
            and start_epoch is None
            and end_epoch is None,
            "returned_packets": len(rows),
            "prefix_limit_reached": reached,
            "display_filter": display_filter,
            "unsupported_fields": missing,
            "scope": f"Input frames {start_frame}–{end_frame}; filters/time bounds apply only in this range. Earlier frames are decoded for protocol context. Use next_start_frame to continue.",
            "limitations": [
                "Only the first occurrence of repeated fields is retained (including tunneled addresses).",
                "Encrypted application content and traffic outside this capture are not visible.",
                "Capture loss, asymmetry and truncation can mimic network faults.",
            ],
        }
        return rows, coverage

    def follow(self, capture_id: str, stream_id: int):
        if not self.config.allow_payload:
            raise ValueError(
                "Payload access is disabled. Enable WIREPILOT_ALLOW_PAYLOAD=1 at server startup if needed."
            )
        if not 0 <= stream_id <= 10000000:
            raise ValueError("Invalid stream_id.")
        capture = self.store.capture(capture_id)
        value = run_bounded(
            [
                self.executable(),
                "-n",
                "-r",
                capture["path"],
                "-c",
                str(self.config.packet_limit),
                "-q",
                "-z",
                f"follow,tcp,ascii,{stream_id}",
            ],
            self.config.timeout,
            1024 * 1024,
        )
        self.store.audit("follow_stream", capture_id)
        return {
            "capture_id": capture_id,
            "sha256": capture["sha256"],
            "stream_id": stream_id,
            "untrusted_capture_content": value[:32000],
            "output_truncated": len(value) > 32000,
            "scope": f"First {self.config.packet_limit} input frames; partial streams are possible.",
        }
