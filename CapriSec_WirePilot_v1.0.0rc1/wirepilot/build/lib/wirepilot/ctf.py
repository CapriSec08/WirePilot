"""Opt-in, bounded inspection of untrusted capture content. Never executes objects."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
import uuid
from urllib.parse import unquote

from .core import FIELDS, run_bounded


def require_payload(decoder):
    if not decoder.config.allow_payload:
        raise ValueError(
            "Content inspection is disabled. Set WIREPILOT_ALLOW_PAYLOAD=1 at startup."
        )


def decode_text(text, encoding):
    if len(text) > 65536:
        raise ValueError("Input limited to 65536 characters.")
    try:
        if encoding == "base64":
            raw = base64.b64decode("".join(text.split()), validate=True)
        elif encoding == "hex":
            raw = bytes.fromhex(text)
        elif encoding == "url":
            raw = unquote(text, errors="strict").encode()
        elif encoding == "rot13":
            raw = codecs.decode(text, "rot_13").encode()
        else:
            raise ValueError("Use base64, hex, url or rot13.")
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise ValueError(f"Cannot decode {encoding}: {exc}") from exc
    return {
        "encoding": encoding,
        "text": raw.decode("utf-8", "replace"),
        "hex": raw.hex(),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_is_untrusted": True,
    }


def stream_bytes(decoder, capture_id, stream_id):
    require_payload(decoder)
    if not 0 <= stream_id <= 10000000:
        raise ValueError("Invalid stream_id")
    capture = decoder.store.capture(capture_id)
    output = run_bounded(
        [
            decoder.executable(),
            "-n",
            "-r",
            capture["path"],
            "-c",
            str(decoder.config.packet_limit),
            "-q",
            "-z",
            f"follow,tcp,raw,{stream_id}",
        ],
        decoder.config.timeout,
        4 * 1024 * 1024,
    )
    directions = [bytearray(), bytearray()]
    for line in output.splitlines():
        text = line.strip()
        if text and len(text) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", text):
            directions[1 if line.startswith("\t") else 0].extend(bytes.fromhex(text))
    decoder.store.audit("inspect_stream_content", capture_id + ":" + str(stream_id))
    return [bytes(value) for value in directions], capture


def search_capture(decoder, capture_id, needle="", stream_id=None, limit=50):
    require_payload(decoder)
    if not 1 <= limit <= 100 or len(needle) > 256:
        raise ValueError("limit must be 1–100; needle ≤256 characters.")
    pattern = (
        None
        if needle
        else re.compile(rb"(?:flag|ctf|HTB|THM|picoCTF)\{[^\r\n{}]{1,200}\}", re.I)
    )
    matches = []
    total = 0
    if stream_id is not None:
        values, capture = stream_bytes(decoder, capture_id, stream_id)
        sources = [
            (value, {"tcp_stream": stream_id, "direction": index})
            for index, value in enumerate(values)
        ]
        coverage = {
            "capture_id": capture_id,
            "sha256": capture["sha256"],
            "scope": f"Reconstructed stream within first {decoder.config.packet_limit} frames; may be partial.",
        }
    else:
        rows, coverage = decoder.packets(
            capture_id, fields=FIELDS + ("tcp.payload", "udp.payload", "http.file_data")
        )
        sources = []
        for row in rows:
            payload = (
                row.get("tcp.payload")
                or row.get("udp.payload")
                or row.get("http.file_data")
                or ""
            )
            try:
                value = bytes.fromhex(payload.replace(":", ""))
            except ValueError:
                continue
            sources.append(
                (
                    value,
                    {
                        "frame": int(row["frame.number"]),
                        "tcp_stream": row.get("tcp.stream"),
                    },
                )
            )
    for value, source in sources:
        if pattern:
            positions = ((m.start(), m.end()) for m in pattern.finditer(value))
        else:
            query = needle.encode()

            def find_positions():
                offset = 0
                lowered = value.lower()
                lowered_query = query.lower()
                while True:
                    at = lowered.find(lowered_query, offset)
                    if at < 0:
                        return
                    yield at, at + len(query)
                    offset = at + max(1, len(query))

            positions = find_positions()
        for start, end in positions:
            total += 1
            if len(matches) < limit:
                matches.append(
                    {
                        **source,
                        "byte_offset": start,
                        "match": value[start:end].decode("utf-8", "replace"),
                        "context": value[
                            max(0, start - 40) : min(len(value), end + 40)
                        ].decode("utf-8", "replace"),
                    }
                )
    return {
        "coverage": coverage,
        "matches": matches,
        "total_matches": total,
        "truncated": total > len(matches),
        "search": needle or "Common CTF flag patterns",
        "content_is_untrusted": True,
        "limitations": [
            "Packet search can miss strings crossing packet boundaries; use stream_id to reassemble TCP.",
            "Encrypted content, unrecognised encodings and nonstandard flag patterns may not match.",
        ],
    }


def credentials(decoder, capture_id, stream_id):
    values, capture = stream_bytes(decoder, capture_id, stream_id)
    results = []
    for direction, value in enumerate(values):
        user = None
        for line in value.splitlines():
            if line.upper().startswith(b"USER "):
                user = line[5:].decode("utf-8", "replace")[:256]
            elif line.upper().startswith(b"PASS "):
                results.append(
                    {
                        "kind": "FTP-like USER/PASS",
                        "username": user,
                        "password": line[5:].decode("utf-8", "replace")[:512],
                        "direction": direction,
                        "qualification": "Line-pattern match; inspect protocol context.",
                    }
                )
            elif line.lower().startswith(b"authorization: basic "):
                try:
                    decoded = base64.b64decode(
                        line.split(None, 2)[2], validate=True
                    ).decode("utf-8", "replace")
                    username, password = decoded.split(":", 1)
                    results.append(
                        {
                            "kind": "HTTP Basic",
                            "username": username[:256],
                            "password": password[:512],
                            "direction": direction,
                        }
                    )
                except (ValueError, binascii.Error):
                    continue
    return {
        "capture_id": capture_id,
        "sha256": capture["sha256"],
        "tcp_stream": stream_id,
        "credentials": results[:50],
        "truncated": len(results) > 50,
        "sensitive_content": True,
        "content_is_untrusted": True,
        "scope": f"First {decoder.config.packet_limit} frames; captured plaintext only. No password cracking or encrypted-session decryption.",
    }


def dechunk(data):
    offset = 0
    output = bytearray()
    while offset < len(data):
        end = data.find(b"\r\n", offset)
        if end < 0:
            raise ValueError("Incomplete chunk header")
        size = int(data[offset:end].split(b";", 1)[0], 16)
        offset = end + 2
        if size < 0:
            raise ValueError("Negative chunk size")
        if size == 0:
            trailer_end = (
                offset + 2
                if data[offset : offset + 2] == b"\r\n"
                else data.find(b"\r\n\r\n", offset) + 4
            )
            if trailer_end < offset + 2 or trailer_end > len(data):
                raise ValueError("Incomplete trailers")
            return bytes(output), trailer_end
        if (
            size > 2 * 1024 * 1024
            or offset + size + 2 > len(data)
            or data[offset + size : offset + size + 2] != b"\r\n"
        ):
            raise ValueError("Incomplete or oversized chunk")
        output.extend(data[offset : offset + size])
        if len(output) > 2 * 1024 * 1024:
            raise ValueError("Object exceeds 2 MiB")
        offset += size + 2
    raise ValueError("Incomplete chunked body")


def http_objects(decoder, capture_id, stream_id):
    values, capture = stream_bytes(decoder, capture_id, stream_id)
    folder = (
        decoder.config.state_root.resolve() / "objects" / ("obj_" + uuid.uuid4().hex)
    )
    folder.mkdir(parents=True, mode=0o700)
    objects, skipped = [], []
    for direction, value in enumerate(values):
        offset = 0
        while offset < len(value) and len(objects) < 20:
            match = re.search(rb"HTTP/1\.[01] ([0-9]{3})[^\r\n]*\r\n", value[offset:])
            if not match:
                break
            start = offset + match.start()
            header_end = value.find(b"\r\n\r\n", start)
            if header_end < 0 or header_end - start > 32768:
                skipped.append("Incomplete or oversized HTTP headers")
                break
            headers = {}
            for line in value[start:header_end].split(b"\r\n")[1:]:
                if b":" in line:
                    key, content = line.split(b":", 1)
                    headers.setdefault(key.strip().lower(), []).append(content.strip())
            body_start = header_end + 4
            status = int(match.group(1))
            try:
                if 100 <= status < 200 or status in (204, 304):
                    offset = body_start
                    continue
                if b"transfer-encoding" in headers and b"content-length" in headers:
                    raise ValueError("Ambiguous transfer framing")
                if b"transfer-encoding" in headers:
                    if headers[b"transfer-encoding"] != [b"chunked"]:
                        raise ValueError("Unsupported/ambiguous transfer encoding")
                    body, used = dechunk(value[body_start:])
                    offset = body_start + used
                else:
                    lengths = headers.get(b"content-length", [])
                    if len(lengths) != 1:
                        raise ValueError(
                            "Missing/ambiguous Content-Length; close-delimited bodies are not exported"
                        )
                    size = int(lengths[0])
                    if (
                        size < 0
                        or size > 2 * 1024 * 1024
                        or body_start + size > len(value)
                    ):
                        raise ValueError("Incomplete or oversized HTTP object")
                    body = value[body_start : body_start + size]
                    offset = body_start + size
                path = folder / (f"object_{len(objects) + 1:03d}.bin")
                with path.open("xb") as stream:
                    stream.write(body)
                path.chmod(0o600)
                objects.append(
                    {
                        "path": str(path),
                        "bytes": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "status": status,
                        "direction": direction,
                        "stream_byte_offset": body_start,
                        "content_type": headers.get(b"content-type", [b""])[0].decode(
                            "utf-8", "replace"
                        ),
                        "content_encoding": headers.get(b"content-encoding", [b""])[
                            0
                        ].decode("utf-8", "replace"),
                        "note": "Saved raw entity bytes as .bin; content encoding retained. Not executed or declared safe.",
                    }
                )
            except (ValueError, OverflowError) as exc:
                skipped.append(str(exc))
                break
    decoder.store.audit("export_http_objects", capture_id + ":" + str(stream_id))
    return {
        "capture_id": capture_id,
        "sha256": capture["sha256"],
        "tcp_stream": stream_id,
        "objects": objects,
        "skipped": skipped,
        "limit_reached": len(objects) >= 20,
        "scope": f"Visible HTTP/1 responses in reconstructed stream within first {decoder.config.packet_limit} frames.",
        "content_is_untrusted": True,
        "limitations": [
            "Only explicit Content-Length or chunked bodies are exported; no HTTP/2, encrypted HTTP or archive expansion.",
            "Capture completeness and original object identity are not guaranteed. Names supplied by traffic are never used as paths.",
        ],
    }
