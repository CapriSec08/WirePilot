"""Controlled ingestion of local capture and JSON-lines evidence."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from pathlib import Path


def input_path(config, path, limit=16 * 1024 * 1024):
    if config.import_root is None:
        raise ValueError(
            "Configure WIREPILOT_IMPORT_ROOT for imports. The MCP host must save attachments there first."
        )
    root = config.import_root.resolve()
    value = (root / Path(path)).resolve()
    if (
        not value.is_relative_to(root)
        or not value.is_file()
        or value.stat().st_size > limit
    ):
        raise ValueError(
            "Import must be a regular file within WIREPILOT_IMPORT_ROOT and within its size limit."
        )
    return value


def import_capture(store, path):
    source = input_path(store.config, path, store.config.max_capture_bytes)
    root = store.config.capture_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    # Read-only preflight validates type before copying; root check still applies to registration.
    with source.open("rb") as stream:
        magic = stream.read(4)
    if magic not in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    ):
        raise ValueError("Only uncompressed PCAP/PCAPNG imports are supported.")
    suffix = ".pcapng" if magic == b"\x0a\x0d\x0d\x0a" else ".pcap"
    target = root / ("import_" + uuid.uuid4().hex + suffix)
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as src, target.open("xb") as dst:
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > store.config.max_capture_bytes:
                    raise ValueError("Import grew beyond the capture limit.")
                digest.update(chunk)
                dst.write(chunk)
        target.chmod(0o600)
        # Detect a source changed during copying; the copy remains independent afterwards.
        if store.digest(source) != digest.hexdigest():
            raise ValueError(
                "Source changed during import; retry after the upload finishes."
            )
        result = store.register(str(target))
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    result["source_name"] = source.name
    result["note"] = (
        "Copied and registered locally. No remote upload or automatic access to chat attachments."
    )
    return result


def import_events(store, path, format):
    if format not in ("suricata", "zeek", "network"):
        raise ValueError("format must be suricata, zeek or network")
    source = input_path(store.config, path)
    with source.open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Event file exceeds 16 MiB")
    events = []
    total = 0
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > 65536:
            raise ValueError(f"Line {number} exceeds 64 KiB")
        try:
            row = json.loads(
                line,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("Nonfinite JSON number")
                ),
            )
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f"Invalid JSON on line {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"Line {number} must be a JSON object")
        if format == "suricata":
            alert = row.get("alert") if isinstance(row.get("alert"), dict) else {}
            event = {
                "time": row.get("timestamp"),
                "source": row.get("src_ip"),
                "destination": row.get("dest_ip"),
                "kind": row.get("event_type"),
                "description": alert.get("signature") or row.get("app_proto"),
                "external_severity": alert.get("severity"),
                "external_signature_id": alert.get("signature_id"),
            }
        elif format == "zeek":
            event = {
                "time": row.get("ts"),
                "source": row.get("id.orig_h"),
                "destination": row.get("id.resp_h"),
                "kind": row.get("_path") or row.get("service") or "zeek_event",
                "description": row.get("note")
                or row.get("msg")
                or row.get("conn_state")
                or row.get("query"),
            }
        else:
            event = {
                key: row.get(key)
                for key in (
                    "time",
                    "source",
                    "destination",
                    "kind",
                    "description",
                    "device",
                    "decision",
                    "interface",
                    "route",
                    "mtu",
                    "counter",
                )
            }
        # Preserve only bounded primitive values; raw logs remain separately hashed source evidence.
        event = {
            k: (v[:1024] if isinstance(v, str) else v)
            for k, v in event.items()
            if v is None or isinstance(v, (str, int, float, bool))
        }
        if any(
            isinstance(value, float) and not math.isfinite(value)
            for value in event.values()
        ):
            raise ValueError(f"Nonfinite value on line {number}")
        event["source_line"] = number
        total += 1
        if len(events) < 2000:
            events.append(event)
    folder = store.config.state_root.resolve() / "event-evidence"
    folder.mkdir(exist_ok=True)
    event_id = "evt_" + uuid.uuid4().hex
    record = {
        "event_id": event_id,
        "format": format,
        "source_name": source.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "events": events,
        "total_events": total,
        "truncated": total > len(events),
        "content_is_untrusted": True,
        "note": "Imported external assertions, not independently verified packet findings. JSON-lines only; Zeek TSV is not supported.",
    }
    target = folder / (event_id + ".json")
    with target.open("x", encoding="utf-8") as output:
        json.dump(record, output, indent=2, allow_nan=False)
    target.chmod(0o600)
    store.audit("import_events", event_id)
    return {k: v for k, v in record.items() if k != "events"}


def get_events(store, event_id, offset=0, limit=100):
    import re

    if (
        not re.fullmatch(r"evt_[a-f0-9]{32}", event_id)
        or not 0 <= offset <= 2000
        or not 1 <= limit <= 200
    ):
        raise ValueError("Invalid evidence ID or page")
    path = store.config.state_root.resolve() / "event-evidence" / (event_id + ".json")
    if not path.is_file():
        raise ValueError("Unknown event_id")
    data = json.loads(path.read_text())
    stored = len(data["events"])
    data["events"] = data["events"][offset : offset + limit]
    data["next_offset"] = offset + limit if offset + limit < stored else None
    return data


def correlate(rows, events, max_seconds=5):
    from . import analysis as a
    from datetime import datetime
    from bisect import bisect_left, bisect_right
    import math

    if not 0 <= max_seconds <= 300:
        raise ValueError("Tolerance must be 0–300 seconds")
    by_pair = {}
    for row in rows:
        by_pair.setdefault((a.src(row), a.dst(row)), []).append(row)
    for key, values in by_pair.items():
        values.sort(key=a.stamp)
        by_pair[key] = ([a.stamp(r) for r in values], values)
    matches = []
    for event in events:
        value = event.get("time")
        try:
            if (
                isinstance(value, (float, int))
                or str(value).replace(".", "", 1).isdigit()
            ):
                epoch = float(value)
            else:
                date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if date.tzinfo is None:
                    continue
                epoch = date.timestamp()
            if not math.isfinite(epoch):
                continue
        except (ValueError, TypeError, OverflowError):
            continue
        source, destination = event.get("source"), event.get("destination")
        near = []
        matched = 0
        for pair in {(source, destination), (destination, source)}:
            times, candidates = by_pair.get(pair, ([], []))
            left = bisect_left(times, epoch - max_seconds)
            right = bisect_right(times, epoch + max_seconds)
            matched += right - left
            near.extend(candidates[left : min(right, left + 20)])
        if near and len(matches) < 100:
            matches.append(
                {
                    "source_line": event["source_line"],
                    "event_time": value,
                    "description": event.get("description"),
                    "packet_evidence": a.evidence(near),
                    "matched_packets": matched,
                }
            )
    return {
        "matches": matches,
        "limit_reached": len(matches) == 100,
        "note": "Time/address proximity is a correlation lead, not proof of causality or endpoint identity; verify clock skew, NAT and DHCP reuse.",
    }
