"""Deterministic, explainable triage. Findings are hypotheses, not verdicts."""

from __future__ import annotations

import ipaddress
import statistics
from collections import Counter, defaultdict


def num(value, default=0):
    try:
        import math

        result = int(value, 0) if str(value).lower().startswith("0x") else float(value)
        return result if math.isfinite(result) else default
    except (ValueError, TypeError):
        return default


def yes(row, field):
    return row.get(field, "") not in ("", "0", "False", "false")


def src(row):
    return row.get("ip.src") or row.get("ipv6.src") or row.get("eth.src", "unknown")


def dst(row):
    return row.get("ip.dst") or row.get("ipv6.dst") or row.get("eth.dst", "unknown")


def dport(row):
    return row.get("tcp.dstport") or row.get("udp.dstport", "")


def stamp(row):
    return num(row.get("frame.time_epoch"))


def evidence(rows):
    return [
        {
            "frame": int(num(r.get("frame.number"))),
            "time_epoch": stamp(r),
            "source": src(r),
            "destination": dst(r),
        }
        for r in rows[:20]
    ]


def finding(
    code,
    title,
    rows,
    explanation,
    alternatives,
    next_steps,
    severity="medium",
    confidence="low",
):
    return {
        "rule_id": code,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "observed_packets": len(rows),
        "evidence": evidence(rows),
        "evidence_truncated": len(rows) > 20,
        "interpretation": explanation,
        "alternative_explanations": alternatives,
        "next_steps": next_steps,
    }


def summary(rows):
    protocols = Counter()
    talkers = Counter()
    ports = Counter()
    for row in rows:
        protocols.update(set(row.get("frame.protocols", "").split(":")) - {""})
        talkers[src(row)] += int(num(row.get("frame.len")))
        if dport(row):
            ports[("tcp" if row.get("tcp.dstport") else "udp") + "/" + dport(row)] += 1
    times = [stamp(row) for row in rows]
    duration = max(times) - min(times) if times else 0
    total = sum(int(num(row.get("frame.len"))) for row in rows)
    return {
        "packets": len(rows),
        "wire_bytes": total,
        "duration_seconds": round(duration, 6),
        "first_epoch": min(times) if times else None,
        "last_epoch": max(times) if times else None,
        "average_bits_per_second": round(total * 8 / duration, 2) if duration else None,
        "protocol_packet_counts": dict(protocols.most_common(30)),
        "top_source_wire_bytes": dict(talkers.most_common(20)),
        "top_destination_ports": dict(ports.most_common(20)),
        "truncated_frames": sum(
            num(r.get("frame.cap_len")) < num(r.get("frame.len")) for r in rows
        ),
        "note": "Wire bytes include headers and retransmissions; they are not unique application bytes.",
    }


def conversations(rows):
    groups = defaultdict(list)
    for row in rows:
        if row.get("tcp.stream") != "" and row.get("tcp.stream") is not None:
            groups[row["tcp.stream"]].append(row)
    result = []
    for stream, packets in groups.items():
        syn = [
            r
            for r in packets
            if yes(r, "tcp.flags.syn") and not yes(r, "tcp.flags.ack")
        ]
        synack = [
            r for r in packets if yes(r, "tcp.flags.syn") and yes(r, "tcp.flags.ack")
        ]
        resets = [r for r in packets if yes(r, "tcp.flags.reset")]
        state = "partial/midstream"
        if syn and not synack:
            state = (
                "SYN and reset observed" if resets else "SYN without observed SYN-ACK"
            )
        elif syn and synack:
            state = "SYN and SYN-ACK observed; application success unverified"
        result.append(
            {
                "stream_id": int(stream),
                "source": src(packets[0]),
                "destination": dst(packets[0]),
                "destination_port": dport(packets[0]),
                "packets": len(packets),
                "wire_bytes": sum(int(num(r.get("frame.len"))) for r in packets),
                "state": state,
                "reset_packets": len(resets),
                "retransmission_packets": sum(
                    yes(r, "tcp.analysis.retransmission")
                    or yes(r, "tcp.analysis.fast_retransmission")
                    for r in packets
                ),
                "first_frame": int(num(packets[0].get("frame.number"))),
            }
        )
    return sorted(result, key=lambda r: r["wire_bytes"], reverse=True)


def connectivity(rows):
    findings = []
    dns_errors = [
        r
        for r in rows
        if yes(r, "dns.flags.response") and num(r.get("dns.flags.rcode")) != 0
    ]
    if dns_errors:
        findings.append(
            finding(
                "DNS_ERROR",
                "DNS error responses",
                dns_errors,
                "The resolver returned a non-zero response code. NXDOMAIN, SERVFAIL and REFUSED have different causes.",
                ["Expected nonexistent names", "Split DNS", "Resolver policy"],
                [
                    "Inspect response codes and query names with inspect_protocol(dns).",
                    "Compare client resolver configuration and an approved working client.",
                ],
                confidence="high",
            )
        )
    streams = defaultdict(list)
    for row in rows:
        if row.get("tcp.stream"):
            streams[row["tcp.stream"]].append(row)
    for stream, packets in streams.items():
        syns = [
            r
            for r in packets
            if yes(r, "tcp.flags.syn") and not yes(r, "tcp.flags.ack")
        ]
        synacks = [
            r for r in packets if yes(r, "tcp.flags.syn") and yes(r, "tcp.flags.ack")
        ]
        resets = [r for r in packets if yes(r, "tcp.flags.reset")]
        if syns and not synacks:
            reset = bool(resets)
            findings.append(
                finding(
                    "TCP_REFUSED" if reset else "TCP_NO_REPLY",
                    f"Stream {stream}: connection establishment not observed",
                    syns + resets,
                    "A reset followed connection attempts; an endpoint or intermediary may reject the connection."
                    if reset
                    else "SYN packets have no visible SYN-ACK in this capture. A firewall drop, path issue or unavailable host is possible.",
                    [
                        "Asymmetric capture",
                        "Capture ended too early",
                        "Packet loss at the capture point",
                    ],
                    [
                        "Check capture placement and timing.",
                        "Check route, firewall logs and destination listener; compare a working flow.",
                    ],
                )
            )
    for code, title, selected, description, next_steps in [
        (
            "TCP_RETRANSMISSION",
            "TCP retransmissions observed",
            [
                r
                for r in rows
                if yes(r, "tcp.analysis.retransmission")
                or yes(r, "tcp.analysis.fast_retransmission")
            ],
            "TShark classified retransmissions; this alone does not locate packet loss.",
            ["Compare captures at both ends and interface drop/error counters."],
        ),
        (
            "TCP_ZERO_WINDOW",
            "Receiver advertised a zero window",
            [r for r in rows if yes(r, "tcp.analysis.zero_window")],
            "The receiver may not be draining its TCP receive buffer.",
            ["Inspect receiving application load and host resources."],
        ),
        (
            "ICMP_ERROR",
            "ICMP path errors",
            [
                r
                for r in rows
                if num(r.get("icmp.type"), -1) in (3, 11, 12)
                or num(r.get("icmpv6.type"), -1) in (1, 2, 3, 4)
            ],
            "Unreachable, time exceeded, packet-too-big or parameter errors may explain path/MTU failures.",
            ["Inspect ICMP type/code and the quoted original packet in Wireshark."],
        ),
        (
            "TLS_ALERT",
            "TLS alerts observed",
            [r for r in rows if r.get("tls.alert_message.desc")],
            "An alert is visible; its code and direction matter, and close_notify can be normal.",
            ["Inspect alert code, SNI and endpoint TLS/certificate logs."],
        ),
        (
            "HTTP_ERROR",
            "HTTP error responses",
            [r for r in rows if num(r.get("http.response.code")) >= 400],
            "HTTP returned an application/client error; TCP reachability alone does not imply service health.",
            ["Check response codes and reverse-proxy/application logs."],
        ),
    ]:
        if selected:
            findings.append(
                finding(
                    code,
                    title,
                    selected,
                    description,
                    [
                        "Benign application behavior",
                        "Capture artifacts or incomplete visibility",
                    ],
                    next_steps,
                )
            )
    return findings


def anomalies(rows):
    findings = []
    # Sliding 60-second window, deduplicating destination ports; retransmits do not create extra ports.
    by_source = defaultdict(list)
    for row in rows:
        if yes(row, "tcp.flags.syn") and not yes(row, "tcp.flags.ack"):
            by_source[src(row)].append(row)
    for source, packets in by_source.items():
        ordered = sorted(packets, key=stamp)
        left = 0
        pairs = Counter()
        for right, row in enumerate(ordered):
            pairs[(dst(row), dport(row))] += 1
            while stamp(row) - stamp(ordered[left]) > 60:
                old = ordered[left]
                key = (dst(old), dport(old))
                pairs[key] -= 1
                if not pairs[key]:
                    del pairs[key]
                left += 1
            if len(pairs) >= 20:
                findings.append(
                    finding(
                        "SYN_FANOUT",
                        f"Connection fan-out from {source}",
                        ordered[left : right + 1],
                        f"At least {len(pairs)} distinct destination address/port pairs received SYNs within 60 seconds.",
                        [
                            "Approved vulnerability scanner",
                            "Service discovery",
                            "Busy legitimate client",
                        ],
                        [
                            "Check asset role and scanner schedules.",
                            "Correlate originating processes and firewall logs.",
                        ],
                    )
                )
                break
    # First SYN per stream: retransmissions are not counted as beacon events.
    periodic = defaultdict(list)
    seen = set()
    for row in sorted(rows, key=stamp):
        stream = row.get("tcp.stream")
        if (
            stream
            and stream not in seen
            and yes(row, "tcp.flags.syn")
            and not yes(row, "tcp.flags.ack")
        ):
            periodic[(src(row), dst(row), dport(row))].append(row)
            seen.add(stream)
    for key, packets in periodic.items():
        if len(packets) >= 8:
            gaps = [stamp(b) - stamp(a) for a, b in zip(packets, packets[1:])]
            mean = statistics.mean(gaps)
            if mean >= 1 and statistics.pstdev(gaps) / mean <= 0.15:
                findings.append(
                    finding(
                        "PERIODIC_CONNECTIONS",
                        f"Regular connections: {key[0]} → {key[1]}:{key[2]}",
                        packets,
                        f"At least 8 separate TCP streams; average interval {mean:.2f}s, interval CV ≤ 0.15.",
                        [
                            "Monitoring/health checks",
                            "Software updates",
                            "Scheduled polling",
                        ],
                        [
                            "Inspect destination ownership, TLS SNI and endpoint process ancestry.",
                            "Compare with the asset baseline before classifying C2.",
                        ],
                    )
                )
    long_dns = [
        r
        for r in rows
        if not yes(r, "dns.flags.response")
        and any(len(label) >= 45 for label in r.get("dns.qry.name", "").split("."))
    ]
    if len(long_dns) >= 5:
        findings.append(
            finding(
                "LONG_DNS_LABELS",
                "Repeated long DNS labels",
                long_dns,
                "Five or more queries contain labels at least 45 characters long; this is a triage signal, not a tunneling verdict.",
                [
                    "CDN/tracking names",
                    "Security products",
                    "Legitimate encoded identifiers",
                ],
                ["Review parent domains, response types, volume and source process."],
            )
        )
    arp = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if (
            row.get("arp.src.proto_ipv4")
            and row.get("arp.src.hw_mac")
            and row["arp.src.proto_ipv4"] != "0.0.0.0"
        ):
            arp[row["arp.src.proto_ipv4"]][row["arp.src.hw_mac"]].append(row)
    for address, macs in arp.items():
        if len(macs) > 1:
            packets = [row for group in macs.values() for row in group]
            findings.append(
                finding(
                    "ARP_MAPPING_CHANGE",
                    f"Multiple MAC addresses claim {address}",
                    packets,
                    f"Observed {len(macs)} source MAC mappings for the same IPv4 address.",
                    [
                        "HA/failover",
                        "DHCP reassignment",
                        "Duplicate IP",
                        "ARP spoofing",
                    ],
                    [
                        "Compare timestamps, switch MAC tables and approved gateway MACs."
                    ],
                )
            )
    return findings


def ransomware(rows):
    findings = []
    writers = defaultdict(list)
    admin = defaultdict(list)
    creates = {}
    filenames = {}
    for original in sorted(rows, key=stamp):
        row = dict(original)
        stream = row.get("tcp.stream", "")
        message = row.get("smb2.msg_id", "")
        if num(row.get("smb2.cmd"), -1) == 5:
            if (
                not yes(row, "smb2.flags.response")
                and message
                and row.get("smb2.filename")
            ):
                creates[(stream, message)] = row["smb2.filename"]
            elif yes(row, "smb2.flags.response") and row.get("smb2.fid"):
                name = creates.get((stream, message))
                if name:
                    filenames[(stream, row["smb2.fid"])] = name
        if not row.get("smb2.filename") and row.get("smb2.fid"):
            row["smb2.filename"] = filenames.get((stream, row["smb2.fid"]), "")
        if num(row.get("smb2.cmd"), -1) in (9, 17) and not yes(
            row, "smb2.flags.response"
        ):
            writers[src(row)].append(row)
        if (
            dport(row) in ("445", "3389", "5985", "5986", "135")
            and yes(row, "tcp.flags.syn")
            and not yes(row, "tcp.flags.ack")
        ):
            admin[src(row)].append(row)
    for source, packets in writers.items():
        if len(packets) >= 30:
            findings.append(
                finding(
                    "SMB_FILE_ACTIVITY",
                    f"Repeated SMB WRITE/SET_INFO requests from {source}",
                    packets,
                    "At least 30 visible SMB2 WRITE or SET_INFO requests in the analysed capture. SET_INFO is not necessarily rename/delete. This rule has no historical baseline.",
                    [
                        "File copy",
                        "Backup",
                        "Software deployment",
                        "Ransomware-related file modification",
                    ],
                    [
                        "Inspect SMB operation details and file-server auditing.",
                        "Ask VeloPilot for process trees, file-change bursts, ransom notes and EDR alerts.",
                    ],
                    severity="medium",
                )
            )
        ordered = sorted(packets, key=stamp)
        left = 0
        names = Counter()
        commands = Counter()
        for right, row in enumerate(ordered):
            if row.get("smb2.filename"):
                names[row["smb2.filename"]] += 1
            commands[int(num(row.get("smb2.cmd"), -1))] += 1
            while stamp(row) - stamp(ordered[left]) > 60:
                old = ordered[left]
                if old.get("smb2.filename"):
                    name = old["smb2.filename"]
                    names[name] -= 1
                    if not names[name]:
                        del names[name]
                command = int(num(old.get("smb2.cmd"), -1))
                commands[command] -= 1
                if not commands[command]:
                    del commands[command]
                left += 1
            if len(names) >= 10 and {9, 17}.issubset(commands):
                burst = ordered[left : right + 1]
                result = finding(
                    "SMB_MODIFICATION_BURST",
                    f"SMB write/metadata burst across files from {source}",
                    burst,
                    f"At least {len(names)} visible filenames with WRITE and SET_INFO requests within 60 seconds. This increases investigation priority but does not establish encryption or ransomware.",
                    [
                        "Backup/synchronisation",
                        "Bulk file management",
                        "Software deployment",
                    ],
                    [
                        "Check exact SET_INFO classes, file-server audit trails and source process ancestry.",
                        "Correlate ransom notes, file-extension/content changes and EDR alerts before declaring ransomware.",
                    ],
                    confidence="medium",
                )
                result["filenames_sample"] = sorted(names)[:20]
                findings.append(result)
                break
    for source, packets in admin.items():
        if len({dst(r) for r in packets}) >= 5:
            findings.append(
                finding(
                    "ADMIN_FANOUT",
                    f"Administrative-service fan-out from {source}",
                    packets,
                    "Connections target administrative services on at least five hosts across this capture.",
                    [
                        "IT administration",
                        "Inventory or monitoring",
                        "Lateral movement",
                    ],
                    [
                        "Validate the source role and maintenance window.",
                        "Correlate authentication events and remote process/service creation in VeloPilot.",
                    ],
                )
            )
    return {
        "assessment": "Network indicators only; ransomware cannot be confirmed or ruled out from these checks.",
        "findings": findings,
        "coverage_gaps": [
            "Encrypted SMB hides file operations.",
            "Local-only file encryption may leave no relevant network signal.",
            "No malware signatures, file content classification or endpoint telemetry are used.",
        ],
        "velopilot_handoff": {
            "status": "Recommended handoff; no VeloPilot connection is implemented.",
            "hosts": sorted(set(writers) | set(admin))[:50],
            "collect": [
                "EDR alerts",
                "process trees",
                "file modification timeline",
                "SMB authentication",
                "service/task creation",
                "ransom notes",
            ],
        },
    }


def hunt(rows, indicators):
    if not 1 <= len(indicators) <= 100:
        raise ValueError("Provide 1–100 IP addresses or domain names.")
    parsed = []
    for item in indicators:
        item = item.strip().lower().rstrip(".")
        if not item or len(item) > 253 or any(c.isspace() for c in item):
            raise ValueError("Invalid indicator.")
        try:
            item = str(ipaddress.ip_address(item))
            kind = "ip"
        except ValueError:
            kind = "domain"
        parsed.append((item, kind))
    matches = []
    total = 0
    for row in rows:
        names = [
            row.get(field, "").lower().rstrip(".")
            for field in (
                "dns.qry.name",
                "http.host",
                "tls.handshake.extensions_server_name",
            )
        ]
        for item, kind in parsed:
            hit = (
                item in (src(row), dst(row))
                if kind == "ip"
                else any(name == item or name.endswith("." + item) for name in names)
            )
            if hit:
                total += 1
                if len(matches) < 200:
                    matches.append({"indicator": item, "evidence": evidence([row])[0]})
    return {
        "matches": matches,
        "total_matches": total,
        "truncated": total > len(matches),
        "note": "Domain matches include subdomains with label boundaries; no reputation lookups are performed.",
    }
