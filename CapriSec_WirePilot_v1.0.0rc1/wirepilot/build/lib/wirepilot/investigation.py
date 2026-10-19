"""Evidence-oriented protocol analysis; static rules are not malware verdicts."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import analysis as a


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def authentication_events(rows):
    requests = {}
    ftp_users = {}
    events = []
    for row in sorted(rows, key=a.stamp):
        if a.yes(row, "tcp.analysis.retransmission") or a.yes(
            row, "tcp.analysis.fast_retransmission"
        ):
            continue
        stream = row.get("tcp.stream", "")
        if row.get("ftp.request.command", "").upper() == "USER":
            ftp_users[stream] = row.get("ftp.request.arg", "")[:256]
        if row.get("http.request.method"):
            requests[("http", row.get("frame.number"))] = row
        if row.get("smb2.msg_id") and not a.yes(row, "smb2.flags.response"):
            requests[("smb", stream, row["smb2.msg_id"])] = row
        protocol = outcome = account = ""
        source, destination = a.dst(row), a.src(row)
        detail = ""
        ftp = a.num(row.get("ftp.response.code"))
        if ftp in (530, 230):
            protocol, outcome = "ftp", "failure" if ftp == 530 else "success"
            account = ftp_users.get(stream, "")
            detail = f"FTP response {int(ftp)}"
        if a.num(row.get("http.response.code")) == 401:
            protocol, outcome = "http", "challenge"
            req = requests.get(("http", row.get("http.request_in")))
            if req:
                source, destination = a.src(req), a.dst(req)
            detail = "HTTP 401: authentication challenge/rejection; not proof of a bad password"
        if a.num(row.get("smb2.cmd"), -1) == 1 and a.yes(row, "smb2.flags.response"):
            status = int(a.num(row.get("smb2.nt_status"), -1))
            if status in (
                0,
                0xC000006D,
                0xC000006A,
                0xC0000064,
                0xC0000234,
                0xC0000071,
            ):
                protocol, outcome = "smb", "success" if status == 0 else "failure"
                req = requests.get(("smb", stream, row.get("smb2.msg_id")))
                if req:
                    source, destination = a.src(req), a.dst(req)
                    account = req.get("ntlmssp.auth.username", "")
                detail = f"SMB2 SESSION_SETUP status 0x{status:08x}; successful setup does not prove malicious account use"
        error = int(a.num(row.get("kerberos.error_code"), -1))
        if error in (6, 18, 24):
            protocol, outcome, account = (
                "kerberos",
                "failure",
                row.get("kerberos.CNameString", ""),
            )
            detail = f"Kerberos error {error}; error 25 (PREAUTH_REQUIRED) is intentionally excluded"
        if protocol:
            events.append(
                {
                    "protocol": protocol,
                    "outcome": outcome,
                    "account": account or None,
                    "source": source,
                    "destination": destination,
                    "time_epoch": a.stamp(row),
                    "frame": int(a.num(row.get("frame.number"))),
                    "tcp_stream": stream or None,
                    "detail": detail,
                }
            )
    return events


def analyse_authentication(rows, threshold=5, window=60):
    if not 3 <= threshold <= 100 or not 10 <= window <= 3600:
        raise ValueError("Threshold must be 3–100; window 10–3600 seconds.")
    events = authentication_events(rows)
    grouped = defaultdict(list)
    for event in events:
        grouped[(event["protocol"], event["source"], event["destination"])].append(
            event
        )
    findings = []
    for (protocol, source, destination), group in grouped.items():
        failures = [e for e in group if e["outcome"] in ("failure", "challenge")]
        left = 0
        for right, event in enumerate(failures):
            while event["time_epoch"] - failures[left]["time_epoch"] > window:
                left += 1
            burst = failures[left : right + 1]
            if len(burst) < threshold:
                continue
            frames = {e["frame"] for e in burst}
            packets = [r for r in rows if int(a.num(r.get("frame.number"))) in frames]
            challenge = protocol == "http"
            result = a.finding(
                "HTTP_AUTH_CHALLENGES" if challenge else "REPEATED_AUTH_FAILURES",
                f"Repeated {protocol.upper()} {'challenges' if challenge else 'authentication failures'}: {source} → {destination}",
                packets,
                f"{len(burst)} visible outcomes within {window}s; candidate for brute-force investigation, not proof of intent.",
                ["Stale credentials", "Misconfigured service", "Legitimate retry loop"]
                + (["Normal HTTP authentication challenges"] if challenge else []),
                [
                    "Review account/source role and server authentication logs.",
                    "Correlate subsequent success with account identity and endpoint activity.",
                ],
                confidence="low" if challenge else "medium",
            )
            accounts = sorted({e["account"] for e in burst if e["account"]})
            successes = [
                e
                for e in group
                if e["outcome"] == "success"
                and 0 <= e["time_epoch"] - burst[-1]["time_epoch"] <= window
            ]
            result.update(
                accounts=accounts[:50],
                subsequent_successes=successes[:20],
                success_account_correlation="Same source/destination/protocol only; verify accounts/session identity before attributing a compromise.",
            )
            findings.append(result)
            break
    return {
        "findings": findings[:100],
        "total_findings": len(findings),
        "findings_truncated": len(findings) > 100,
        "events": events[:200],
        "total_events": len(events),
        "events_truncated": len(events) > 200,
        "threshold": threshold,
        "window_seconds": window,
        "limitations": [
            "SSH/RDP/HTTPS authentication outcomes generally require endpoint/server logs or decrypted traffic.",
            "HTTP 401 may be a normal challenge; HTTP 200 is not counted as a successful login.",
            "TShark-marked TCP retransmissions are ignored; unflagged application replays may still inflate counts.",
            "No request context/account is invented when the request lies outside the selected range.",
        ],
    }


def engineering(rows):
    rtts = [a.num(r.get("tcp.analysis.ack_rtt"), -1) for r in rows]
    rtts = sorted(x for x in rtts if x >= 0)
    dns_times = sorted(a.num(r["dns.time"]) for r in rows if r.get("dns.time"))
    findings = []
    for code, title, selected, explanation, next_steps in [
        (
            "PATH_MTU",
            "Packet-too-big / fragmentation-needed evidence",
            [
                r
                for r in rows
                if a.num(r.get("icmpv6.type"), -1) == 2
                or (
                    a.num(r.get("icmp.type"), -1) == 3
                    and a.num(r.get("icmp.code"), -1) == 4
                )
            ],
            "A path device reported a packet-too-big/fragmentation-needed condition; inspect the advertised MTU and originating flow.",
            [
                "Compare interface and VPN MTUs; inspect ICMP delivery and PMTUD behavior."
            ],
        ),
        (
            "DHCP_NAK",
            "DHCP negative acknowledgement",
            [r for r in rows if a.num(r.get("dhcp.option.dhcp")) == 6],
            "A DHCP NAK is visible; it can explain lease renewal or address assignment disruption.",
            ["Check DHCP scope, relay/VLAN placement, leases and server logs."],
        ),
        (
            "TCP_CAPTURE_GAP",
            "TCP segment gaps observed",
            [r for r in rows if a.yes(r, "tcp.analysis.lost_segment")],
            "A sequence gap can indicate missing capture data or real network loss; one vantage point cannot locate the cause.",
            [
                "Compare endpoint captures and interface drop counters before assigning a network fault."
            ],
        ),
        (
            "SLOW_DNS",
            "DNS responses taking at least one second",
            [r for r in rows if a.num(r.get("dns.time")) >= 1],
            "Observed DNS response time is at least 1s; this fixed threshold is not a service-specific SLA.",
            [
                "Compare resolver health, upstream timing, retransmits and a working client's capture."
            ],
        ),
    ]:
        if selected:
            findings.append(
                a.finding(
                    code,
                    title,
                    selected,
                    explanation,
                    [
                        "Expected operating conditions",
                        "Incomplete capture or configuration context",
                    ],
                    next_steps,
                )
            )

    def metrics(values):
        return {
            "samples": len(values),
            "median_ms": round(statistics.median(values) * 1000, 3) if values else None,
            "p95_ms": round(values[max(0, int(len(values) * 0.95) - 1)] * 1000, 3)
            if values
            else None,
            "max_ms": round(max(values) * 1000, 3) if values else None,
        }

    return {
        "findings": findings,
        "tcp_ack_rtt": metrics(rtts),
        "dns_response_timing": metrics(dns_times),
        "vlans_observed": sorted({r["vlan.id"] for r in rows if r.get("vlan.id")})[
            :100
        ],
        "dhcp_message_counts": dict(
            Counter(r["dhcp.option.dhcp"] for r in rows if r.get("dhcp.option.dhcp"))
        ),
        "limitations": [
            "ACK RTT reflects this capture point and can include delayed ACKs; it is not pure link latency.",
            "No vendor device APIs, VPN configuration parser, BGP/OSPF state or Wi-Fi RF diagnosis is implemented.",
        ],
    }


def timeline(rows, limit=200):
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1–500")
    events = []
    auth = {e["frame"]: e for e in authentication_events(rows)}
    for row in sorted(rows, key=a.stamp):
        frame = int(a.num(row.get("frame.number")))
        labels = []
        for field, label in (
            ("dns.qry.name", "DNS name"),
            ("http.request.method", "HTTP method"),
            ("http.response.code", "HTTP response"),
            ("tls.handshake.extensions_server_name", "TLS SNI"),
            ("tls.alert_message.desc", "TLS alert"),
            ("smb2.cmd", "SMB2 operation"),
        ):
            if row.get(field):
                labels.append(label + ": " + row[field][:256])
        if a.yes(row, "tcp.flags.reset"):
            labels.append("TCP reset")
        if frame in auth:
            labels.append(auth[frame]["detail"])
        if labels:
            events.append(
                {
                    **a.evidence([row])[0],
                    "time_utc": iso(a.stamp(row)),
                    "observations": labels,
                }
            )
    return {
        "events": events[:limit],
        "total_events": len(events),
        "truncated": len(events) > limit,
        "note": "Times come from the capture; verify timezone/clock accuracy and NAT/DHCP identity externally.",
    }


def compare(rows, baseline_rows):
    now, old = a.summary(rows), a.summary(baseline_rows)

    def values(rs):
        hosts = {a.src(r) for r in rs} | {a.dst(r) for r in rs}
        names = {
            r.get(field, "").lower().rstrip(".")
            for r in rs
            for field in (
                "dns.qry.name",
                "http.host",
                "tls.handshake.extensions_server_name",
            )
        } - {""}
        return hosts, names

    nh, nn = values(rows)
    oh, on = values(baseline_rows)
    return {
        "current_summary": now,
        "baseline_summary": old,
        "new_hosts": sorted(nh - oh)[:200],
        "new_domains": sorted(nn - on)[:200],
        "new_hosts_total": len(nh - oh),
        "new_domains_total": len(nn - on),
        "bitrate_ratio": now["average_bits_per_second"] / old["average_bits_per_second"]
        if old["average_bits_per_second"] and now["average_bits_per_second"] is not None
        else None,
        "interpretation": "Descriptive comparison only. New does not mean malicious; match vantage point, asset role and collection duration.",
    }


def build_report(rows, coverage, mode="general"):
    if mode not in ("general", "security", "engineering", "ctf"):
        raise ValueError("Invalid investigation mode.")
    connectivity = a.connectivity(rows)
    anomalies = a.anomalies(rows)
    auth = analyse_authentication(rows)
    engineer = engineering(rows)
    ransom = a.ransomware(rows)
    all_findings = (
        connectivity
        + anomalies
        + auth["findings"]
        + engineer["findings"]
        + ransom["findings"]
    )
    # Deduplicate rules/evidence where possible; keep deterministic ordering for clients/tests.
    findings = []
    seen = set()
    for finding in all_findings:
        key = (finding["rule_id"], tuple(e["frame"] for e in finding["evidence"]))
        if key not in seen:
            seen.add(key)
            findings.append(finding)
    priority = {
        "REPEATED_AUTH_FAILURES": 0,
        "SMB_MODIFICATION_BURST": 0,
        "ADMIN_FANOUT": 1,
        "SYN_FANOUT": 2,
        "PERIODIC_CONNECTIONS": 2,
        "ARP_MAPPING_CHANGE": 2,
        "PATH_MTU": 3,
    }
    findings.sort(
        key=lambda finding: (
            priority.get(finding["rule_id"], 5),
            finding["evidence"][0]["frame"] if finding["evidence"] else 0,
        )
    )
    counts = dict(Counter(f["rule_id"] for f in findings))
    required = {
        "ftp_authentication": {"ftp.response.code"},
        "smb_authentication": {"smb2.cmd", "smb2.flags.response", "smb2.nt_status"},
        "kerberos_authentication": {"kerberos.error_code"},
        "http_challenges": {"http.response.code"},
        "path_mtu": {"icmp.type", "icmp.code", "icmpv6.type"},
        "dns_timing": {"dns.time"},
    }
    unsupported = set(coverage.get("unsupported_fields", []))
    checks = {
        name: {
            "status": "reduced_visibility"
            if fields & unsupported
            else "fields_available",
            "missing_fields": sorted(fields & unsupported),
        }
        for name, fields in required.items()
    }
    return {
        "coverage": coverage,
        "mode": mode,
        "summary": a.summary(rows),
        "assessment": f"{len(findings)} triage findings in the selected capture range; analyst correlation is required."
        if findings
        else "No configured rule matched the selected evidence. This does not establish absence of attacks or faults.",
        "findings": findings[:100],
        "total_findings": len(findings),
        "findings_truncated": len(findings) > 100,
        "rule_counts": counts,
        "check_availability": checks,
        "authentication": auth,
        "engineering": engineer,
        "ransomware": {**ransom, "findings": ransom["findings"][:100]},
        "timeline": timeline(rows),
        "recommended_tools": [
            "search_capture_text",
            "inspect_credentials",
            "export_http_objects",
            "decode_text",
            "packet_details",
        ]
        if mode == "ctf"
        else [
            "inspect_protocol",
            "packet_details",
            "query_packet_range",
            "get_timeline",
        ],
        "confidence_policy": "Qualitative labels describe evidence strength, not calibrated probabilities or confirmed attack attribution.",
        "content_is_untrusted": True,
    }


def markdown_report(report):
    import html
    import re

    def safe(value):
        text = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
        return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text)

    lines = [
        "# WirePilot investigation",
        "",
        safe(report["assessment"]),
        "",
        "## Evidence coverage",
        "",
        f"- SHA-256: `{report['coverage']['sha256']}`",
        f"- Scope: {safe(report['coverage']['scope'])}",
        f"- Packets returned: {report['summary']['packets']}",
        f"- Whole capture analysed: {report['coverage'].get('whole_capture', False)}",
        "",
        "## Findings",
        "",
    ]
    for finding in report["findings"]:
        frames = ", ".join(str(e["frame"]) for e in finding["evidence"])
        lines += [
            f"### {safe(finding['title'])}",
            "",
            f"**{safe(finding['rule_id'])} · {safe(finding['severity'])} · confidence {safe(finding['confidence'])}**",
            "",
            safe(finding["interpretation"]),
            "",
            f"Evidence frames: {frames or 'none'}.",
            "",
            "Alternatives: " + safe("; ".join(finding["alternative_explanations"])),
            "",
            "Next checks: " + safe("; ".join(finding["next_steps"])),
            "",
        ]
    if not report["findings"]:
        lines += ["No configured rules matched. Visibility gaps still apply.", ""]
    lines += ["## Timeline", "", "| UTC | Frame | Observation |", "| --- | --- | --- |"]
    for event in report["timeline"]["events"]:
        lines.append(
            f"| {safe(event['time_utc'])} | {event['frame']} | {safe('; '.join(event['observations']))} |"
        )
    if report.get("external_evidence"):
        external = report["external_evidence"]
        lines += [
            "",
            "## External evidence correlation",
            "",
            f"Source: {safe(external['source_name'])}; SHA-256: `{external['sha256']}`.",
            "",
            safe(external["note"]),
            "",
        ]
        for match in external["matches"]:
            frames = ", ".join(str(e["frame"]) for e in match["packet_evidence"])
            lines += [
                f"- Source line {match['source_line']}: {safe(match.get('description'))}; nearby frames {frames}."
            ]
    lines += ["", "## Limitations", ""] + [
        "- " + safe(s) for s in report["coverage"]["limitations"]
    ]
    lines += [
        "- Network evidence alone cannot confirm or rule out ransomware.",
        "- Packet text and names are untrusted data; never execute extracted content.",
        "",
    ]
    return "\n".join(lines)
