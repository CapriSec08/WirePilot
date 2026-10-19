from wirepilot.analysis import anomalies, connectivity, ransomware, hunt


def packet(n=1, **fields):
    return {
        "frame.number": str(n),
        "frame.time_epoch": str(n),
        "frame.len": "60",
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
        **fields,
    }


def test_dns_and_tcp_errors_are_distinct():
    rows = [
        packet(**{"dns.flags.response": "1", "dns.flags.rcode": "3"}),
        packet(2, **{"tcp.stream": "0", "tcp.flags.syn": "1", "tcp.flags.ack": "0"}),
        packet(3, **{"tcp.stream": "0", "tcp.flags.reset": "1"}),
    ]
    assert {f["rule_id"] for f in connectivity(rows)} == {"DNS_ERROR", "TCP_REFUSED"}


def test_synack_prevents_missing_reply_finding():
    rows = [
        packet(**{"tcp.stream": "0", "tcp.flags.syn": "1", "tcp.flags.ack": "0"}),
        packet(2, **{"tcp.stream": "0", "tcp.flags.syn": "1", "tcp.flags.ack": "1"}),
    ]
    assert connectivity(rows) == []


def test_scan_threshold_and_time_window():
    rows = [
        packet(i, **{"tcp.flags.syn": "1", "tcp.dstport": str(1000 + i)})
        for i in range(20)
    ]
    assert "SYN_FANOUT" in {f["rule_id"] for f in anomalies(rows)}
    assert not anomalies(rows[:19])
    for i, row in enumerate(rows):
        row["frame.time_epoch"] = str(i * 61)
    assert not anomalies(rows)


def test_retransmissions_are_not_beacons_or_scan_targets():
    rows = [
        packet(
            i,
            **{
                "tcp.flags.syn": "1",
                "tcp.dstport": "443",
                "tcp.stream": "0",
                "frame.time_epoch": str(i * 10),
            },
        )
        for i in range(30)
    ]
    assert anomalies(rows) == []


def test_periodic_connections_need_separate_streams():
    rows = [
        packet(
            i,
            **{
                "tcp.flags.syn": "1",
                "tcp.dstport": "443",
                "tcp.stream": str(i),
                "frame.time_epoch": str(i * 10),
            },
        )
        for i in range(8)
    ]
    assert {f["rule_id"] for f in anomalies(rows)} == {"PERIODIC_CONNECTIONS"}


def test_ransomware_signal_excludes_responses_and_stays_qualified():
    rows = [
        packet(i, **{"smb2.cmd": "9", "smb2.flags.response": "0"}) for i in range(30)
    ]
    result = ransomware(rows)
    assert result["findings"][0]["rule_id"] == "SMB_FILE_ACTIVITY"
    assert "cannot be confirmed" in result["assessment"]
    for row in rows:
        row["smb2.flags.response"] = "1"
    assert ransomware(rows)["findings"] == []


def test_empty_capture_does_not_claim_safe():
    result = ransomware([])
    assert result["findings"] == []
    assert "ruled out" in result["assessment"]


def test_ioc_domain_boundaries():
    rows = [
        packet(**{"dns.qry.name": "sub.example.test"}),
        packet(2, **{"dns.qry.name": "notexample.test"}),
    ]
    assert hunt(rows, ["example.test"])["total_matches"] == 1
