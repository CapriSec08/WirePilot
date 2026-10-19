import dataclasses
import json
import os
import shutil
from pathlib import Path
import sys
import time

import pytest

from wirepilot import analysis, ctf, evidence, investigation
from wirepilot.core import Config, Store, Decoder, run_bounded
from scenarios import (
    ftp_capture,
    ctf_capture,
    smb_capture,
    ipv6_capture,
    pcapng_from_pcap,
    smb_activity_capture,
)


TShark = shutil.which(os.environ.get("WIREPILOT_TSHARK", "tshark"))
needs_tshark = pytest.mark.skipif(not TShark, reason="TShark not installed")


@pytest.fixture
def lab(tmp_path):
    root = tmp_path / "captures"
    root.mkdir()
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    for name, function in [
        ("ftp", ftp_capture),
        ("ctf", ctf_capture),
        ("smb", smb_capture),
        ("ipv6", ipv6_capture),
    ]:
        function(root / (name + ".pcap"))
    pcapng_from_pcap(root / "ctf.pcap", root / "ctf.pcapng")
    config = Config(
        root,
        tmp_path / "state",
        tshark=TShark or "tshark",
        allow_payload=True,
        import_root=incoming,
    )
    return Store(config)


@needs_tshark
def test_real_ftp_failures_then_success_and_password_redaction(lab):
    decoder = Decoder(lab)
    cap = lab.register("ftp.pcap")
    rows, coverage = decoder.packets(cap["capture_id"])
    result = investigation.analyse_authentication(rows)
    assert result["findings"][0]["rule_id"] == "REPEATED_AUTH_FAILURES"
    assert result["findings"][0]["accounts"] == ["analyst"]
    assert result["findings"][0]["subsequent_successes"][0]["outcome"] == "success"
    assert "lab-only-password" not in json.dumps(rows)
    assert all(
        "ftp.request.arg" not in row
        for row in rows
        if row.get("ftp.request.command") == "PASS"
    )
    credentials = ctf.credentials(decoder, cap["capture_id"], 0)
    assert any(
        row["password"] == "lab-success-password" for row in credentials["credentials"]
    )


@needs_tshark
def test_real_smb_failures_not_more_processing(lab):
    decoder = Decoder(lab)
    cap = lab.register("smb.pcap")
    rows, _ = decoder.packets(cap["capture_id"])
    result = investigation.analyse_authentication(rows)
    assert result["findings"][0]["rule_id"] == "REPEATED_AUTH_FAILURES"
    assert result["findings"][0]["subsequent_successes"]
    for row in rows:
        row["smb2.nt_status"] = "0xc0000016"
    assert not investigation.analyse_authentication(rows)["findings"]


@needs_tshark
def test_real_visible_smb_writes_are_only_indicators(lab):
    smb_activity_capture(lab.config.capture_root / "writes.pcap")
    cap = lab.register("writes.pcap")
    rows, _ = Decoder(lab).packets(cap["capture_id"])
    result = analysis.ransomware(rows)
    assert "SMB_FILE_ACTIVITY" in {f["rule_id"] for f in result["findings"]}
    assert "cannot be confirmed" in result["assessment"]


@needs_tshark
def test_real_benign_login_does_not_trigger_bruteforce(lab):
    ftp_capture(lab.config.capture_root / "benign.pcap", failures=1)
    cap = lab.register("benign.pcap")
    rows, _ = Decoder(lab).packets(cap["capture_id"])
    assert not investigation.analyse_authentication(rows)["findings"]


def auth_row(frame, **fields):
    return {
        "frame.number": str(frame),
        "frame.time_epoch": str(frame),
        "ip.src": "10.0.0.20",
        "ip.dst": "10.0.0.10",
        **fields,
    }


def test_http_challenges_never_claim_login_success():
    rows = [auth_row(i, **{"http.response.code": "401"}) for i in range(5)]
    rows.append(auth_row(6, **{"http.response.code": "200"}))
    result = investigation.analyse_authentication(rows)
    assert result["findings"][0]["rule_id"] == "HTTP_AUTH_CHALLENGES"
    assert result["findings"][0]["subsequent_successes"] == []
    assert result["findings"][0]["confidence"] == "low"


def test_retransmitted_auth_responses_do_not_create_a_burst():
    rows = [
        auth_row(
            i,
            **{
                "ftp.response.code": "530",
                "tcp.stream": "0",
                "tcp.analysis.retransmission": "1" if i else "",
            },
        )
        for i in range(10)
    ]
    result = investigation.analyse_authentication(rows)
    assert len(result["events"]) == 1
    assert not result["findings"]


def test_kerberos_preauth_required_is_normal_and_retry_threshold():
    rows = [auth_row(i, **{"kerberos.error_code": "25"}) for i in range(10)]
    assert not investigation.analyse_authentication(rows)["events"]
    for row in rows:
        row["kerberos.error_code"] = "24"
    assert investigation.analyse_authentication(rows)["findings"]
    assert not investigation.analyse_authentication(rows[:4])["findings"]


def test_modification_burst_is_qualified_and_time_bounded():
    rows = [
        auth_row(
            i,
            **{
                "smb2.cmd": "9" if i % 2 else "17",
                "smb2.flags.response": "0",
                "smb2.filename": f"file-{i}.txt",
            },
        )
        for i in range(12)
    ]
    findings = analysis.ransomware(rows)["findings"]
    assert "SMB_MODIFICATION_BURST" in {f["rule_id"] for f in findings}
    assert all(
        "ransomware confirmed" not in f["interpretation"].lower() for f in findings
    )
    for i, row in enumerate(rows):
        row["frame.time_epoch"] = str(i * 120)
    assert not analysis.ransomware(rows)["findings"]


@needs_tshark
def test_ctf_split_flag_reassembly_and_http_export(lab):
    decoder = Decoder(lab)
    cap = lab.register("ctf.pcap")
    assert ctf.search_capture(decoder, cap["capture_id"])["matches"] == []
    result = ctf.search_capture(decoder, cap["capture_id"], stream_id=0)
    assert result["matches"][0]["match"] == "flag{wirepilot_stream_reassembly}"
    creds = ctf.credentials(decoder, cap["capture_id"], 0)["credentials"]
    assert creds[0]["username"] == "lab" and creds[0]["password"] == "test-only"
    output = ctf.http_objects(decoder, cap["capture_id"], 0)
    assert len(output["objects"]) == 1
    obj = Path(output["objects"][0]["path"])
    assert obj.is_relative_to(lab.config.state_root)
    assert obj.name == "object_001.bin"
    assert obj.read_bytes().endswith(b"flag{wirepilot_stream_reassembly}")
    assert not (lab.config.state_root / "escape.sh").exists()


@needs_tshark
def test_pcapng_ipv6_and_late_frame_queries(lab):
    decoder = Decoder(lab)
    for name in ("ctf.pcapng", "ipv6.pcap"):
        cap = lab.register(name)
        rows, coverage = decoder.packets(cap["capture_id"])
        assert coverage["whole_capture"]
        if name.startswith("ipv6"):
            assert (
                investigation.engineering(rows)["findings"][0]["rule_id"] == "PATH_MTU"
            )
    cap = lab.register("ftp.pcap")
    first, coverage = decoder.packets(cap["capture_id"], frame_count=5)
    assert coverage["next_start_frame"] == 6
    later, next_coverage = decoder.packets(
        cap["capture_id"], start_frame=6, frame_count=5
    )
    assert later and all(int(row["frame.number"]) >= 6 for row in later)
    empty, coverage = decoder.packets(
        cap["capture_id"], "frame.number == 99999", frame_count=5
    )
    assert empty == [] and coverage["next_start_frame"] == 6
    timed, coverage = decoder.packets(
        cap["capture_id"], start_epoch=1760000001, end_epoch=1760000001.5
    )
    assert all(
        1760000001 <= float(row["frame.time_epoch"]) <= 1760000001.5 for row in timed
    )
    assert not coverage["whole_capture"]


def test_all_content_tools_obey_payload_setting(lab):
    decoder = Decoder(Store(dataclasses.replace(lab.config, allow_payload=False)))
    for operation in [
        lambda: ctf.search_capture(decoder, "x"),
        lambda: ctf.credentials(decoder, "x", 0),
        lambda: ctf.http_objects(decoder, "x", 0),
    ]:
        with pytest.raises(ValueError, match="disabled"):
            operation()


@pytest.mark.parametrize(
    "encoding,text,expected",
    [
        ("base64", "ZmxhZ3tsYWJ9", "flag{lab}"),
        ("hex", "4142", "AB"),
        ("url", "a%20b", "a b"),
        ("rot13", "synt", "flag"),
    ],
)
def test_decoding_is_data_only(encoding, text, expected):
    assert ctf.decode_text(text, encoding)["text"] == expected


def test_chunk_parser_and_truncation():
    assert ctf.dechunk(b"3\r\nabc\r\n0\r\n\r\n") == (b"abc", 13)
    with pytest.raises(ValueError):
        ctf.dechunk(b"4\r\nabc")
    with pytest.raises(ValueError, match="Negative"):
        ctf.dechunk(b"-1\r\nabc\r\n0\r\n\r\n")


@needs_tshark
def test_truncated_capture_and_invalid_time_are_errors(lab):
    good = (lab.config.capture_root / "ctf.pcap").read_bytes()
    (lab.config.capture_root / "broken.pcap").write_bytes(good[:42])
    cap = lab.register("broken.pcap")
    with pytest.raises(ValueError, match="Command failed"):
        Decoder(lab).packets(cap["capture_id"])
    valid = lab.register("ctf.pcap")
    with pytest.raises(ValueError, match="finite"):
        Decoder(lab).packets(valid["capture_id"], start_epoch=float("nan"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group lifecycle check")
def test_timeout_also_closes_descendant_output_pipes():
    script = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); time.sleep(30)'
    start = time.monotonic()
    with pytest.raises(ValueError, match="timed out"):
        run_bounded([sys.executable, "-c", script], timeout=1)
    assert time.monotonic() - start < 5


def test_import_copy_is_independent_and_escape_rejected(lab, tmp_path):
    source = lab.config.import_root / "upload.pcap"
    shutil.copyfile(lab.config.capture_root / "ctf.pcap", source)
    result = evidence.import_capture(lab, "upload.pcap")
    source.write_text("changed original")
    assert lab.capture(result["capture_id"])["sha256"] == result["sha256"]
    with pytest.raises(ValueError, match="within"):
        evidence.import_capture(lab, "../outside.pcap")
    (lab.config.import_root / "link.pcap").symlink_to(
        lab.config.capture_root / "ctf.pcap"
    )
    with pytest.raises(ValueError, match="within"):
        evidence.import_capture(lab, "link.pcap")


def test_event_import_correlation_and_nonfinite_rejected(lab):
    path = lab.config.import_root / "eve.jsonl"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2025-10-09T08:53:20Z",
                "src_ip": "10.0.0.20",
                "dest_ip": "10.0.0.10",
                "event_type": "alert",
                "alert": {"signature": "Lab alert"},
            }
        )
        + "\n"
    )
    result = evidence.import_events(lab, "eve.jsonl", "suricata")
    data = evidence.get_events(lab, result["event_id"])
    assert data["events"][0]["description"] == "Lab alert"
    row = auth_row(1)
    row["frame.time_epoch"] = "1760000000"
    event = {
        "time": 1760000000,
        "source": "10.0.0.20",
        "destination": "10.0.0.10",
        "description": "test",
        "source_line": 1,
    }
    assert (
        evidence.correlate([row], [event])["matches"][0]["packet_evidence"][0]["frame"]
        == 1
    )
    path.write_text('{"time":NaN}')
    with pytest.raises(ValueError, match="Invalid JSON"):
        evidence.import_events(lab, "eve.jsonl", "network")
    with pytest.raises(ValueError):
        evidence.get_events(lab, "../../escape")


def test_empty_report_and_markdown_escape():
    coverage = {
        "sha256": "a" * 64,
        "scope": "test",
        "whole_capture": True,
        "limitations": [],
    }
    report = investigation.build_report([], coverage)
    assert "does not establish absence" in report["assessment"]
    report["assessment"] = "![leak](https://example.test) <script>alert(1)</script>"
    text = investigation.markdown_report(report)
    assert "<script>" not in text and "![leak]" not in text
