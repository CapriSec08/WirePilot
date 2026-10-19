import dataclasses
import os
import shutil
import sys

import pytest

from wirepilot.core import Config, Store
from wirepilot.network_tools import NetworkTools
from make_fixture import write_fixture


@pytest.fixture
def adapter(tmp_path):
    root = tmp_path / "captures"
    root.mkdir()
    write_fixture(root / "fixture.pcap")
    return NetworkTools(
        Store(
            Config(
                root,
                tmp_path / "state",
                capture_interfaces=("eth0",),
                probe_cidrs=("192.0.2.0/24",),
            )
        )
    )


def test_capture_disabled_and_remote_interface_rejected(adapter):
    with pytest.raises(ValueError, match="outside"):
        adapter.capture_live("tcpdump", "eth1", "host 192.0.2.1")
    denied = NetworkTools(
        Store(dataclasses.replace(adapter.config, capture_interfaces=()))
    )
    with pytest.raises(ValueError, match="outside"):
        denied.capture_live("tcpdump", "eth0", "ip")
    remote = NetworkTools(
        Store(
            dataclasses.replace(
                adapter.config, capture_interfaces=("rpcap://remote/eth0",)
            )
        )
    )
    with pytest.raises(ValueError, match="local"):
        remote.capture_live("dumpcap", "rpcap://remote/eth0", "ip")


def test_capture_arguments_and_resource_budget(adapter, monkeypatch, tmp_path):
    monkeypatch.setattr(adapter, "executable", lambda name: name)
    output = tmp_path / "fixed.pcap"
    expression = "host 192.0.2.10 and tcp port 443"
    args = adapter.capture_command("tcpdump", "eth0", expression, 5, 100, 512, output)
    assert args[-2:] == ["--", expression]
    assert "-p" in args and "-U" in args
    dumpcap = adapter.capture_command(
        "dumpcap", "eth0", expression, 5, 100, 512, output
    )
    assert "duration:5" in dumpcap and "filesize:65536" in dumpcap
    with pytest.raises(ValueError, match="budget"):
        adapter.capture_command("tcpdump", "eth0", "ip", 5, 20000, 65535, output)
    with pytest.raises(ValueError, match="Bounds"):
        adapter.capture_command("tcpdump", "eth0", "ip", 31, 100, 512, output)


def test_diagnostic_scope_and_dns_option_injection(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "executable", lambda name: name)
    with pytest.raises(ValueError, match="outside"):
        adapter.diagnostic_command("ping", "198.51.100.1")
    for name in [
        "+trace",
        "-f/etc/passwd",
        "example.test;id",
        "two words",
        "",
        "x..test",
    ]:
        with pytest.raises(ValueError, match="DNS name"):
            adapter.diagnostic_command("dns", "192.0.2.53", name)
    command = adapter.diagnostic_command(
        "dns", "192.0.2.53", "app.example.test", "AAAA"
    )
    assert command[:4] == ["dig", "@192.0.2.53", "app.example.test", "AAAA"]
    assert "+time=2" in command and "+tries=1" in command


def test_platform_specific_probe_arguments(adapter, monkeypatch):
    monkeypatch.setattr(adapter, "executable", lambda name: name)
    monkeypatch.setattr("wirepilot.network_tools.platform.system", lambda: "Linux")
    assert adapter.diagnostic_command("ping", "192.0.2.1")[1:5] == [
        "-n",
        "-c",
        "3",
        "-W",
    ]
    assert adapter.diagnostic_command("trace", "192.0.2.1")[0] == "traceroute"
    monkeypatch.setattr("wirepilot.network_tools.platform.system", lambda: "Windows")
    assert adapter.diagnostic_command("trace", "192.0.2.1")[0] == "tracert"


def fake_capture_program(tmp_path, fail=False, wait=False):
    program = tmp_path / "fake_capture"
    program.write_text(
        f"#!{sys.executable}\nimport sys,struct,time\n"
        "out=sys.argv[sys.argv.index('-w')+1]\n"
        "with open(out,'wb') as f: f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))\n"
        + (
            "sys.stderr.write('fixture failure'); sys.exit(2)\n"
            if fail
            else "time.sleep(5)\n"
            if wait
            else ""
        )
    )
    program.chmod(0o700)
    return str(program)


@pytest.mark.skipif(os.name == "nt", reason="Fixture executable uses a POSIX shebang")
def test_capture_supervisor_registers_completed_fixture(adapter, monkeypatch, tmp_path):
    monkeypatch.setattr(
        adapter, "executable", lambda name: fake_capture_program(tmp_path)
    )
    result = adapter.capture_live("tcpdump", "eth0", "host 192.0.2.1", duration=1)
    assert result["stop_reason"] == "tool_completed"
    assert adapter.store.capture(result["capture_id"])["size"] == 24


@pytest.mark.skipif(os.name == "nt", reason="Fixture executable uses a POSIX shebang")
def test_capture_deadline_stops_child_and_releases_lock(adapter, monkeypatch, tmp_path):
    monkeypatch.setattr(
        adapter, "executable", lambda name: fake_capture_program(tmp_path, wait=True)
    )
    result = adapter.capture_live("tcpdump", "eth0", "ip", duration=1)
    assert result["stop_reason"] == "duration_limit"
    assert result["elapsed_seconds"] < 4
    assert not adapter.capture_lock.locked()


@pytest.mark.skipif(os.name == "nt", reason="Fixture executable uses a POSIX shebang")
def test_capture_failure_not_registered(adapter, monkeypatch, tmp_path):
    monkeypatch.setattr(
        adapter, "executable", lambda name: fake_capture_program(tmp_path, fail=True)
    )
    with pytest.raises(ValueError, match="fixture failure"):
        adapter.capture_live("tcpdump", "eth0", "ip", duration=1)
    with adapter.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0
    assert not adapter.capture_lock.locked()


@pytest.mark.skipif(
    not shutil.which(os.environ.get("WIREPILOT_TCPDUMP", "tcpdump")),
    reason="tcpdump not installed",
)
def test_real_tcpdump_offline(adapter):
    cap = adapter.store.register("fixture.pcap")
    try:
        result = adapter.tcpdump_summary(cap["capture_id"], 2)
    except ValueError as exc:
        if "Couldn't find user 'tcpdump'" in str(exc):
            pytest.skip(
                "Container lacks the distro tcpdump privilege-drop account; no privilege override is applied."
            )
        raise
    assert "10.0.0.10" in result["output"]
    assert len(result["output"].splitlines()) == 2


@pytest.mark.skipif(
    not shutil.which(os.environ.get("WIREPILOT_CAPINFOS", "capinfos")),
    reason="capinfos not installed",
)
def test_real_capinfos_whole_file(adapter):
    cap = adapter.store.register("fixture.pcap")
    result = adapter.capture_metadata(cap["capture_id"])
    assert "44" in result["output"]
    assert result["sha256"] == cap["sha256"]
