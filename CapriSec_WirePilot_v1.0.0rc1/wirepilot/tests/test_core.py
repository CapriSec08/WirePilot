import os
import dataclasses
import shutil
import socket
import sys
import threading

import pytest

from wirepilot.core import Config, Store, Decoder, run_bounded
from wirepilot.diagnostics import endpoint_probe
from make_fixture import write_fixture


@pytest.fixture
def config(tmp_path):
    root = tmp_path / "captures"
    root.mkdir()
    write_fixture(root / "test.pcap")
    return Config(
        root, tmp_path / "state", tshark=os.environ.get("WIREPILOT_TSHARK", "tshark")
    )


def test_path_escape_and_symlink_denied(config, tmp_path):
    store = Store(config)
    outside = tmp_path / "outside.pcap"
    write_fixture(outside)
    with pytest.raises(ValueError, match="inside"):
        store.register(str(outside))
    with pytest.raises(ValueError, match="inside"):
        store.register("../outside.pcap")
    (config.capture_root / "link.pcap").symlink_to(outside)
    with pytest.raises(ValueError, match="inside"):
        store.register("link.pcap")


def test_hash_change_detected(config):
    store = Store(config)
    info = store.register("test.pcap")
    with (config.capture_root / "test.pcap").open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="changed"):
        store.capture(info["capture_id"])


def test_invalid_magic(config):
    (config.capture_root / "fake.pcap").write_text("not a pcap")
    with pytest.raises(ValueError, match="Expected"):
        Store(config).register("fake.pcap")


def test_payload_disabled(config):
    with pytest.raises(ValueError, match="disabled"):
        Decoder(Store(config)).follow("anything", 0)


def test_output_and_timeout_limits():
    with pytest.raises(ValueError, match="Output limit"):
        run_bounded([sys.executable, "-c", "print('X'*100000)"], max_bytes=1024)
    with pytest.raises(ValueError, match="timed out"):
        run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)


def test_probe_disabled_and_local_connect(config):
    with pytest.raises(ValueError, match="outside"):
        endpoint_probe(config, "127.0.0.1", 443)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()

        def accept():
            conn, _ = listener.accept()
            conn.close()

        thread = threading.Thread(target=accept)
        thread.start()
        result = endpoint_probe(
            dataclasses.replace(config, probe_cidrs=("127.0.0.1/32",)),
            "127.0.0.1",
            listener.getsockname()[1],
        )
        thread.join()
    assert result["tcp"] == "connected"


@pytest.mark.skipif(
    not shutil.which(os.environ.get("WIREPILOT_TSHARK", "tshark")),
    reason="TShark not installed",
)
def test_real_tshark_decode_and_limit(config):
    store = Store(config)
    info = store.register("test.pcap")
    rows, coverage = Decoder(store).packets(info["capture_id"])
    assert len(rows) == 44
    assert not coverage["prefix_limit_reached"]
    assert any(r.get("dns.flags.rcode") == "3" for r in rows)
    limited = Decoder(Store(dataclasses.replace(config, packet_limit=3)))
    rows, coverage = limited.packets(info["capture_id"])
    assert len(rows) == 3
    assert coverage["prefix_limit_reached"]
    rows, coverage = limited.packets(info["capture_id"], "dns")
    assert coverage["prefix_limit_reached"] is True
    assert len(rows) == 2


@pytest.mark.skipif(
    not shutil.which(os.environ.get("WIREPILOT_TSHARK", "tshark")),
    reason="TShark not installed",
)
def test_filter_validation_and_payload(config):
    store = Store(config)
    info = store.register("test.pcap")
    with pytest.raises(ValueError, match="Command failed"):
        Decoder(store).packets(info["capture_id"], "badfield_does_not_exist ===")
    decoder = Decoder(Store(dataclasses.replace(config, allow_payload=True)))
    result = decoder.follow(info["capture_id"], 1)
    assert "HTTP/1.1 503" in result["untrusted_capture_content"]
