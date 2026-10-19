"""Linux launch, host routing, and no-write-on-failure installer checks."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

PROJECT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("linux_setup_common", PROJECT / "scripts" / "setup_common.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def options(**kwargs):
    return SimpleNamespace(**dict({"config": None, "claude_code": False, "export_only": False}, **kwargs))


def test_linux_xdg_discovery_and_ambiguity(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    expected = tmp_path / "Claude" / "claude_desktop_config.json"
    assert setup.config_path(options(), "linux") == expected
    other = tmp_path / "claude" / expected.name
    other.parent.mkdir()
    other.write_text("{}")
    assert setup.config_path(options(), "linux") == other
    expected.parent.mkdir()
    expected.write_text("{}")
    with pytest.raises(ValueError, match="Multiple"):
        setup.config_path(options(), "linux")
    assert setup.config_path(options(config=other), "linux") == other


def test_linux_code_and_export_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "ROOT", tmp_path / "project")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "private-code"))
    assert setup.config_path(options(claude_code=True), "linux") == tmp_path / "private-code" / ".claude.json"
    monkeypatch.delenv("CLAUDE_CONFIG_DIR")
    monkeypatch.setattr(setup.Path, "home", lambda: tmp_path)
    assert setup.config_path(options(claude_code=True), "linux") == tmp_path / ".claude.json"
    assert setup.config_path(options(export_only=True), "linux") == tmp_path / "project" / "mcp-config.json"
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative")
    with pytest.raises(ValueError, match="absolute"):
        setup.config_path(options(), "linux")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux shell launcher")
def test_launcher_finds_own_directory_with_spaces(tmp_path):
    target = tmp_path / "WirePilot project with spaces"
    target.mkdir()
    shutil.copy2(PROJECT / "SETUP_LINUX.sh", target)
    shutil.copytree(PROJECT / "scripts", target / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    result = subprocess.run(["bash", str(target / "SETUP_LINUX.sh"), "--help"],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "--claude-code" in result.stdout and "--export-only" in result.stdout


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux installer")
def test_failed_mcp_test_never_changes_host_config(tmp_path, monkeypatch):
    config = tmp_path / "host.json"
    original = b'{"mcpServers":{"velopilot":{"command":"keep"}}}'
    config.write_bytes(original)
    monkeypatch.setattr(setup, "ROOT", tmp_path)
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(setup.shutil, "which", lambda value: "/usr/bin/tshark")
    def fake_run(args, **kwargs):
        if any("make_claude_config.py" in str(a) for a in args):
            return json.dumps({"mcpServers": {"wirepilot": {"command": "python", "env": {}}}})
        return ""
    monkeypatch.setattr(setup, "run", fake_run)
    def fail(*args):
        raise ValueError("fixture MCP failure")
    monkeypatch.setattr(setup, "smoke", fail)
    assert setup.main(["--config", str(config)], platform="linux") == 1
    assert config.read_bytes() == original
    assert not list(tmp_path.glob("*.bak"))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux root guard")
def test_root_guard_precedes_install(tmp_path, monkeypatch):
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(setup, "run", lambda *args, **kwargs: pytest.fail("must not install as root"))
    config = tmp_path / "host.json"
    assert setup.main(["--config", str(config)], platform="linux") == 1
    assert not config.exists()
