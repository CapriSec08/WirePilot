"""Portable installer logic tests; native Windows execution is still required."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

spec = importlib.util.spec_from_file_location("shared_setup", Path(__file__).parents[1] / "scripts" / "setup_common.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def test_merge_preserves_servers_and_settings_and_backup(tmp_path):
    path = tmp_path / "Claude" / "claude_desktop_config.json"
    path.parent.mkdir()
    original = {"mcpServers": {"velopilot": {"command": "keep"}, "wirepilot": {"command": "old"}}, "preferences": {"theme": "dark"}}
    raw = ("\ufeff" + json.dumps(original)).encode("utf-8")
    path.write_bytes(raw)
    entry = {"command": r"C:\Users\Jay S\WirePilot\.venv\Scripts\python.exe", "args": ["-m", "wirepilot.server"]}
    backup = setup.write_config(path, setup.read_config(path), entry)
    updated = setup.read_config(path)
    assert updated["mcpServers"]["velopilot"] == original["mcpServers"]["velopilot"]
    assert updated["preferences"] == original["preferences"]
    assert updated["mcpServers"]["wirepilot"] == entry
    assert backup.read_bytes() == raw
    setup.write_config(path, updated, entry)
    assert setup.read_config(path) == updated


@pytest.mark.parametrize("contents", ['{broken', '[]', '{"mcpServers": []}'])
def test_invalid_config_is_untouched(tmp_path, contents):
    path = tmp_path / "settings.json"
    path.write_text(contents)
    with pytest.raises(ValueError):
        setup.read_config(path)
    assert path.read_text() == contents


def test_new_config_and_concurrent_edit(tmp_path):
    path = tmp_path / "new" / "settings.json"
    assert setup.write_config(path, {}, {"command": "python"}) is None
    original = setup.read_config(path)
    path.write_text('{"another": true}')
    with pytest.raises(ValueError, match="changed"):
        setup.write_config(path, original, {})
    assert setup.read_config(path) == {"another": True}


@pytest.mark.parametrize("result", [
    {"mcp_initialized": True, "health": {"status": "error"}},
    {"mcp_initialized": False, "health": {"status": "ready"}},
    {"mcp_initialized": True, "health": {"status": "ready"}, "investigation": {"packets": 0}},
])
def test_failed_smoke_is_rejected(monkeypatch, result):
    monkeypatch.setattr(setup, "run", lambda *args, **kwargs: json.dumps(result))
    with pytest.raises(ValueError):
        setup.smoke("python", {})


def test_installer_subprocess_deadline():
    with pytest.raises(ValueError, match="timed out"):
        setup.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2, capture=True)
