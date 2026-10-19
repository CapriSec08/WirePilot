"""WirePilot setup: validate dependencies, test stdio, then merge host settings.

Uses only the Python standard library until the private venv is installed.
Does not launch/kill Claude, delete evidence, or overwrite other MCP entries.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def read_config(path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"Claude configuration is invalid JSON: {path}. It was not changed.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers", {}), dict):
        raise ValueError(f"Claude configuration must contain a JSON object and mcpServers object: {path}")
    return data


def write_config(path, original, entry):
    # Refuse a concurrent edit instead of replacing another application's changes.
    if read_config(path) != original:
        raise ValueError("Claude settings changed during setup. Run setup again.")
    data = dict(original)
    servers = dict(data.get("mcpServers", {}))
    servers["wirepilot"] = entry
    data["mcpServers"] = servers
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        backup = path.with_name(path.name + f".wirepilot-{time.time_ns()}.bak")
        shutil.copy2(path, backup)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".wirepilot-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return backup


def run(args, *, env=None, timeout=180, capture=False):
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    with subprocess.Popen(args, cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None, **options) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise ValueError(f"Step timed out after {timeout}s: {args[1:]}. Claude settings were not changed.")
        if proc.returncode:
            # Error text is shown locally; no account configuration is printed.
            raise ValueError(f"Step failed: {args[1:]}\n{stderr or stdout or 'See output above.'}")
        return stdout


def smoke(python, env):
    result = json.loads(run([str(python), "-m", "wirepilot.smoke", "--capture", "lab-ftp-auth.pcap"],
                            env=env, timeout=90, capture=True))
    if not result.get("mcp_initialized") or result.get("health", {}).get("status") != "ready":
        raise ValueError("WirePilot did not report a ready MCP connection. Claude settings were not changed.")
    if result.get("investigation", {}).get("packets", 0) <= 0:
        raise ValueError("PCAP test returned no packets. Claude settings were not changed.")
    return result


def config_path(args, platform):
    if args.config:
        return args.config.expanduser().resolve()
    if platform == "windows":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise ValueError("APPDATA is missing. Run setup from your normal Windows user account.")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    if args.export_only:
        return ROOT / "mcp-config.json"
    if args.claude_code:
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
        return Path(config_dir).expanduser().resolve() / ".claude.json" if config_dir else Path.home() / ".claude.json"
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config").expanduser()
    if not base.is_absolute():
        raise ValueError("XDG_CONFIG_HOME must be an absolute path; use --config to specify the host config.")
    candidates = [base / name / "claude_desktop_config.json" for name in ("Claude", "claude")]
    existing = [p for p in candidates if p.exists()]
    if len(existing) > 1:
        raise ValueError("Multiple Claude Desktop configs found. Use --config with the path shown by Developer > Edit Config.")
    return existing[0] if existing else candidates[0]


def main(argv=None, *, platform="windows"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", action="store_true", help="Enable optional content/CTF/credential tools")
    host = parser.add_mutually_exclusive_group()
    host.add_argument("--config", type=Path, help="Explicit host config path (e.g. from Edit Config)")
    if platform == "linux":
        host.add_argument("--claude-code", action="store_true", help="Configure Claude Code user scope instead of Desktop")
        host.add_argument("--export-only", action="store_true", help="Write mcp-config.json for another MCP client")
    args = parser.parse_args(argv)
    if (platform == "windows" and os.name != "nt") or (platform == "linux" and not sys.platform.startswith("linux")):
        parser.error(f"This launcher is for {platform}.")
    if sys.version_info < (3, 11):
        parser.error("Python 3.11+ is required.")
    try:
        if platform == "linux" and os.geteuid() == 0:
            raise ValueError("Run bash SETUP_LINUX.sh as your normal user, without sudo. This avoids configuring root's Claude account.")
        config = config_path(args, platform)
        original = read_config(config)
        print("Close the target Claude app/session before setup changes its settings.", flush=True)
        tshark = os.environ.get("WIREPILOT_TSHARK") or shutil.which("tshark")
        if not tshark and platform == "windows":
            tshark = str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe")
        if not tshark:
            raise ValueError("TShark was not found on PATH. Install TShark, or set WIREPILOT_TSHARK to its full path.")
        tshark = shutil.which(tshark) or str(Path(tshark).expanduser().resolve())
        run([tshark, "--version"], capture=True, timeout=15)
        print("[1/4] TShark found. Preparing private Python environment...", flush=True)
        python = ROOT / ".venv" / ("Scripts/python.exe" if platform == "windows" else "bin/python")
        if not python.exists():
            run([sys.executable, "-m", "venv", str(ROOT / ".venv")])
        run([str(python), "-m", "pip", "install", "--disable-pip-version-check", str(ROOT)], timeout=600)
        print("[2/4] Installed. Preparing sample captures...", flush=True)
        for folder in ("captures", "incoming", "state"):
            (ROOT / folder).mkdir(exist_ok=True)
        for pattern in ("*.pcap", "*.pcapng"):
            for source in (ROOT / "examples").glob(pattern):
                target = ROOT / "captures" / source.name
                if not target.exists():
                    shutil.copy2(source, target)
        generator_env = dict(os.environ, WIREPILOT_TSHARK=tshark)
        command = [str(python), str(ROOT / "scripts" / "make_claude_config.py")]
        if args.payload:
            command.append("--payload")
        entry = json.loads(run(command, env=generator_env, capture=True))["mcpServers"]["wirepilot"]
        print("[3/4] Testing real MCP handshake and sample PCAP (up to 90 seconds)...", flush=True)
        result = smoke(python, dict(os.environ, **entry["env"]))
        print(f"MCP ready: {result['tool_count']} tools; sample PCAP decoded.", flush=True)
        backup = write_config(config, original, entry)
        print(f"[4/4] WirePilot configuration saved to: {config}")
        if backup:
            print(f"Previous settings backed up to: {backup}")
        print("Local test passed. Claude's connection still needs to be checked.")
        if platform == "linux" and args.export_only:
            print("Import the wirepilot entry from mcp-config.json into your MCP client.")
        elif platform == "linux" and args.claude_code:
            print("Start a new Claude Code session and use /mcp to check WirePilot.")
        else:
            print("Reopen Claude Desktop and start a NEW chat. Enable WirePilot if needed.")
            if platform == "linux":
                print("If missing, compare this path with Developer > Edit Config; rerun with --config if needed.")
        print("Send: Use WirePilot health_check, then investigate lab-ftp-auth.pcap.")
        print("Keep this extracted folder in place; Claude starts WirePilot from here.")
        launcher = "SETUP_WINDOWS.cmd" if platform == "windows" else "bash SETUP_LINUX.sh"
        print("Content/CTF tools: " + ("enabled" if args.payload else f"off; rerun {launcher} --payload to enable"))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"\nSETUP FAILED: {exc}", file=sys.stderr)
        if platform == "linux":
            print("On Kali/Debian/Ubuntu, prerequisites: sudo apt install python3 python3-venv tshark", file=sys.stderr)
            print("On Fedora: sudo dnf install python3 python3-pip wireshark-cli", file=sys.stderr)
            print("On Arch: sudo pacman -S python python-pip wireshark-cli", file=sys.stderr)
            print("Install missing prerequisites, then rerun setup without sudo.", file=sys.stderr)
        else:
            print("If TShark is missing, install Wireshark with the TShark component and rerun setup.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
