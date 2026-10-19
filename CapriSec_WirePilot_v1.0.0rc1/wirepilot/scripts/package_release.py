"""Package source, built distributions and launchers without local evidence/state.

Run after building dist/ with the project's current source.
"""
from pathlib import Path
import hashlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / "CapriSec_WirePilot_v1.0.0rc1.zip"
ALLOWED_DIRS = {".github", "dist", "docs", "examples", "scripts", "src", "tests"}
EXCLUDED = {".venv", "build", "__pycache__", ".pytest_cache", ".ruff_cache"}


def main():
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDED or part.endswith(".egg-info") for part in rel.parts):
            continue
        if len(rel.parts) > 1 and rel.parts[0] not in ALLOWED_DIRS:
            continue
        if len(rel.parts) == 1 and path.suffix not in {".md", ".toml", ".txt", ".cmd", ".sh"} and path.name not in {"LICENSE", ".gitignore"}:
            continue
        if path.suffix in {".pyc", ".pyo"} or path.name == "SHA256SUMS.txt":
            continue
        files.append(path)
    files.sort()
    (ROOT / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}\n"
        for p in files), encoding="utf-8")
    files.append(ROOT / "SHA256SUMS.txt")
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("SETUP_WINDOWS.cmd", '@echo off\r\ncall "%~dp0wirepilot\\SETUP_WINDOWS.cmd" %*\r\nexit /b %errorlevel%\r\n')
        launcher = '#!/usr/bin/env bash\nset -euo pipefail\nsetup_dir="$(CDPATH=\'\' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"\nexec bash "$setup_dir/wirepilot/SETUP_LINUX.sh" "$@"\n'
        info = zipfile.ZipInfo("SETUP_LINUX.sh")
        info.create_system = 3
        info.external_attr = 0o100755 << 16
        archive.writestr(info, launcher, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("START_HERE.txt", """WirePilot for Claude - Windows and Linux setup

1. Fully quit the target Claude app/session.
2. Extract the entire ZIP into a permanent folder. Do not run inside the ZIP.
3. Windows: double-click SETUP_WINDOWS.cmd beside this file.
   Linux: open a terminal in this folder and run bash SETUP_LINUX.sh (without sudo).
4. After LOCAL TEST PASSED, reopen Claude and start a new chat.
5. Ask: Use WirePilot health_check, then investigate lab-ftp-auth.pcap.

Prerequisites: Python 3.11+, TShark (included with Wireshark), your MCP host.
Linux (Kali/Debian/Ubuntu): sudo apt install python3 python3-venv tshark
No WirePilot API key required. Internet needed for Python dependencies.
Setup preserves other MCP servers and creates a config backup.
Keep this extracted folder in place; the host starts WirePilot from here.
Optional content/CTF tools: add --payload to the setup command.
Linux Claude Code: bash SETUP_LINUX.sh --claude-code
Linux other hosts: bash SETUP_LINUX.sh --export-only
See wirepilot/docs/LINUX_SETUP.md or WINDOWS_SETUP.md for recovery and host options.
Host UI acceptance is still required. This remains a release candidate.
""")
        for path in files:
            archive.write(path, "wirepilot/" + path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(OUTPUT) as archive:
        assert archive.testzip() is None
    print(f"{OUTPUT}\n{OUTPUT.stat().st_size} bytes\nSHA256 {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
