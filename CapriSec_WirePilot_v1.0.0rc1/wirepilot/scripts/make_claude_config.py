"""Print a WirePilot MCP configuration fragment. Does not edit existing Claude config."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--payload",
    action="store_true",
    help="Enable explicit content/CTF tools, including plaintext credentials",
)
parser.add_argument(
    "--capture-interface",
    default="",
    help="Optional authorised local capture interface",
)
parser.add_argument(
    "--probe-cidrs",
    default="",
    help="Optional comma-separated authorised active diagnostic ranges",
)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
for folder in ("captures", "incoming", "state"):
    (root / folder).mkdir(exist_ok=True)
tshark = os.environ.get("WIREPILOT_TSHARK") or shutil.which("tshark")
if (
    not tshark
    and os.name == "nt"
    and Path(r"C:\Program Files\Wireshark\tshark.exe").is_file()
):
    tshark = r"C:\Program Files\Wireshark\tshark.exe"
env = {
    "WIREPILOT_CAPTURE_ROOT": str(root / "captures"),
    "WIREPILOT_IMPORT_ROOT": str(root / "incoming"),
    "WIREPILOT_STATE_ROOT": str(root / "state"),
    "WIREPILOT_TSHARK": tshark or "tshark",
    "WIREPILOT_ALLOW_PAYLOAD": "1" if args.payload else "0",
}
if args.capture_interface:
    env["WIREPILOT_CAPTURE_INTERFACES"] = args.capture_interface
if args.probe_cidrs:
    env["WIREPILOT_PROBE_CIDRS"] = args.probe_cidrs
if tshark:
    folder = Path(tshark).parent
    for name in ("dumpcap", "capinfos"):
        candidate = folder / (name + (".exe" if os.name == "nt" else ""))
        if candidate.is_file():
            env["WIREPILOT_" + name.upper()] = str(candidate)
print(
    json.dumps(
        {
            "mcpServers": {
                "wirepilot": {
                    "command": sys.executable,
                    "args": ["-m", "wirepilot.server"],
                    "env": env,
                }
            }
        },
        indent=2,
    )
)
