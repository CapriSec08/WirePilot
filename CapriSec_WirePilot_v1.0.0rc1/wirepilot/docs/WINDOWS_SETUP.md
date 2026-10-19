# Windows setup and recovery

Start with SETUP_WINDOWS.cmd in the extracted project. It does not require you to
change directory, activate Python, copy JSON, provide an API key or run as admin.
The outer release folder also has a launcher, so either launcher works.

## What setup changes

- Installs WirePilot and its dependencies into the project `.venv`.
- Creates captures/incoming/state directories and copies missing sample captures.
- Tests a real stdio MCP connection and sample PCAP investigation, with a 90-second
  deadline and child-process cleanup. Package installation has a 10-minute deadline.
- Only after tests pass, replaces the single `wirepilot` entry in Claude settings,
  preserving other servers and preferences. Backs up the original file first.

Claude must be fully closed before setup and reopened afterward. No process is
automatically killed except setup's own timed-out subprocess tree. Existing evidence
and case state are not deleted. Optional payload access defaults off. To enable it,
open a terminal in the project and run `SETUP_WINDOWS.cmd --payload`.

## If setup stops

- **Python missing:** install Python 3.11+ from python.org, enable the launcher/PATH,
  then run setup again.
- **TShark missing:** install Wireshark with TShark. The standard Program Files
  location and PATH are detected. For a custom location set WIREPILOT_TSHARK in
  your terminal before starting the launcher.
- **Package install failed:** read pip's message, check internet/proxy access, and rerun.
- **Invalid JSON:** the original config is left untouched. Open Claude's Settings →
  Developer → Edit Config, correct the JSON, save, close Claude, and rerun setup.
- **Local test fails/times out:** Claude configuration is not updated. Copy the error
  shown by setup; it distinguishes installation, MCP and PCAP stages.
- **Local test passes but Claude cannot see WirePilot:** verify the server in Claude's
  Developer settings and enable its tools in a new chat. Use Edit Config to confirm
  the actual config path. If different, rerun with `--config "FULL_PATH"`.

The standard configuration is `%APPDATA%\Claude\claude_desktop_config.json`.
Claude's server log is `%APPDATA%\Claude\logs\mcp-server-wirepilot.log`.
The setup never prints existing Claude settings or other servers' API keys.

## Roll back configuration

With Claude closed, copy the timestamped `.wirepilot-....bak` file reported by setup
over the config file to restore that exact previous configuration. This also restores
other settings to their state at backup time, so preserve any newer edits first.
To disconnect only WirePilot, remove only its entry inside `mcpServers` using Edit
Config and restart Claude. Leave other entries intact. Project data can stay in place.

## Public release status

Portable configuration preservation, invalid-config handling, concurrent-edit checks,
and subprocess deadline tests run in the supplied suite. Native Windows launcher,
TShark, and actual Claude UI connection must still be tested before public launch.
This launcher is an interim installer; it is not a signed Windows installer or a
Claude Desktop extension, and Python/Wireshark are not bundled.
