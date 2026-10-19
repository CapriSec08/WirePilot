# Linux setup shortcut

Prerequisites: Python 3.11+, Python venv support, TShark, and your chosen MCP host.
Install Claude separately and sign in to that host normally. WirePilot itself
does not require an API key. Internet access is needed for Python dependencies.

On Kali/Debian/Ubuntu, install prerequisites with:

```bash
sudo apt install python3 python3-venv tshark
```

On Fedora: `sudo dnf install python3 python3-pip wireshark-cli`.
On Arch: `sudo pacman -S python python-pip wireshark-cli`.
Other distributions need their equivalent Python/venv/TShark packages. The setup
prints these hints but does not automatically install system packages or change
capture permissions. Npcap is a Windows dependency, not a Linux dependency.

## One-command setup

Close the target host. Extract the full ZIP into a permanent folder. In that folder:

```bash
bash SETUP_LINUX.sh
```

Run this without sudo. The script locates the project even when launched from a
different working directory or a path containing spaces. `bash` avoids needing to
change executable permissions after ZIP extraction.

Setup checks TShark, creates `.venv/bin/python`, installs the package, copies
missing sample PCAPs, tests real stdio MCP initialization and sample investigation
with a 90-second deadline, then saves the host config with a timestamped backup.
It preserves other MCP entries, preferences, captures and case state. Package
installation has a 10-minute deadline. Failed preflight/installation/MCP tests
leave host configuration unchanged. Root execution is rejected to avoid configuring
root's account instead of your own.

## Select your host

Default: Claude Desktop. Existing config files under `Claude` and `claude` inside
`XDG_CONFIG_HOME` (or `~/.config`) are detected. If both exist, setup asks for an
explicit path instead of choosing one. If neither exists, it creates the `Claude`
path. This conventional path is a discovery default, not a guarantee for every
Desktop build. Use the path shown by **Developer → Edit Config** when different:

```bash
bash SETUP_LINUX.sh --config "/absolute/path/claude_desktop_config.json"
```

Claude Code (a separate host):

```bash
bash SETUP_LINUX.sh --claude-code
```

This merges the user-scoped `mcpServers.wirepilot` entry in `~/.claude.json`, or
`$CLAUDE_CONFIG_DIR/.claude.json` when a custom config directory is set. It preserves
other app state and servers and backs up the original file. Close Code before setup;
start a new session afterward and check `/mcp`. Host policies, project-level
overrides, or disabled servers may still prevent loading.

Other MCP clients, including a future LEON host:

```bash
bash SETUP_LINUX.sh --export-only
```

This writes `wirepilot/mcp-config.json` inside the extracted release and changes no
Claude config. Import its `wirepilot` entry using your client's configuration flow.
Generated paths refer to this Linux installation and should not be copied to Windows.

Add `--payload` to any mode to enable content/CTF/credential tools explicitly. Default
operation is metadata-only. Live interfaces and active probe scopes stay disabled
until explicitly configured. Keep the extracted project directory after installation.

## Test and troubleshoot

After setup passes, reopen the host and ask:

> Use WirePilot health_check, then investigate lab-ftp-auth.pcap with packet references.

Expected sample: five failed FTP logins followed by visible success for analyst.
The local smoke pass verifies WirePilot/TShark, not the host UI or detection accuracy
on arbitrary captures. Native Claude Desktop/Code connection must be checked separately.

- Missing Python/venv/TShark: install the prerequisite package and rerun.
- Custom TShark location: set `WIREPILOT_TSHARK` to its full executable path.
- Invalid JSON: correct the existing host config; setup leaves it unchanged.
- Moving between Windows and Linux: extract a fresh copy; virtual environments and
  executable paths are OS-specific.
- WSL: this launcher configures a Linux host inside WSL. For Claude Desktop on
  Windows, use `SETUP_WINDOWS.cmd` in Windows; a Linux config does not connect that app.

To roll back, close the host and restore the timestamped config backup reported by
setup. Preserve any subsequent config changes first. To disconnect only WirePilot,
remove its entry from `mcpServers`; project data need not be deleted.

Reference: Claude Code documents user-scoped MCP configuration at
https://code.claude.com/docs/en/mcp . Claude Desktop platform availability is described
at https://support.claude.com/en/articles/10065433-install-claude-desktop .
