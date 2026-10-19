# Local acceptance testing with Claude

For normal setup, use `SETUP_WINDOWS.cmd` or `bash SETUP_LINUX.sh` from the extracted
release. See [Windows](WINDOWS_SETUP.md) or [Linux](LINUX_SETUP.md) for host options.
The manual commands below are for developer testing and troubleshooting.

Test this release candidate before promoting it to a public stable release.
The stdio client tests in VALIDATION.md are not a claim that Claude Desktop/Code
has been tested against this package.

## 1. Install and run the automated checks

Follow the root README for Python/TShark installation. Copy the bundled examples
into the capture folder. Run tests inside the extracted `wirepilot` folder:

```bash
.venv/bin/python -m pytest -q
```

Windows: use `.\.venv\Scripts\python.exe -m pytest -q`.
A skipped integration test is not a pass for that feature. Inspect skipped reasons.
Do not run the AI host as root to make a failed capture test disappear.

## 2. Generate the configuration

```bash
.venv/bin/python scripts/make_claude_config.py --payload
```

Windows: `.\.venv\Scripts\python.exe scripts\make_claude_config.py --payload`.
This creates local `captures`, `incoming`, `state` directories and prints paths for
this installation. It does not edit Claude's existing config. Merge its `wirepilot`
server entry into your host configuration, preserving VeloPilot/other servers.

- Claude Desktop on Windows: Settings → Developer → Edit Config. The file is
  `%APPDATA%\Claude\claude_desktop_config.json`. Fully quit/restart after editing.
- Claude Desktop on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`.
- Claude Code on Kali/Linux: merge the entry into the project's `.mcp.json`, then
  inspect `/mcp`. Follow Claude's own project trust/tool approval controls.
- If Claude is on Windows and WirePilot is in WSL, the native Windows Python path
  cannot launch a Linux virtual environment. Use Claude Code inside the same WSL
  environment first, or a correctly configured `wsl.exe` wrapper. WSL capture sees
  the WSL network vantage point, not automatically every physical Windows interface.

Do not paste a terminal transcript into JSON. Use the generator's JSON object.
Do not assume uploading a PCAP to chat transfers it to the local MCP process.
Save uploads into the configured incoming folder and use `import_capture_file`.

## 3. Optional protocol smoke check without Claude

Set capture/state paths in the terminal. On Kali, from the extracted project folder:

```bash
export WIREPILOT_CAPTURE_ROOT="$PWD/captures"
export WIREPILOT_STATE_ROOT="$PWD/state"
.venv/bin/python -m wirepilot.smoke --capture synthetic-investigation.pcap
```

Expect `mcp_initialized: true`, 44 tools, the installed version and a capture summary.
This performs local file analysis, not capture or active network probing.

## 4. Claude test matrix

| Test | Ask Claude to do | Acceptance evidence |
| --- | --- | --- |
| Discovery | Check WirePilot health and list available tools | Version 1.0.0rc1, 44 tools, correct capture root/TShark path |
| General PCAP | Register `synthetic-investigation.pcap`; investigate failed connections | DNS error, refused TCP and HTTP 503 with actual frames |
| Authentication | Analyse `lab-ftp-auth.pcap` | Repeated failures, account `analyst`, subsequent visible success; no automatic compromise verdict |
| SMB authentication | Analyse `lab-smb-auth.pcap` | Five failures and subsequent setup success; no account invented if absent |
| SMB activity | Investigate `lab-smb-activity.pcap` for ransomware indicators | SMB write activity qualified as a lead; bulk file writes do not prove ransomware |
| CTF split flag | Investigate `lab-ctf-http.pcap`; find a flag | `flag{wirepilot_stream_reassembly}` through TCP reassembly |
| Credentials | Explicitly inspect captured plaintext credentials in that CTF stream | Lab HTTP Basic account `lab`, password `test-only`; require payload access |
| Object recovery | Recover the CTF HTTP response body | Generated `.bin` path, SHA-256, matching harmless flag content; no execution |
| Engineering | Analyse `lab-ipv6-mtu.pcap` | IPv6 packet-too-big/MTU evidence with frame reference; no fabricated device configuration |
| PCAPNG | Analyse `lab-ctf-http.pcapng` | Equivalent visible network evidence to the PCAP version |
| Paging | Query the FTP capture with frame_count 5, then next_start_frame | Later frame numbers actually change; empty filter still reports continuation |
| Protocol depth | Find fields for a protocol, then query selected fields | Known field validation; sensitive custom fields require payload mode |
| Timeline | Build a timeline and inspect an important frame | UTC timestamps and consistent capture/frame references |
| Baseline | Compare a capture with itself | No new hosts/domains; no false claim of learned normality |
| Imported events | Import bundled `lab-events.jsonl` as network, correlate with synthetic PCAP | Exact source hash/line references; external assertions remain qualified |
| Cases/reports | Create case, attach capture, add notes, export, restart Claude | Notes survive; readable report contains SHA-256, scope, evidence and alternatives |
| Boundaries | Request outside-root file or disabled active destination/interface | Explicit tool error; no path escape or silent permission changes |

For a benign comparison, use a known-authorised capture and confirm that normal
traffic produces appropriately qualified results. Never rely only on attack fixtures.

## 5. Local active tests, separately scoped

After offline checks pass, configure only a lab interface and authorised target IP
range. List capture interfaces first. Ask for a 5–10 second filtered capture of your
own lab connection. Confirm packet file, hash, stop time, snaplen and scope. Then test
DNS/ping/path and TCP/TLS against known reachable/unreachable lab services.

Verify success and failure paths, permissions, clean timeout and absence of lingering
capture processes. Test a trusted certificate and a deliberately mismatched test SNI;
certificate verification must remain enabled. These checks require your actual OS/tools
and have not been performed on your network by this build.

## 6. Record results before publication

For each test, record: version, OS/Python/TShark, exact tool arguments, capture SHA-256,
expected result, observed result, packet evidence and any limitation. Redact credentials
and private evidence before posting issues. Fix incorrect conclusions before stable release.
A truthful public alpha/RC can retain documented unsupported features.

Official setup references:
- https://code.claude.com/docs/en/mcp
- https://modelcontextprotocol.io/docs/develop/connect-local-servers
# Windows shortcut

For normal Windows installation, use `SETUP_WINDOWS.cmd` and
[the setup guide](WINDOWS_SETUP.md). It installs, tests and merges Claude settings
automatically. The manual commands below are for development and troubleshooting.

