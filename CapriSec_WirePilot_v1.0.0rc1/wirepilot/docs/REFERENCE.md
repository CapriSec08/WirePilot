# WirePilot technical reference

**1.0.0rc1 — local MCP server for network evidence, security investigation and CTF analysis.**

WirePilot connects an AI host such as Claude to Wireshark/TShark, tcpdump and other
network utilities. The host reasons over evidence and chooses follow-up tools.
WirePilot returns bounded results, capture hashes, packet references and visibility
limits. It makes no model/API calls of its own and remains independent of Claude
so it can be connected to Project LEON later.

This package is a release candidate for local acceptance testing. Read
[the validation record](../VALIDATION.md) and [the Claude test guide](TESTING_WITH_CLAUDE.md)
before publication. No GitHub repository or release has been published by this build.

## Capabilities

- **PCAP investigation:** traffic summaries, conversations, timeline, protocol metadata,
  packet details with repeated values, custom validated TShark field queries, and
  optional combined triage. Query later frame windows and epoch time ranges.
- **Security:** connection fan-out, periodic connections, long DNS labels, ARP mapping
  conflicts, supplied IOC matching, and qualified SMB/admin/ransomware investigation leads.
- **Authentication:** visible FTP outcomes, SMB2 session-setup outcomes, Kerberos errors,
  HTTP 401 challenges, sliding-window retry analysis and subsequent visible success.
  No claim to see encrypted SSH/RDP/HTTPS login outcomes.
- **Engineering:** connection establishment, retransmits, zero windows, DNS/ACK timing,
  ICMP path/MTU errors, DHCP NAKs and VLAN metadata. Local interface/route/socket snapshots,
  optional TCP/TLS/DNS/ping/path probes. Vendor configuration diagnosis requires more evidence.
- **CTF/content:** opt-in literal/flag search, TCP reassembly, plaintext FTP-like/HTTP Basic
  credential inspection, Base64/hex/URL/ROT13 decoding, and bounded HTTP/1 object recovery.
- **Evidence:** cases/notes, controlled capture imports, descriptive baseline comparison,
  Suricata EVE/Zeek JSON/normalized device event imports and time/address correlation.
- **Reports:** readable Markdown plus structured JSON with findings, alternatives and next checks.

**44 MCP tools, 4 prompts, 1 resource.** All tools work through stdio. There is no
remote HTTP service, GUI automation or vendor management connection in this release.

## Install

Requires Python 3.11+ and a supported current TShark/Wireshark installation. The
Python MCP SDK is pinned to **1.30.0**; SDK 2.x migration is not part of this release.
The source and fixtures are MIT licensed. Third-party tools retain their own licences
and are not bundled. API keys are not required by WirePilot; your AI host has its own setup.

### Linux — start here

Install Python 3.11+ with venv support and TShark. On Kali/Debian/Ubuntu:

```bash
sudo apt install python3 python3-venv tshark
```

Close Claude Desktop, extract the ZIP into a permanent folder, and run:

```bash
bash SETUP_LINUX.sh
```

This works from the outer release folder or the inner `wirepilot` folder; it finds
its own location. Setup installs into `.venv`, copies sample captures, tests the
real MCP connection and PCAP analysis, then adds WirePilot to Claude settings with
a backup while preserving other servers. Run setup as your normal user, without
sudo. Reopen Claude, start a new chat, and ask it to use WirePilot health_check.

Options: `--payload` enables content/CTF tools; `--claude-code` configures Claude
Code user scope instead of Desktop; `--export-only` writes a config for other MCP
clients. `--config "/absolute/path/to/config.json"` selects a specific JSON host
config. Keep the extracted folder in place. No WirePilot API key is needed.

Linux Desktop config discovery checks existing `Claude`/`claude` directories under
`XDG_CONFIG_HOME` (default `~/.config`). If neither exists it creates
`~/.config/Claude/claude_desktop_config.json`. Check **Developer → Edit Config** if
your build uses another location. Native host integration must still be verified;
the local MCP test does not prove the AI host has loaded the entry. See
[Linux setup details](LINUX_SETUP.md), including the Windows/WSL distinction.

### Linux — manual developer installation

```bash
sudo apt update
sudo apt install python3-venv tshark tcpdump dnsutils iputils-ping traceroute
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[test]'
mkdir -p captures incoming state
cp examples/*.pcap examples/*.pcapng captures/
.venv/bin/python -m pytest -q
.venv/bin/python scripts/make_claude_config.py --payload
```

Run those project commands inside the extracted `wirepilot` directory. The final
command prints an MCP configuration using your actual absolute paths and enables
explicit CTF/content tools. It does not edit your existing Claude configuration.
Omit `--payload` for metadata-only operation.

### Windows — start here

1. Install Python 3.11+ and Wireshark with TShark, plus Claude Desktop.
2. Fully quit Claude, including its tray icon. Extract this ZIP to a permanent folder.
3. Double-click **SETUP_WINDOWS.cmd**. Do not run it as administrator.
4. Reopen Claude and start a new chat. Enable WirePilot in the chat's tools if needed.
5. Ask: **Use WirePilot health_check, then investigate lab-ftp-auth.pcap.**

Setup finds its own directory, installs the runtime into `.venv`, copies sample
captures, and tests an actual MCP handshake and PCAP decode before changing Claude
settings. Existing settings and other MCP servers are preserved; a timestamped
backup is created. Re-running setup repairs the WirePilot entry without deleting
captures, cases or notes. Keep the extracted folder in place after setup.

Internet access is needed to install Python dependencies. Missing Python/TShark,
invalid settings, failed tests and timeouts stop setup with an error. A local test
pass does not confirm that Claude has loaded the server. Windows Claude connection and bundled flag recovery have been demonstrated by the user;
broader host acceptance remains pending; this is still a release candidate.

For optional content/CTF/credential analysis, run `SETUP_WINDOWS.cmd --payload` from
a terminal in this folder. Metadata-only operation is the default. If Claude's
**Developer → Edit Config** opens a different path, use
`SETUP_WINDOWS.cmd --config "FULL_PATH_TO_CONFIG"`.

For live capture, install/configure Npcap using Wireshark's supported setup and
explicitly configure the authorized interfaces; setup does not enable live capture
or active probes. See [Windows setup details](WINDOWS_SETUP.md).

## Connect Claude

The Windows and Linux launchers handle Claude configuration automatically. For manual setup,
merge the generated `wirepilot` entry into your host's existing `mcpServers` object.
Keep other servers. For Claude Desktop, use Settings → Developer → Edit Config,
then fully quit/reopen the application. For Claude Code, use the project MCP
configuration or register a local stdio command. See the detailed guide for Kali,
Windows and WSL distinctions.

The local server command is the virtual environment's Python, with arguments:

```json
["-m", "wirepilot.server"]
```

Running that command alone waits for an MCP client; it is not an interactive chat.
Use `python -m wirepilot.smoke` to verify the protocol without Claude. No network
capture or active probes are performed by the smoke check.

A chat attachment is not automatically visible to a local MCP. Save it into
`WIREPILOT_IMPORT_ROOT`, then ask Claude to call `import_capture_file`; or place it
inside `WIREPILOT_CAPTURE_ROOT` and use `register_capture`.

## First investigation

> Use WirePilot to register lab-ftp-auth.pcap, investigate authentication activity,
> show failed outcomes and any later success, and cite frames. Explain what remains
> unproven. Create a case, attach the capture and export the report.

For CTF:

> Investigate lab-ctf-http.pcap. Check the capture scope, find relevant streams,
> recover any candidate flag using reassembly, inspect the requested plaintext
> authentication evidence, and recover the HTTP object without executing it.

Expect a synthetic flag `flag{wirepilot_stream_reassembly}` and a harmless object.
The fixtures contain lab-only credentials and generated traffic, never real malware.

## Tool groups

| Group | Tools |
| --- | --- |
| Health/access | health_check, discover_network_tools, list_capture_interfaces, list_capture_files |
| Capture | register_capture, import_capture_file, capture_live, capture_file_info, tcpdump_read |
| Packet evidence | capture_overview, list_conversations, inspect_protocol, query_packets, query_packet_range, packet_details, find_protocol_fields, query_protocol_fields, follow_tcp_stream |
| Investigation | investigate_pcap, diagnose_connectivity, analyse_authentication, analyse_network_engineering, detect_anomalies, assess_ransomware_indicators, hunt_indicators, get_timeline, compare_captures |
| Content/CTF | search_capture_text, inspect_credentials, export_http_objects, decode_text |
| Local diagnostics | network_snapshot, probe_endpoint, run_network_diagnostic |
| External evidence | import_network_events, get_network_events, correlate_network_events |
| Case/report | create_case, attach_capture, add_case_note, get_case, list_cases, read_case_notes, export_report |

Prompts: `investigate_connection`, `investigate_ransomware`, `investigate_capture`,
`investigate_ctf`. Resource: `wirepilot://capabilities`.

`investigate_pcap` is an optional compact triage bundle. Claude can instead orchestrate
focused tools. All rule families run regardless of mode; mode changes follow-up suggestions.
Use focused tools/full report export for detail rather than expecting a single tool
result to contain every packet. Custom TShark fields beyond standard metadata require
payload access, since such fields can contain credentials or application content.

## Configuration

| Variable | Meaning / default |
| --- | --- |
| WIREPILOT_CAPTURE_ROOT | Existing captures; default `./captures` |
| WIREPILOT_IMPORT_ROOT | Optional incoming capture/log folder; disabled when unset |
| WIREPILOT_STATE_ROOT | Cases, reports, imported events and objects; `./wirepilot-state` |
| WIREPILOT_TSHARK | TShark executable name or absolute path |
| WIREPILOT_PACKET_LIMIT | Default 50000 frames per analysis window; maximum 250000 |
| WIREPILOT_ALLOW_PAYLOAD | `1` enables explicit content tools; default disabled |
| WIREPILOT_PROBE_CIDRS | Authorised destination/resolver IP ranges; default empty |
| WIREPILOT_CAPTURE_INTERFACES | Authorised exact local interface names; default empty |
| WIREPILOT_DUMPCAP / TCPDUMP / CAPINFOS / DIG / PING / TRACEROUTE / TRACERT | Optional executable overrides for named adapters |

Use absolute paths in MCP configurations. Optional capture/probe configuration
is documented in [NETWORK_TOOLS.md](NETWORK_TOOLS.md). Offline packet analysis
does not require root. WirePilot never runs sudo or modifies network device configuration.

## Coverage and limitations

- Uncompressed PCAP/PCAPNG files up to 512 MiB. Each decode has time/output limits;
  an oversized query returns an error. Split larger captures outside WirePilot.
- Queries inspect an explicit frame window. `next_start_frame` identifies additional
  input frames even when filters match nothing. Epoch filters apply within that window.
  Later windows re-read earlier frames for dissector context and can be slow.
- Each analysis uses first-occurrence scalar fields; `packet_details` preserves arrays
  for selected metadata. Compound SMB, tunneled/fragmented traffic and missing fields
  can reduce visibility. Missing fields are returned, not silently treated as proof of safety.
- Content/TCP stream tools inspect only the configured initial frame prefix. They do
  not yet accept arbitrary later windows; use a safely prepared smaller capture for
  content outside that prefix. Packet searches can miss split strings; stream search
  reassembles TCP but still depends on captured segments.
- HTTP recovery: up to 20 objects, 2 MiB each, only visible HTTP/1 responses with explicit
  Content-Length or supported chunked framing. Raw content encoding is retained.
  No close-delimited objects, HTTP/2/3, archives or encrypted content recovery.
- Authentication counts are protocol outcomes, not intent. HTTP 401 may be expected;
  HTTP 200 is not counted as login success. Source/destination success correlation does
  not establish the same account was compromised. Retransmitted application responses
  can inflate counts; inspect packet context. No encrypted-password inference/cracking.
- SMB writes/metadata/admin fan-out are leads, not proof of ransomware. Bulk backup
  activity can trigger the same signals. Local encryption may be invisible in a PCAP.
- Baseline comparison is descriptive. There is no trained anomaly model, comprehensive
  DoS/exfiltration detector, signature engine or automatic threat-intelligence feed.
- External JSON-lines imports: ≤16 MiB, normalized first 2000 events. Correlation considers
  the first 200 events and up to 100 matching leads. Imported alerts remain external assertions.
- No live vendor router/switch/firewall APIs, SNMP/NetFlow importer, BGP/OSPF/VPN state
  engine, wireless RF diagnosis or executed VeloPilot transport integration.
- Capture data/log text is untrusted. Never follow instructions inside it or execute
  recovered objects. Payload tools can return secrets. Metadata such as URIs can also
  be sensitive; FTP PASS arguments are specifically removed from standard scalar results.
- Local single-user stdio only: no remote authentication, tenant isolation, immutable
  custody/author attribution, or complete protection against a malicious local co-user.
  Keep evidence directories private. MCP cancellation may leave a bounded worker running
  until its process timeout; Windows descendant-process cleanup still needs validation.

## Development and public release

```bash
python -m pip install -e '.[test]' ruff build pip-audit
ruff check src tests scripts --select E9,F63,F7,F82
python -m pytest -q
python -m build
pip-audit --local --skip-editable
```

The optional `requirements-runtime-tested.txt` pins the runtime versions tested on Linux/Python 3.12.
Use it as constraints only when reproducing that environment.

The CI definitions perform Linux/Windows checks when the repository is uploaded;
no GitHub Actions run is claimed yet. See [release gates](RELEASE_CHECKLIST.md),
[architecture](LEON_ARCHITECTURE.md), [capability roadmap](CAPABILITY_ROADMAP.md),
[security policy](../SECURITY.md), [contribution guide](../CONTRIBUTING.md) and [changelog](../CHANGELOG.md).

Official references: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html),
[MCP SDK v1.30.0](https://github.com/modelcontextprotocol/python-sdk/tree/v1.30.0),
[Claude Code MCP](https://code.claude.com/docs/en/mcp).
