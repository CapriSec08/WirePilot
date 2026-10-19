# Network tools in WirePilot 1.0.0rc1

WirePilot uses installed command-line executables through fixed argument lists.
There is no general-purpose shell tool. Missing executables are reported instead
of silently substituted or installed. The AI host selects an investigation tool;
WirePilot validates its parameters, runs the underlying utility and returns evidence.

## Access and coverage

| Utility | Implemented access | Important boundary |
| --- | --- | --- |
| TShark | Packet decoding, filtering, TCP streams | Wireshark engine; no desktop GUI control |
| dumpcap | Interface listing, bounded live capture | Configured local interfaces and OS capture permissions |
| tcpdump | Interface listing, bounded live capture, offline summaries | Terse metadata output; live capture saves raw bytes |
| capinfos | Full-file capture type/count/timing/size | Metadata operation may time out on a difficult file |
| dig | One DNS query to an explicit resolver IP | Resolver must be in configured probe ranges |
| ping | Three ICMP probes | Linux/Windows argument adapters; ICMP may be filtered |
| traceroute / tracert | Path to one IP, maximum 12 hops | Linux/Windows adapters; not an exhaustive path diagnosis |
| ip / ss | Local Linux interface/route/neighbour/socket snapshot | MCP host only, using tools found on PATH |
| ipconfig / route / arp / netstat | Local Windows snapshot | Windows execution still needs validation |
| ifconfig / arp / netstat | Local macOS snapshot | macOS execution still needs validation |
| Wireshark desktop | Installation discovery only | No GUI automation implemented |

Nmap, mtr, iperf3, ethtool, Zeek, Suricata, SNMP and vendor APIs are potential
future adapters, not capabilities shipped in this version. Some require peers,
additional privileges or more intrusive testing, so each needs its own scope and
test contract. There is no promise to operate every installed network utility.

## Optional installation on Kali/Debian/Ubuntu

```bash
sudo apt install tshark tcpdump dnsutils iputils-ping traceroute
```

Wireshark distributions commonly provide dumpcap and capinfos alongside their
CLI tools; `discover_network_tools` reports the actual installation. On Windows,
install Wireshark/TShark and Npcap as appropriate. dig and tcpdump are not assumed
to exist on Windows; use the dumpcap backend there.

For a non-PATH installation, configure absolute executable paths, for example:

```json
{
  "WIREPILOT_TSHARK": "C:\\Program Files\\Wireshark\\tshark.exe",
  "WIREPILOT_DUMPCAP": "C:\\Program Files\\Wireshark\\dumpcap.exe",
  "WIREPILOT_CAPINFOS": "C:\\Program Files\\Wireshark\\capinfos.exe"
}
```

## Enable only the lab interfaces and targets you intend to investigate

Add environment values to the WirePilot entry in your MCP host configuration.
Replace these example values with your actual authorised local interface and lab range:

```json
{
  "WIREPILOT_CAPTURE_INTERFACES": "eth0",
  "WIREPILOT_PROBE_CIDRS": "192.168.56.0/24"
}
```

Restart the MCP server after changing configuration. `list_capture_interfaces`
can help identify interfaces, but does not grant access. The capture interface
setting is an exact allowlist, not a permission escalation mechanism. Configure
capture permissions using the OS/distribution's supported Wireshark/dumpcap
setup. WirePilot never runs sudo, changes group membership or changes capabilities.
Prefer narrowly scoped capture permissions; do not run the whole AI host as root.

## Bounded live capture

Example tool arguments after configuring the lab interface:

```json
{
  "interface": "eth0",
  "capture_filter": "host 192.168.56.10 and tcp port 443",
  "backend": "dumpcap",
  "duration": 10,
  "packet_count": 1000,
  "snaplen": 512
}
```

The MCP call is `capture_live`. The result includes a registered capture ID, SHA-256,
backend diagnostics and collection parameters. Use that ID with the existing analysis
tools. Limits: 30 seconds requested duration, 20,000 packets, 64–65,535 snapshot bytes,
and a calculated 64 MiB packet/snapshot budget. The supervisor also monitors size
and runtime. Shutdown can take a short grace period; this is not a real-time guarantee.
Only one capture runs at a time per server. No ring-buffer overwrites or indefinite
background jobs are exposed.

Captures use non-promiscuous mode and do not request wireless monitor mode. A BPF
filter is required. A 512-byte snapshot can truncate application evidence; full
snapshots may need a lower packet count to stay within the budget. Raw capture
files can contain sensitive payloads even with stream-display access disabled.
Failure/forced termination is reported; incomplete files may remain for inspection
but are not automatically registered after a failed capture.

## Diagnostics examples

Call `run_network_diagnostic` with one of:

```json
{"operation":"dns","address":"192.168.56.53","name":"app.example.test","record_type":"A"}
```

```json
{"operation":"ping","address":"192.168.56.10"}
```

```json
{"operation":"trace","address":"192.168.56.10"}
```

These actions send network traffic. For DNS, the authorised address is the resolver;
it may contact other DNS infrastructure according to its own configuration. The
queries accept domain names, not arbitrary dig arguments. Path probes target the
configured destination but traverse and elicit responses from intermediate devices.
Do not treat a timeout as proof of a broken link; compare ICMP/firewall policy and
other evidence. Output is retained as utility text, not a guaranteed root cause.

## Evidence status

Read `VALIDATION.md` before interpreting the test count. Live-capture supervision
is tested with an offline fixture process; packet capture permissions and raw
network access must be verified on the user's machine. No user network has been
captured or probed during development.

Official references:
- https://www.wireshark.org/docs/man-pages/tshark.html
- https://www.wireshark.org/docs/man-pages/dumpcap.html
- https://www.wireshark.org/docs/man-pages/capinfos.html
- https://www.tcpdump.org/manpages/tcpdump.1.html
- https://bind9.readthedocs.io/en/latest/manpages.html
