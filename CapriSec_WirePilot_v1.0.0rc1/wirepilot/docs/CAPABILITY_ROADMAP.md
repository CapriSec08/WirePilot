# Capability status for 1.0.0rc1

The scope is a provider-independent local evidence MCP. Capability is measured by
reproducible investigations and correct qualifications, not the number of tools.

| Area | Implemented | Remaining scope |
| --- | --- | --- |
| Capture/evidence | Bounded capture adapters, hashes, controlled import, frame/time windows, reports | User-host capture/permission testing; indexed large-capture store |
| Packet depth | Common metadata and validated installed-TShark field queries; repeated-value packet details | Complete tunnel/compound-message normalization; content beyond the initial prefix |
| DNS/TCP | Errors, states, retransmit/zero-window clues, ACK/DNS timing; resolver/ping/path/TLS adapters | Full DHCP/DNS/PMTUD lab matrix and service-specific SLO diagnosis |
| Authentication | FTP/SMB outcomes, Kerberos errors, qualified HTTP challenges and retries | Additional protocols; robust application-level retry deduplication; decrypted/server-log correlation |
| CTF/content | Flag/literal search, TCP reassembly, plaintext credential inspection, four decoding formats, bounded HTTP/1 recovery | HTTP/2/3, close-delimited bodies, archive/content pipelines, arbitrary encoding discovery |
| Ransomware | Visible SMB writes/metadata, file-name association when available, bursts/admin fan-out and handoff guidance | Representative labelled evaluation and actual VeloPilot endpoint correlation |
| External telemetry | Suricata EVE/Zeek JSON/normalized device JSON-lines; time/address proximity | Zeek TSV, NetFlow/sFlow, vendor-specific log/config parsers |
| Baselines | Descriptive capture-to-capture comparison | Statistical/history-based models and validated anomaly scoring |
| Devices | Local interface/route/neighbour/socket snapshots; normalized device evidence import | Live vendor APIs, SNMP, BGP/OSPF/VRF state, NAT/session/rule explanations |
| VPN/cloud/wireless | Generic packet symptoms only | VPN configuration/rekey, cloud/Kubernetes policy/path and wireless RF telemetry |
| Agent integration | Standard MCP tools/prompts; optional combined triage; Claude setup and smoke client | Actual Claude acceptance; LEON host and VeloPilot transport integration |
| Operations | Cases/notes pagination, local activity records, CI definitions, package metadata | Authenticated multi-user remote service, immutable custody/author attribution |

The next acceptance step is Claude on the user's machine. Platform/feature claims
must follow actual acceptance results. A public RC can document future capabilities;
a stable release must pass every gate corresponding to its advertised scope.
