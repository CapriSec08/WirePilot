# Changelog

## 1.0.0rc1 — 2026-10-19

- Added SETUP_LINUX.sh with shared Windows/Linux setup, XDG Desktop config discovery,
  explicit host-config selection, Claude Code and config-export modes, root guard,
  package hints and Linux launcher tests. Existing Windows entry point is retained.
- Added a Windows launcher that finds the project directory, checks dependencies,
  installs into a private environment, tests real MCP/PCAP operation with a deadline,
  and merges Claude settings with a backup. Native Windows acceptance is pending.
- Added 20 evidence/investigation tools: paged frame/time queries, repeated-value
  packet metadata, authentication outcomes, engineering metrics, timeline, baseline
  comparison, combined triage, CTF searches/decoding/credentials/HTTP recovery,
  controlled capture imports, JSON-lines event import/correlation, case pagination and validated protocol-field discovery/queries.
- Added general and CTF MCP prompts, readable reports and Claude configuration generation.
- Added FTP/SMB/CTF/PCAPNG/IPv6 synthetic lab fixtures and integration checks.
- Added release packaging, MIT licence, security/contribution guidance and CI definitions.
- Hardened subprocess group termination, evidence checks, input bounds and report escaping.
- Improved coverage with an unfiltered sentinel and next-frame continuation.

This is a release candidate pending the user's actual Claude/OS tests. It does not
implement vendor device APIs, a learned anomaly engine, NetFlow, remote service
authentication or an executed VeloPilot integration. It does not certify absence of attacks.

## 0.2.0

Added bounded capture adapters, tool discovery, capinfos, DNS/ping/path diagnostics.

## 0.1.0

Initial MCP, packet triage, cases, local diagnostics and reports.
