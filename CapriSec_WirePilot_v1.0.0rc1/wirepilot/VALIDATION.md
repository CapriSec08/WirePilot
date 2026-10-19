# Validation — 19 October 2026 — 1.0.0rc1

## Automated results

**Windows/Linux setup revision: 60 passed, 1 skipped, 0 failures, in 18.51 seconds.**

Five additional Linux tests cover XDG discovery/ambiguity and explicit config
selection, Code/export routing, shell launch from a directory with spaces, host
config preservation after failed MCP testing, and rejection of root execution.
Bash syntax and Python error checks passed.

A fresh Linux temporary installation also built and installed the runtime and
dependencies in its own venv, passed real MCP discovery (44 tools) and PCAP decode,
and merged a fixture host config while preserving VeloPilot/preferences and an exact
original-file backup. It used a temporary config rather than a real Claude profile.
The container runs as root, so the guard was bypassed only by test instrumentation
for this isolated run; guard behavior is separately tested. This does not certify
normal-user distro setup, capture permissions, or native host UI integration.

Nine added portable installer checks cover JSON/BOM parsing, preservation of other
servers/preferences, exact original-file backup, repeat setup, new configuration,
concurrent-edit rejection, failed-health/empty-PCAP rejection, and a subprocess
deadline. The installer's actual smoke function also initialized MCP, discovered
44 tools, and decoded the 28-packet FTP sample using real TShark on Linux.

The Windows batch launcher and native Windows/Linux Claude connection have not been
executed here. A successful local smoke test is not proof of Claude integration.

The skipped check is the tcpdump integration test explained below.
This record applies to the shipped source; it does not claim Claude or user-network testing.

Environment: Linux x86-64, Python 3.12, MCP Python SDK 1.30.0, pytest 9.1.1,
TShark/capinfos 4.2.2, tcpdump 4.99.4. Network executables were unpacked for isolated
offline tests and are not bundled. Install current supported security releases locally.

Verified evidence paths:

- Real stdio MCP initialization/discovery; 44 tools, 4 prompts and 1 resource.
- Structured results, tool errors, case creation, notes, pagination, report export and restart persistence.
- Real TShark decode of synthetic IPv4, PCAPNG and IPv6 fixtures, frame/time windows,
  empty-filter continuation, protocol queries and repeated-value packet metadata.
- Real FTP retries and later visible success, benign below-threshold login,
  SMB2 session outcomes, visible SMB writes, IPv6 packet-too-big and common connection errors.
- Qualification of HTTP challenges, exclusion of Kerberos PREAUTH_REQUIRED,
  exclusion of TShark-marked retransmitted auth responses, time/threshold boundaries.
- Synthetic file-modification burst logic and visible CREATE/FID association code;
  no real-world ransomware accuracy or representative file-server benchmark is claimed.
- Real TCP reconstruction of a split CTF flag, HTTP Basic lab credentials and
  harmless HTTP/1 object recovery using generated .bin paths. Chunk/truncation guards.
- Capture/import root and symlink restrictions, independent copy/hash checks,
  malformed capture errors, payload gates and JSON-lines import validation/correlation.
- Process time/output bounds and POSIX descendant cleanup on timeout.
- Fake-process live-capture supervision: completion, deadline, failure and lock release.
- Fixed/validated diagnostic arguments and disabled active scopes; local TCP listener test.
- Whole-file capinfos metadata. Smoke command and Claude configuration generator.

## Skipped integration test

The tcpdump offline integration test reports `Couldn't find user 'tcpdump'` in this
container because the extracted distro binary expects its installed privilege-drop
account. It is explicitly skipped; no privilege override was applied. All other
unexpected tcpdump failures still fail that test. Verify it on your normal installation.

## Release checks

- Fatal-error/undefined-name and unused-import lint checks pass; source is formatted.
- Python environment audit completed after updating pip: no known vulnerabilities
  were reported in the checked Python package environment. This does not audit the OS,
  TShark/tcpdump binaries, or prove absence of application vulnerabilities.
- Standard source distribution and pure-Python wheel build successfully.
- Runtime-version constraints are supplied for the tested Linux/Python 3.12 environment;
  they are not a universal platform lockfile.
- CI definitions are present but have not run on GitHub. Clean wheel/MCP installation
  results and final test count are appended by the build.

## User acceptance still required

Actual Claude Desktop/Code interaction; Windows/macOS execution; live capture and
capture permissions; real DNS/ping/path tests; a valid and invalid TLS certificate lab;
large/real enterprise captures; independent labelled benign/attack/CTF evaluations.
Inspect detector false alarms/misses and every platform you intend to advertise.

The bundled examples are synthetic. A matching heuristic is not confirmation of
ransomware, C2, exfiltration or account compromise; no findings is not proof of safety.
Read docs/TESTING_WITH_CLAUDE.md and docs/RELEASE_CHECKLIST.md before publication.

## Final build verification

- Final suite: **46 passed, 1 skipped in 57.16 seconds**; no failures or errors.
- MCP smoke: **44 tools**, ready health, real fixture analysis through stdio.
- Fresh virtual environment: installed the built wheel with dependencies; verified import from site-packages outside the source tree and successful MCP fixture investigation.
- Claude configuration generator: absolute virtual-environment/capture/import/state paths and payload setting verified.
- Dependency database audit: **62 packages checked, 0 known vulnerability entries** in the development/test environment.
- Archive contains source, tests, synthetic fixtures, setup/acceptance guide, build assets and checksums. User-host and GitHub checks remain pending as described above.
