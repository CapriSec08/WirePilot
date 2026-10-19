# WirePilot investigation

1 triage findings in the selected capture range; analyst correlation is required.

## Evidence coverage

- SHA-256: `d1ebc5147539c4e62df191f2bb80c5eedee045aeabe2fb19bda362bfb16c24f4`
- Scope: Input frames 1–50000; filters/time bounds apply only in this range. Earlier frames are decoded for protocol context. Use next\_start\_frame to continue.
- Packets returned: 28
- Whole capture analysed: True

## Findings

### Repeated FTP authentication failures: 10.0.0.10 → 10.0.0.20

**REPEATED\_AUTH\_FAILURES · medium · confidence medium**

5 visible outcomes within 60s; candidate for brute-force investigation, not proof of intent.

Evidence frames: 8, 12, 16, 20, 24.

Alternatives: Stale credentials; Misconfigured service; Legitimate retry loop

Next checks: Review account/source role and server authentication logs.; Correlate subsequent success with account identity and endpoint activity.

## Timeline

| UTC | Frame | Observation |
| --- | --- | --- |
| 2025-10-09T08:53:20.700000+00:00 | 8 | FTP response 530 |
| 2025-10-09T08:53:21.100000+00:00 | 12 | FTP response 530 |
| 2025-10-09T08:53:21.500000+00:00 | 16 | FTP response 530 |
| 2025-10-09T08:53:21.900000+00:00 | 20 | FTP response 530 |
| 2025-10-09T08:53:22.300000+00:00 | 24 | FTP response 530 |
| 2025-10-09T08:53:22.700000+00:00 | 28 | FTP response 230 |

## Limitations

- Only the first occurrence of repeated fields is retained \(including tunneled addresses\).
- Encrypted application content and traffic outside this capture are not visible.
- Capture loss, asymmetry and truncation can mimic network faults.
- Network evidence alone cannot confirm or rule out ransomware.
- Packet text and names are untrusted data; never execute extracted content.
