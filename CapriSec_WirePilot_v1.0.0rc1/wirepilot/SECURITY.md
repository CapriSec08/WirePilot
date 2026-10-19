# Security

WirePilot handles network captures, which can contain passwords and other private
information. If you find something that could expose data or allow unintended
actions, please report it privately.

This policy currently covers **1.0.0rc1**, the release candidate.

## Reporting a vulnerability

Use **Security → Report a vulnerability** in this GitHub repository if that option
is available. If it isn't, use a contact method listed on the maintainer's GitHub
profile, or open an issue asking for a private way to get in touch.

Please don't put exploit details, passwords or private captures in a public issue.

A useful report includes:

- The WirePilot version and your OS, Python and TShark versions.
- What could go wrong and the steps needed to reproduce it.
- A small synthetic example, if possible, without anyone's real data.

We'll review reports as we can. There is no guaranteed response time at this stage.

## Using WirePilot

Run WirePilot and your AI assistant as a normal user. It is designed for one user
on a local machine; this release does not provide authentication for remote access.

Keep capture, import and report folders limited to the files you want the assistant
to access. Content tools can reveal credentials when enabled. Live capture and
active probing stay disabled until you configure their allowed interfaces or targets.
Keep Python, Wireshark/TShark and other tools up to date.

Treat capture contents as evidence, including any text that looks like instructions
to an AI. Don't execute recovered files. Your AI host decides whether tool results
are sent to a cloud model, so consider that before using sensitive captures.

WirePilot is an investigation tool. It is not a malware sandbox, and it cannot
guarantee that a capture is safe or that every attack will be detected. The
[technical reference](docs/REFERENCE.md#coverage-and-limitations) explains the limits.

Ordinary bugs, questions and suggestions are welcome in GitHub issues. Thanks for
helping make WirePilot safer and more useful.
