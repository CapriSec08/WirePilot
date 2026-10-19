# CapriSec WirePilot

WirePilot lets you explore network traffic by talking to your AI assistant. Connect
it to Claude or another MCP client to work through packet captures, troubleshoot
connection problems, investigate suspicious activity, or hunt for CTF flags.

It uses tools such as TShark and tcpdump and returns packet references so you can
check the findings yourself. Built by CapriSec as part of Project LEON.

**Version: 1.0.0rc1 — release candidate.**

## Getting started

Install **Python 3.11+**, **Wireshark with TShark**, and your preferred MCP client.
WirePilot does not need an API key of its own. Your AI assistant has its own login
or model setup. Internet access is needed to install Python dependencies.

Download and extract the full release ZIP into a folder you plan to keep. Close
Claude before running setup.

### Windows

Double-click **SETUP_WINDOWS.cmd**. Once it finishes, reopen Claude Desktop and
start a new chat. No administrator access is needed for setup.

### Linux

On Kali, Debian or Ubuntu, install the prerequisites:

```bash
sudo apt install python3 python3-venv tshark
```

Open a terminal in the extracted folder and run:

```bash
bash SETUP_LINUX.sh
```

Run setup without sudo, then reopen Claude Desktop.

Using Claude Code on Linux instead? Run:

```bash
bash SETUP_LINUX.sh --claude-code
```

Start a new session and check `/mcp`.

Both shortcuts install WirePilot, prepare sample captures, run a local connection
and PCAP test, and update Claude's configuration. They back up the config and keep
other MCP servers. Keep the extracted folder in place after setup.

## Try it out

Ask your assistant:

> Use WirePilot health_check, then investigate lab-ftp-auth.pcap. Show failed
> logins and any later success, with packet references.

For flags and visible credentials, enable the optional content tools by rerunning
setup from a terminal:

Windows PowerShell:

```powershell
.\SETUP_WINDOWS.cmd --payload
```

Linux:

```bash
bash SETUP_LINUX.sh --payload
```

For Claude Code, add `--claude-code` too. Restart your assistant, then ask:

> Investigate lab-ctf-http.pcap with WirePilot. Reassemble the TCP streams and
> find the flag and any visible credentials. Show the supporting packets.

To use your own capture, put it in the project's `captures` folder. A chat
attachment is not automatically available to the local server.

## What to expect

WirePilot helps you investigate; its findings still need your judgement. A
suspicious pattern alone does not prove an attack, and encrypted traffic may hide
the details you need. Live capture and active probing need explicit configuration.

WirePilot makes no AI API calls itself. Your assistant controls whether evidence
is sent to a cloud model. Windows Claude connection and the sample flag test have
been demonstrated; Linux host integration still needs user testing.

## Tell us what you think

Suggestions, questions, bugs and complaints are all welcome. Open a GitHub issue
in this repository and tell us what worked, what didn't, or what you'd like to see.
For bugs, include your OS, steps to reproduce and the error message, with private
data removed. For security issues, use the private route in [SECURITY.md](SECURITY.md).

Want to help improve it? See [CONTRIBUTING.md](CONTRIBUTING.md).

## More details

[Windows help](docs/WINDOWS_SETUP.md) · [Linux help](docs/LINUX_SETUP.md) ·
[Technical reference](docs/REFERENCE.md) · [Testing](VALIDATION.md)

Licensed under [MIT](LICENSE).
