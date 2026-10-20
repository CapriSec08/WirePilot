
<p align="center">
  <img src="./wirepilot.png" alt="WirePilot by CapriSec — Network investigation through MCP" width="100%">
</p>

WirePilot lets you investigate network traffic by talking to your AI assistant.
Ask it to explain a packet capture, investigate a failed connection, look into
suspicious traffic, or find a CTF flag. It uses tools such as TShark and tcpdump
and returns packet references so you can check the evidence.

Built by **CapriSec** as part of **Project LEON**. **Version: 1.0.0rc1 — release candidate.**

## **What can I do with it?**

- Read PCAP and PCAPNG files and see which hosts and protocols are involved.
- Inspect packets, filter traffic and reconstruct TCP conversations.
- Investigate DNS problems, failed connections and retransmissions.
- Examine visible login failures, repeated attempts and later success.
- Look into unusual traffic and possible ransomware indicators.
- Find CTF flags and visible plaintext credentials when content access is enabled.
- Decode common encodings and recover supported HTTP/1 response files.
- Build timelines, keep investigation notes and export reports.
- Use live capture and network probes after explicitly configuring their allowed scope.

There are **44 MCP tools**. Findings are investigation leads, not proof of an
attack. What WirePilot can establish depends on the traffic actually captured.

## **Start here: choose one route**

You do **not** need to follow every section below. Pick the app you want to use.

| I want to use… | Start here | Status with WirePilot |
| --- | --- | --- |
| Claude Desktop | [Route A](#route-a-claude-desktop) — automatic setup | Windows connection and sample flag recovery demonstrated; Linux app pending |
| Claude Code | [Route B](#route-b-claude-code) | Instructions provided; host test pending |
| Ollama | [Route C](#route-c-ollama-or-deepseek-with-cline) — use an MCP app such as Cline | Instructions provided; not tested |
| DeepSeek API | [Route C](#route-c-ollama-or-deepseek-with-cline) — use an MCP app such as Cline | Instructions provided; not tested |
| Hermes Agent | [Route D](#route-d-hermes-agent) | Configuration based on Hermes docs; not tested |
| OpenClaw | [Route E](#route-e-openclaw) | Configuration based on OpenClaw docs; not tested |
| ChatGPT | [Route F](#route-f-chatgpt) — separate tunnel setup | Advanced route; not bundled or tested |
| Another MCP app | [Other clients](#other-mcp-clients) | Depends on that app's local MCP support |

**A quick explanation:** WirePilot supplies the network tools. Your **MCP client**
is the app that starts WirePilot and lets an AI model use those tools. **Ollama**
runs models; **DeepSeek** provides models/API access. They still need a suitable
client to use WirePilot. MCP over **stdio** simply means the client starts a local
program and exchanges messages with it.

WirePilot has no AI API key. Your chosen app/provider may need a login, an API key
or paid usage. With a cloud model, tool results can be sent to that provider.

## **1. Install the prerequisites**

### ***Windows***

1. Install **Python 3.11 or newer** from [python.org](https://www.python.org/downloads/windows/).
   Enable the Python launcher and the option to add Python to PATH if offered.
2. Install [Wireshark](https://www.wireshark.org/download.html), including **TShark**.
   Npcap is needed for live packet capture, but not for reading saved captures.
3. **Install your chosen AI app separately.**
4. Open a **new PowerShell window** and check Python:

```powershell
py -3 --version
```

It should report Python 3.11 or newer. With Wireshark in its usual location, check:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" --version
```

If you installed Wireshark elsewhere, use its actual path. Fix a missing prerequisite
before continuing.

### ***Linux***

On Kali, Debian or Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv tshark
```

Then check:

```bash
python3 --version
tshark --version
```

Python must be 3.11 or newer. Other distributions need their equivalent packages;
see [Linux help](docs/LINUX_SETUP.md). *Run WirePilot setup as your normal user,
without sudo.* The commands using sudo above are only for installing OS packages.

## **2. Download and extract WirePilot**

1. Download the release ZIP from this repository's **Releases** page, if published,
   or download the repository using **Code → Download ZIP**.
2. **Extract the whole ZIP.** Do not run setup from inside an unopened ZIP.
3. **Put it somewhere you plan to keep it, such as a Projects folder.**

**If you use Claude Desktop, go to [Route A](#route-a-claude-desktop). For other
local apps, follow [Install without Claude](#install-without-claude-windows-and-linux)
first.** The default double-click setup is for Claude Desktop; it is not a universal
client installer.

The release ZIP has shortcuts in its first folder. Inside `wirepilot`, you should
also find `README.md`, `pyproject.toml`, `scripts` and `examples`. A repository ZIP
may put these files directly in its extracted project folder.

**Keep this folder after setup.** The client launches WirePilot from it. If you
move it later, update the client configuration or rerun setup from the new location.
Do not copy a Windows `.venv` to Linux or the other way round.

## **Install without Claude: Windows and Linux**

**Using Ollama, DeepSeek, Hermes, OpenClaw or another MCP app? Start here.**
You do not need Claude installed, a Claude account or a Claude API key.

These steps install WirePilot locally and generate settings for the client you
choose. They do not change Claude's configuration. If WirePilot is already installed
in this same folder, skip the venv/pip commands and generate the configuration.

Follow this section once, then choose your client below:

- [Ollama or DeepSeek with Cline](#route-c-ollama-or-deepseek-with-cline)
- [Hermes Agent](#route-d-hermes-agent)
- [OpenClaw](#route-e-openclaw)
- [Another local MCP app](#other-mcp-clients)

ChatGPT uses a separate advanced connection route; see [Route F](#route-f-chatgpt).

### ***Step 1: open the terminal in the right folder***

Find the folder containing **`pyproject.toml`**.

- **Windows:** open that folder in File Explorer, click the address bar, type
  `powershell`, and press Enter. Run `Get-Item .\pyproject.toml` to check.
- **Linux:** open a terminal in that folder and run `ls pyproject.toml` to check.

If the file is missing, open the inner project folder first. Do not run the
installation command from `C:\Windows\System32`, your home folder, or the outer
release folder without `pyproject.toml`.

### ***Step 2: install WirePilot and generate your configuration***

**Windows PowerShell — run these commands one at a time:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe scripts\make_claude_config.py | Set-Content -Encoding UTF8 .\mcp-config.json
Copy-Item .\examples\*.pcap .\captures\
Copy-Item .\examples\*.pcapng .\captures\
notepad .\mcp-config.json
```

**Linux:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python scripts/make_claude_config.py > mcp-config.json
cp examples/*.pcap examples/*.pcapng captures/
cat mcp-config.json
```

Stop if any command fails. The last commands show your **MCP configuration**: a
small JSON document telling the client which program to launch and which folders
to use. Despite its filename, `make_claude_config.py` can generate settings for
other clients too. It creates the capture directories but does not edit host settings.

`.venv` is WirePilot's private Python environment. Use the Python inside it in
client settings, rather than a bare `python` command.

Linux users can alternatively run `bash SETUP_LINUX.sh --export-only` to install,
test and write `mcp-config.json` without changing Claude's configuration.
That export shortcut is not currently available on Windows.

### ***Step 3: add the generated settings to your chosen app***

Your generated file has this structure. The text below is an explanation, not a
configuration to paste — **use the real values from your own `mcp-config.json`**:

| Field | What it means |
| --- | --- |
| `mcpServers` | The list of servers; some clients use a different outer key |
| `wirepilot` | The name of this server |
| `command` | The full path to WirePilot's `.venv` Python |
| `args` | The two arguments `-m` and `wirepilot.server` |
| `env` | The capture, import, state and TShark paths, plus feature settings |

After adding the settings, enable WirePilot in that app and ask:

> Use WirePilot's health_check and report whether TShark is working.

Look for an actual WirePilot tool call and a `ready` result. The app-specific
sections below explain where to put the settings. Then use the bundled FTP and
flag tests in [your first investigation](#your-first-investigation).

Keep **all** the generated `env` values. Copying only the command can cause the
server to use the wrong capture folder or fail to find TShark.

## **Route A: Claude Desktop**

This is the route with an automatic Desktop configuration shortcut. Close Claude
completely before starting, including its system tray icon on Windows.

### ***Windows***

1. **Open the extracted folder in File Explorer.**
2. Double-click **SETUP_WINDOWS.cmd**. Do not run it as administrator.
3. **Wait for setup to finish. It installs dependencies, prepares sample captures,**
   tests WirePilot and TShark together, then adds WirePilot to Claude's configuration.
4. Look for **MCP ready** and **Local test passed**. If setup says **SETUP FAILED**,
   stop and use the [troubleshooting table](#if-something-goes-wrong).
5. **Reopen Claude Desktop, start a new chat, and enable WirePilot in its tools if needed.**

### ***Linux***

1. **Open a terminal in the extracted folder containing `SETUP_LINUX.sh`.**
2. **Run:**

```bash
bash SETUP_LINUX.sh
```

3. Wait for **MCP ready** and **Local test passed**.
4. **Reopen Claude Desktop and start a new chat. Enable WirePilot's tools if needed.**

Both shortcuts back up the host configuration and preserve other MCP servers.
A local test pass confirms the server works; you must still check the client connection.

### ***Check the connection***

Send this in Claude:

> Use WirePilot's health_check. Tell me whether it is ready and whether TShark works.

Expect a tool call and a result reporting `ready`. If Claude says WirePilot is not
connected, look in **Settings → Developer** for the server and any error.
See [Windows help](docs/WINDOWS_SETUP.md) or [Linux help](docs/LINUX_SETUP.md).

Then continue to [your first investigation](#your-first-investigation).

## **Route B: Claude Code**

Install Claude Code and complete its own sign-in first.

**Linux:** close existing Code sessions, then run this from the extracted folder:

```bash
bash SETUP_LINUX.sh --claude-code
```

Start a new session and enter `/mcp`. Check WirePilot, then ask it to call `health_check`.

**Windows/manual registration:** complete the manual installation above. Claude
Code's `mcp add-json` command accepts the **server object inside**
`mcpServers.wirepilot`, rather than the whole file. Follow the
[official registration guide](https://code.claude.com/docs/en/mcp#add-mcp-servers-from-json-configuration)
for your shell's quoting and user scope. Keep `command`, `args` and `env` together.
There is no Windows Claude Code shortcut in this release; the double-click launcher
configures Desktop. If an entry already exists, back it up before replacing it.

## **Route C: Ollama or DeepSeek with Cline**

**No Claude installation is required.** First complete
[Install without Claude](#install-without-claude-windows-and-linux), then follow
one provider setup below and the shared Cline connection steps.

Cline is one example of an app that supports both model providers and local MCP
servers. These steps use its VS Code extension. Other suitable clients can work too.

### ***First, choose the model provider***

Install [VS Code](https://code.visualstudio.com/) and the Cline extension. Open
Cline's panel and its settings.

**For Ollama:**

1. **Install and start [Ollama](https://ollama.com/).**
2. **Choose and download a model that supports tool use and fits your hardware.**
   Use the `ollama pull` command given on that model's official page.
3. In Cline's provider settings, select **Ollama**.
4. **Set its local model URL to `http://localhost:11434` and select your downloaded model.**

The Ollama URL is for the model, not WirePilot. An ordinary `ollama run` chat does
not automatically connect MCP tools.

**For the DeepSeek API:**

1. **Sign in to [DeepSeek's platform](https://platform.deepseek.com/) and create an API key.**
2. In Cline's provider settings, select **DeepSeek**.
3. **Put the key in Cline's provider field and select a supported model.**

This is a cloud API route and may incur charges. Keep the key out of GitHub and
WirePilot's sample files. If you run a DeepSeek-derived local model through Ollama,
use the Ollama steps and check that particular model's tool support.

### ***Next, connect WirePilot to Cline***

1. **Complete the [manual installation](#install-without-claude-windows-and-linux).**
2. In Cline's panel, click **MCP Servers**, open **Configure**, then choose
   **Configure MCP Servers**. It opens the client's JSON settings.
3. **Back up those settings before editing.**
4. **If no servers are configured, use the full JSON from your `mcp-config.json`.**
   If other servers exist, copy only the `"wirepilot": { ... }` entry into the
   existing `mcpServers` object, separated from adjacent entries by a comma.
   Do not paste the `...` shown in this explanation.
5. **Save. Enable/restart WirePilot in Cline's MCP panel if needed.**
6. **Confirm its tools appear, then ask Cline to call `health_check`.**

Do not create two separate `mcpServers` keys or delete your existing servers.
If the editor reports a JSON error, correct it before continuing.

> **Success:** Cline actually calls WirePilot and receives `ready`. An answer about
what WirePilot might do, without a tool call, is not a connection test.

References: [Cline MCP](https://docs.cline.bot/mcp/mcp-overview),
[local models](https://docs.cline.bot/running-models-locally/overview),
[DeepSeek](https://docs.cline.bot/provider-config/deepseek).

## **Route D: Hermes Agent**

**No Claude installation is required. This route has not been tested with WirePilot.**

1. **Install Hermes Agent and configure its model provider using the**
   [Hermes documentation](https://hermes-agent.nousresearch.com/).
2. **Complete WirePilot's manual installation and open your `mcp-config.json`.**
3. **Back up `~/.hermes/config.yaml`. Here `~` means your home directory.**
4. **Add `wirepilot` under its `mcp_servers` section. Hermes uses YAML, not the**
   generator's JSON format. Convert the generated `command`, `args` and every
   `env` value to the corresponding YAML fields.

For example, this illustrates a **Linux** layout. Replace every example path with
your generated value; the example will not work unchanged:

```yaml
mcp_servers:
  wirepilot:
    command: "/home/YOUR_USER/Projects/wirepilot/.venv/bin/python"
    args: ["-m", "wirepilot.server"]
    env:
      WIREPILOT_CAPTURE_ROOT: "/home/YOUR_USER/Projects/wirepilot/captures"
      WIREPILOT_IMPORT_ROOT: "/home/YOUR_USER/Projects/wirepilot/incoming"
      WIREPILOT_STATE_ROOT: "/home/YOUR_USER/Projects/wirepilot/state"
      WIREPILOT_TSHARK: "/usr/bin/tshark"
      WIREPILOT_ALLOW_PAYLOAD: "0"
```

Keep any extra generated tool paths too. If `mcp_servers` already exists, add only
the `wirepilot` block beneath it. Use spaces for YAML indentation. Save, restart
Hermes with `hermes chat`, and ask it to call WirePilot's `health_check`.
Hermes may prefix tool names, for example `mcp_wirepilot_health_check`.

Source: [Hermes MCP guide](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp).
These are configuration instructions, not a claim of a successful WirePilot test.

## **Route E: OpenClaw**

**No Claude installation is required. This route has not been tested with WirePilot.**

1. **Install OpenClaw and configure its model provider following its own docs.**
2. **Complete WirePilot's manual installation and open `mcp-config.json`.**
3. **Open OpenClaw's Control UI MCP settings at `/settings/mcp` (also `/mcp` in the**
   current docs). Add an outbound local **stdio** server named `wirepilot`.
4. **Use the generated `command`, `args` and `env` in OpenClaw's server definition.**
   OpenClaw's managed registry is `mcp.servers`, not the generated `mcpServers` wrapper.
5. **Save and enable the server using your version's MCP settings. Verify that the**
   selected agent runtime allows MCP tools, then start a new session and request
   WirePilot's `health_check`.

For CLI configuration and a live connection probe, use the
[managed-server guide](https://docs.openclaw.ai/cli/mcp/registry). It distinguishes
saved configuration from a successful connection. CLI mutations and probes in the
current docs require stopping the local Gateway first; use the Control UI for
supported changes while it runs.

`openclaw mcp serve` exposes OpenClaw itself as a server; it is not the command for
connecting WirePilot. Older mcporter-based setups use a separate registry. Follow
your installed version's docs rather than mixing the two formats.

Sources: [OpenClaw MCP](https://docs.openclaw.ai/cli/mcp) and
[managed servers](https://docs.openclaw.ai/cli/mcp/registry).

## **Route F: ChatGPT**

<details>
<summary>Open the advanced ChatGPT route — separate setup, not bundled or tested</summary>

ChatGPT's custom MCP screen does not accept a local Python command. OpenAI documents
**Secure MCP Tunnel** for private MCP servers, including stdio servers.

1. **Check access to custom MCP connections and Platform tunnel permissions for your**
   account/workspace. If unavailable, choose a local client route instead.
2. **Complete WirePilot's manual installation.**
3. **Follow the [official tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)**
   to install `tunnel-client`, create a tunnel and configure a local stdio profile.
4. **Use your generated Python `command`, `args` and `env` values for the profile's**
   server process. The server must see its capture, import, state and TShark paths.
5. **Verify the profile with `tunnel-client doctor --profile wirepilot --explain`, then**
   keep `tunnel-client run --profile wirepilot` running. Substitute your real profile
   name if different.
6. In ChatGPT's custom MCP/plugin flow, choose **Tunnel**, select the tunnel, complete
   authentication and tool discovery, then enable it in a conversation.
7. **Ask ChatGPT to call `health_check`.**

Use [OpenAI's current connection instructions](https://developers.openai.com/api/docs/guides/custom-mcp-server)
for account availability and UI details. WirePilot does not include this tunnel or
an HTTP service. This route is not a tested beginner shortcut or a public plugin
release. Uploading a capture to a normal ChatGPT chat does not start WirePilot.

</details>

## **Other MCP clients**

Complete the manual installation. In your app's local MCP settings, use the
`command`, `args` and all `env` fields from `mcp-config.json`. Choose **stdio/local**,
not an HTTP server URL. Adapt the outer wrapper to the app's required format.

Choose the model/provider in that app separately, enable WirePilot, and call
`health_check`. A client can support MCP while a particular model struggles with
tool use, so verify with a small sample first.

## **Your first investigation**

### ***Test 1: connection and authentication evidence***

The shortcuts and manual steps above put the sample files in `captures`.
Ask your connected assistant:

> Use WirePilot to register lab-ftp-auth.pcap. Investigate the authentication
> attempts. Identify failed logins and any later success, citing packet frames.
> Separate observed evidence from assumptions.

> **Expected result:** five failed FTP logins, then visible success for `analyst`.

### ***Test 2: flag recovery***

Content tools are **off by default**. To enable them for this lab, close the client
and rerun the matching setup command from the extracted folder:

| Setup | Command |
| --- | --- |
| Windows Claude Desktop, in PowerShell | `.\SETUP_WINDOWS.cmd --payload` |
| Linux Claude Desktop | `bash SETUP_LINUX.sh --payload` |
| Linux Claude Code | `bash SETUP_LINUX.sh --claude-code --payload` |
| Linux config export | `bash SETUP_LINUX.sh --export-only --payload` |

For manual clients, regenerate the file with payload access:

Windows PowerShell, in the folder containing `pyproject.toml`:

```powershell
.\.venv\Scripts\python.exe scripts\make_claude_config.py --payload | Set-Content -Encoding UTF8 .\mcp-config.json
```

Linux:

```bash
.venv/bin/python scripts/make_claude_config.py --payload > mcp-config.json
```

Update the client's WirePilot entry with those new settings, preserving other
servers. For Hermes/OpenClaw, update the corresponding environment setting in that
client's format. Restart the client/server, then ask:

> Use WirePilot to investigate lab-ctf-http.pcap. Reassemble the TCP streams, find
> the flag and any visible credentials, and show the supporting packets.

> **Expected result:** `flag{wirepilot_stream_reassembly}`, username `lab`, password `test-only`.
The PCAPNG version of the same lab is also included.

A passing sample is a useful integration check, not a guarantee of accuracy on
all captures or attacks.

## **Use your own capture**

1. Save or copy your `.pcap` or `.pcapng` file into the inner project's **captures** folder.
2. Ask: **Use WirePilot to register my-capture.pcapng and summarise its traffic.**
   Replace the filename with yours.
3. **Ask follow-up questions and request packet references.**

A file attached to the chat is not automatically on the machine running WirePilot.
With a tunnel or remote host, put it in the capture folder on the **server machine**.
The `incoming` folder is for the configured capture/event import tools. The `state`
folder holds case data and reports.

## **If something goes wrong**

| What you see | What to do |
| --- | --- |
| Python command not found | Install Python/launcher, then open a new terminal. On Windows try `py -3 --version`. |
| No `pyproject.toml` / not a Python project | Open the inner project folder, check the file exists, then run the commands again. |
| TShark missing | Install Wireshark with TShark, check its actual path, or set `WIREPILOT_TSHARK` before generating config. |
| Linux venv/ensurepip error | Install your distribution's Python venv package, then rerun setup. |
| WirePilot is not connected | Restart the client, check its MCP panel/logs, and confirm it saved the server definition. |
| Tools do not appear in a resource list | Check the tool list or call `health_check`; tools and resources are different MCP features. |
| The assistant keeps answering without tools | Explicitly request WirePilot `health_check` and confirm a real tool call. Check the selected model's tool support. |
| Flag/content tool disabled | Enable payload access, update the client entry, then restart the server. |
| Capture not found | Check `WIREPILOT_CAPTURE_ROOT` in the client config and put the file there. |
| JSON settings error | Restore the backup or fix commas/brackets. Keep one outer server-list key and preserve existing entries. |
| A terminal running `wirepilot.server` waits silently | Normal: it waits for an MCP client. Add it to your client instead of treating it as a chat program. |
| Live capture or probes denied | These need explicit allowed interfaces/targets. Offline sample analysis does not need them. |

Don't keep going after an installation error. Copy the first useful error and
check the relevant [Windows](docs/WINDOWS_SETUP.md) or [Linux](docs/LINUX_SETUP.md)
guide. To report a bug, include your OS, client, command and error, with private data removed.

## **What has been tested?**

The automated validation record reports **60 passed, 1 skipped**. Local MCP/PCAP
operation and a fresh isolated Linux installation were checked. A user demonstrated
Windows Claude connection and bundled flag recovery. Other host combinations,
including Hermes/OpenClaw, still need testing. See [VALIDATION.md](VALIDATION.md)
for scope and limitations. A saved config is not the same as a working connection.

WirePilot uses Wireshark's command-line tools, not GUI automation. Encryption or
missing packets can hide evidence. WirePilot itself makes no model API calls;
your client's provider settings decide where tool results are processed.

## **Feedback is welcome**

Have a suggestion, question, bug or complaint? Open a GitHub issue in this repository.
Tell us what you tried and what you'd like to improve. Contributions are welcome:
see [CONTRIBUTING.md](CONTRIBUTING.md). Report security vulnerabilities privately
using [SECURITY.md](SECURITY.md).

[Technical reference](docs/REFERENCE.md) · [Windows help](docs/WINDOWS_SETUP.md) ·
[Linux help](docs/LINUX_SETUP.md) · [Changelog](CHANGELOG.md)

Licensed under the [MIT License](LICENSE).
