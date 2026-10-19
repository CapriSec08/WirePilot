# Contributing to WirePilot

Thanks for taking an interest in WirePilot. You don't have to write code to help.
Testing it on your machine, improving the docs, reporting a bug, or suggesting a
feature all make a difference.

## Ideas and bugs

Open a GitHub issue in this repository. Tell us what you tried, what you expected,
and what happened. For a bug, include your OS, WirePilot version and any useful
error messages. Please remove passwords and private data before sharing logs.

If you're planning a bigger change, open an issue first so we can discuss it.
Security vulnerabilities should be reported privately — see [SECURITY.md](SECURITY.md).

## Making a change

Fork the repository, create a branch, and keep your change focused. Explain what
it improves and how you checked it when you open a pull request. Documentation
fixes and small improvements are welcome too.

For development, install Python 3.11+ and TShark. From the project folder, using
your Python virtual environment, run:

```bash
python -m pip install -e '.[test]'
python -m pytest -q
```

Run the relevant checks for your change and update the docs when behaviour changes.
See the [technical reference](docs/REFERENCE.md#development-and-public-release)
for the full development checks.

## A few things to keep in mind

Use synthetic test captures or samples you have permission to share. Don't commit
real customer traffic, credentials or malware binaries.

For a new detection, include an example that should trigger it and a harmless
example that shouldn't. Explain the evidence, what it might miss, and what else
could cause the same pattern.

Keep tools usable with different AI clients. External commands need fixed,
validated arguments and limits on runtime and output. Capture and active probes
should stay opt-in. Document platform support for new tools.

If you get stuck, open an issue and describe where you are. We can work from there.
