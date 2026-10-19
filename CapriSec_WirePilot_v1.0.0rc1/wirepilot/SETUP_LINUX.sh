#!/usr/bin/env bash
set -euo pipefail
setup_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Python 3.11+ is required. On Kali/Debian/Ubuntu: sudo apt install python3 python3-venv' >&2
    exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo 'Python 3.11+ is required. Install a supported version and rerun setup.' >&2
    exit 1
fi
exec python3 "$setup_dir/scripts/setup_linux.py" "$@"
