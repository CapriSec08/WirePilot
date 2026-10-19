#!/usr/bin/env bash
set -euo pipefail
setup_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$setup_dir/wirepilot/SETUP_LINUX.sh" "$@"
