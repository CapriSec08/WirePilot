"""Linux entry point for the shared WirePilot setup."""
from setup_common import main

if __name__ == "__main__":
    raise SystemExit(main(platform="linux"))
