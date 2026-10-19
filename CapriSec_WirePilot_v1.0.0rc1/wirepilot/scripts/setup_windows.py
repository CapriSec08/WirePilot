"""Windows entry point; shared install and verification logic lives in setup_common."""
from setup_common import main

if __name__ == "__main__":
    raise SystemExit(main(platform="windows"))
