"""Support running the command-line application with ``python -m``."""

from pass_manager.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
