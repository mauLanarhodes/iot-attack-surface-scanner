#!/usr/bin/env python3
"""
IoT Attack Surface Scanner — direct-run entry point.

Identical behaviour to the installed `iotscanner` command.

Usage:
    python3 main.py --launch                    # Auto-detect subnet
    python3 main.py --launch 192.168.1.0/24     # Explicit subnet
    python3 main.py --version
    python3 main.py --help
"""

from iotscanner.cli import main

if __name__ == "__main__":
    main()