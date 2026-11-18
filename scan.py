#!/usr/bin/env python3
"""Entry point for agents and schedulers: python3 /path/to/occupai/scan.py <command> [options].
Same as `python3 -m occupai_scan` run from this folder. Read-only; see `--help`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from occupai_scan.cli import main  # noqa: E402

sys.exit(main())
