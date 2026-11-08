"""Invoke the installed CLI without any real gateway traffic in test fixtures."""

import subprocess
import sys


def run(*args):
    return subprocess.run(
        [sys.executable, "-m", "jolly_roger", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
