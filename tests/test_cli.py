"""CLI validation tests; no real gateway traffic."""

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


def test_help_and_validation_before_authentication():
    help_result = run("--help")
    assert help_result.returncode == 0
    assert "global-enable" in help_result.stdout
    for args in [
        ("remove", "07", "--yes"),
        ("scan", "--max-id", "1000"),
        (
            "add",
            "--name",
            "bad<name",
            "--protocol",
            "TCP",
            "--ip",
            "10.0.0.42",
            "--start",
            "54321",
            "--yes",
        ),
    ]:
        result = run("--cdp-url", "http://127.0.0.1:1", *args)
        assert result.returncode == 2
        assert "CDP" not in result.stderr
        assert "Traceback" not in result.stderr


def test_mutation_needs_confirmation_before_browser():
    result = run("--cdp-url", "http://127.0.0.1:1", "remove", "7")
    assert result.returncode == 2
    assert "--yes" in result.stderr
    assert "CDP" not in result.stderr
