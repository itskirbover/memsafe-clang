#!/usr/bin/env python3
"""Integration test runner for memsafe-check CLI and libMemSafePlugin.so."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_cli(cli: str, fixture: Path, extra_args: list[str], compiler_flags: list[str]):
    cmd = [cli, *extra_args, str(fixture), "--", *compiler_flags]
    return subprocess.run(cmd, capture_output=True, text=True)


def check_buffer_overflow(cli: str, fixtures: Path) -> None:
    bad = run_cli(cli, fixtures / "buffer_overflow_bad.c", ["--format=json", "--fail-on-warning"], [])
    assert bad.returncode == 1, f"expected exit 1, got {bad.returncode}\nstderr={bad.stderr}"
    data = json.loads(bad.stdout)
    assert data["count"] == 6, f"expected 6 findings, got {data}"
    cwes = {f["cwe"] for f in data["findings"]}
    assert "CWE-787" in cwes and "CWE-120" in cwes, f"unexpected CWEs: {cwes}"

    good = run_cli(cli, fixtures / "buffer_overflow_good.c", ["--format=json", "--fail-on-warning"], [])
    assert good.returncode == 0, f"expected exit 0, got {good.returncode}\nstdout={good.stdout}\nstderr={good.stderr}"
    assert json.loads(good.stdout)["count"] == 0, f"unexpected findings: {good.stdout}"


def check_use_after_free(cli: str, fixtures: Path) -> None:
    bad = run_cli(cli, fixtures / "use_after_free_bad.cpp", ["--format=json", "--fail-on-warning"], ["-std=c++20"])
    assert bad.returncode == 1, f"expected exit 1, got {bad.returncode}\nstderr={bad.stderr}"
    data = json.loads(bad.stdout)
    assert data["count"] == 4, f"expected 4 findings, got {data}"
    cwes = {f["cwe"] for f in data["findings"]}
    assert "CWE-416" in cwes and "CWE-415" in cwes, f"unexpected CWEs: {cwes}"

    good = run_cli(cli, fixtures / "use_after_free_good.cpp", ["--format=json", "--fail-on-warning"], ["-std=c++20"])
    assert good.returncode == 0, f"expected exit 0, got {good.returncode}\nstdout={good.stdout}\nstderr={good.stderr}"
    assert json.loads(good.stdout)["count"] == 0, f"unexpected findings: {good.stdout}"


def check_uninit_pointer(cli: str, fixtures: Path) -> None:
    bad = run_cli(cli, fixtures / "uninit_ptr_bad.cpp", ["--format=json", "--fail-on-warning"], ["-std=c++20"])
    assert bad.returncode == 1, f"expected exit 1, got {bad.returncode}\nstderr={bad.stderr}"
    data = json.loads(bad.stdout)
    assert data["count"] == 4, f"expected 4 findings, got {data}"
    cwes = {f["cwe"] for f in data["findings"]}
    assert "CWE-824" in cwes and "CWE-457" in cwes, f"unexpected CWEs: {cwes}"

    good = run_cli(cli, fixtures / "uninit_ptr_good.cpp", ["--format=json", "--fail-on-warning"], ["-std=c++20"])
    assert good.returncode == 0, f"expected exit 0, got {good.returncode}\nstdout={good.stdout}\nstderr={good.stderr}"
    assert json.loads(good.stdout)["count"] == 0, f"unexpected findings: {good.stdout}"


def check_filtering(cli: str, fixtures: Path) -> None:
    # Filtering buffer_overflow_bad.c to only use-after-free must yield 0 findings
    res = run_cli(
        cli,
        fixtures / "buffer_overflow_bad.c",
        ["--format=json", "--checks=use-after-free", "--fail-on-warning"],
        [],
    )
    assert res.returncode == 0, f"expected exit 0 when filtered out, got {res.returncode}"
    assert json.loads(res.stdout)["count"] == 0


def check_plugin(plugin: str, clang_bin: str, fixtures: Path) -> None:
    bad_file = str(fixtures / "use_after_free_bad.cpp")
    good_file = str(fixtures / "use_after_free_good.cpp")

    # Warning mode (exit 0, emits [memsafe:use-after-free])
    warn = subprocess.run(
        [clang_bin, f"-fplugin={plugin}", "-std=c++20", "-fsyntax-only", bad_file],
        capture_output=True,
        text=True,
    )
    assert warn.returncode == 0, f"plugin warning mode failed: {warn.stderr}"
    assert "[memsafe:use-after-free]" in warn.stderr, f"missing plugin diagnostic: {warn.stderr}"

    # Error / blocking mode (exit != 0)
    err = subprocess.run(
        [
            clang_bin,
            f"-fplugin={plugin}",
            "-Xclang",
            "-plugin-arg-memsafe",
            "-Xclang",
            "-fail-on-warning",
            "-std=c++20",
            "-fsyntax-only",
            bad_file,
        ],
        capture_output=True,
        text=True,
    )
    assert err.returncode != 0, "plugin -fail-on-warning should block compilation"
    assert "[memsafe:use-after-free]" in err.stderr

    # Clean file passes even in blocking mode
    ok = subprocess.run(
        [
            clang_bin,
            f"-fplugin={plugin}",
            "-Xclang",
            "-plugin-arg-memsafe",
            "-Xclang",
            "-fail-on-warning",
            "-std=c++20",
            "-fsyntax-only",
            good_file,
        ],
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0, f"clean fixture failed under plugin: {ok.stderr}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANGXX", "clang++"))
    parser.add_argument("--fixtures", required=True)
    parser.add_argument(
        "--case",
        choices=["buffer-overflow", "use-after-free", "uninit-pointer", "filtering", "plugin", "all"],
        default="all",
    )
    args = parser.parse_args()
    fixtures = Path(args.fixtures)

    dispatch = {
        "buffer-overflow": lambda: check_buffer_overflow(args.cli, fixtures),
        "use-after-free": lambda: check_use_after_free(args.cli, fixtures),
        "uninit-pointer": lambda: check_uninit_pointer(args.cli, fixtures),
        "filtering": lambda: check_filtering(args.cli, fixtures),
        "plugin": lambda: check_plugin(args.plugin, args.clang, fixtures),
    }

    if args.case == "all":
        for name, fn in dispatch.items():
            fn()
            print(f"PASS: {name}")
    else:
        dispatch[args.case]()
        print(f"PASS: {args.case}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
