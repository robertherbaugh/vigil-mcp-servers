"""The host scripts, run for real with sh, against a fake nft, sudo and logger."""

import os
import stat
import subprocess
from pathlib import Path

import pytest

HOST = Path(__file__).resolve().parents[1] / "host"


@pytest.fixture
def box(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    calls = tmp_path / "calls"

    def tool(name, body):
        p = bin_ / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    # sudo -n <helper> args: run the real helper with the fake nft.
    tool(
        "sudo",
        f'[ "$1" = -n ] && shift; [ "$1" = /usr/local/sbin/vigil-respond-nft ] || exit 9; '
        f'shift; exec sh "{HOST}/vigil-respond-nft" "$@"\n',
    )
    tool(
        "nft",
        f'echo "$*" >> "{calls}"\ncase "$*" in "list table"*) exit 1;; esac\n'
        'case "$*" in "-j list set"*) echo \'{"nftables":[{"set":{"elem":[]}}]}\';; esac\n',
    )
    tool("logger", "exit 0\n")
    never = tmp_path / "never-block"
    never.write_text("127.0.0.0/8\n192.0.2.1  # the gateway\n10.99.0.0/16\n")
    env = {
        "PATH": f"{bin_}:/usr/bin:/bin",
        "VIGIL_RESPOND_NFT": str(bin_ / "nft"),
        "VIGIL_RESPOND_NEVER_BLOCK": str(never),
    }
    return env, calls


def respond(box, request):
    env, calls = box
    # vigil-respond calls sudo by PATH; our fake sudo runs the helper from the checkout.
    script = (
        (HOST / "vigil-respond")
        .read_text()
        .replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={env['PATH']}")
    )
    r = subprocess.run(
        ["sh", "-c", script, "vigil-respond"],
        env={**env, "SSH_ORIGINAL_COMMAND": request},
        capture_output=True,
        text=True,
        timeout=20,
    )
    return r.returncode, r.stdout + r.stderr, calls.read_text() if calls.exists() else ""


def test_block_ip_adds_an_element_with_a_timeout(box):
    code, out, calls = respond(box, "block-ip 198.51.100.7 3600")
    assert code == 0, out
    assert "blocked 198.51.100.7 for 3600s" in out
    assert "add element inet vigil_respond blocked4 { 198.51.100.7 timeout 3600s }" in calls


def test_ipv6_goes_to_its_own_set(box):
    code, _, calls = respond(box, "block-ip 2001:db8::7 600")
    assert code == 0
    assert "blocked6 { 2001:db8::7 timeout 600s }" in calls


@pytest.mark.parametrize(
    "request_",
    [
        "block-ip 198.51.100.7 3600; rm -rf /",
        "block-ip $(id) 60",
        "block-ip `id` 60",
        "block-ip 198.51.100.7 3600 && id",
        "block-ip 198.51.100.7|id 60",
        "bash",
        "",
        "block-ip 198.51.100.7",
        "list-blocks now",
        "unblock-ip",
        "x" * 200,
    ],
)
def test_anything_else_is_refused_before_root(box, request_):
    code, out, calls = respond(box, request_)
    assert code == 2 and "refused" in out
    assert "add element" not in calls and "delete element" not in calls


@pytest.mark.parametrize(
    ("request_", "why"),
    [
        ("block-ip 999.1.1.1 60", "not an IP"),
        ("block-ip 198.51.100.7 30", "60 to 86400"),
        ("block-ip 198.51.100.7 90000", "60 to 86400"),
        ("block-ip 192.0.2.1 60", "never-block"),
        ("block-ip 10.99.50.87 60", "never-block"),
        ("block-ip 127.0.0.1 60", "never-block"),
    ],
)
def test_root_helper_checks_again(box, request_, why):
    code, out, calls = respond(box, request_)
    assert code == 2 and why in out
    assert "add element" not in calls


def test_unblock_and_list(box):
    assert respond(box, "unblock-ip 198.51.100.7")[0] == 0
    code, out, calls = respond(box, "list-blocks")
    assert code == 0 and "nftables" in out
    assert "delete element inet vigil_respond blocked4 { 198.51.100.7 }" in calls


def test_installer_refuses_a_host_without_step_ca(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("as root the installer would change this machine")
    r = subprocess.run(["sh", str(HOST / "install.sh")], capture_output=True, text=True)
    assert r.returncode == 2 and "run as root" in r.stderr
