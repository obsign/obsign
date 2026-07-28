#!/usr/bin/env python3
"""Demonstrates hot rotation of the identity provider's keys.

    cargo build --workspace
    cargo run -p policy --example mkbundle -- /tmp/rot
    python3 scripts/demo-rotation.py /tmp/rot

The gateway starts with a bundle that only knows `k1` and a short-lived token.
Mid-session the IdP moves to `k2` and the control plane republishes the
bundle. The gateway detects the unknown `kid`, reloads, and keeps serving --
with no restart.

A driver is needed because the stdio transport makes the gateway exit as soon
as its input closes: the pipe has to stay open long enough for the rotation to
happen in flight.
"""
import subprocess, sys, time
from pathlib import Path

D = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/rot")
ROOT = Path(__file__).resolve().parent.parent
GW = ROOT / "target/debug/probant-proxy"
SRV = ROOT / "target/debug/mock-mcp-server"

def mint(kid, exp):
    subprocess.run(
        ["cargo", "run", "-q", "-p", "probant-proxy", "--example", "mint_demo_token",
         "--", str(D), str(exp), "user", kid],
        cwd=ROOT, check=True, stdout=subprocess.DEVNULL)

REQ = ('{"jsonrpc":"2.0","id":%d,"method":"tools/call",'
       '"params":{"name":"ticket_update","arguments":{}}}\n')

mint("k1", 3)
proxy = subprocess.Popen(
    [GW, "--policy", D / "policy-bundle.json",
     "--trusted-keys", D / "trusted-keys.json",
     "--identity-bundle", D / "identity-bundle.json",
     "--token-file", D / "token.jwt",
     "--wal", D / "wal", "--chain-id", "rot", "--env", "prod",
     "--evidence-out", D / "ev.json", "--", SRV],
    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)

proxy.stdin.write(REQ % 1); proxy.stdin.flush()
time.sleep(1)

print(">>> rotation: the IdP moves to k2, the control plane republishes the bundle")
mint("k2", 3600)
time.sleep(3)          # the k1 token expires

proxy.stdin.write(REQ % 2); proxy.stdin.flush()
time.sleep(1)
proxy.stdin.close()
proxy.wait(timeout=20)
