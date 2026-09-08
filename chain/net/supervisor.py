"""The harness: lay out a testnet, start it, look at it, break it.

The supervisor is deliberately the only clever thing in `net/`, because it is
the part that exists to break things.  A node is a plain process; killing one
is `kill`, partitioning two is refusing to dial, and skewing a clock is a field
in `net.json`.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time

from .. import genesis as genesis_mod
from ..hardening.params import PRESETS as HARDENING_PRESETS
from ..params import PRESETS as CHAIN_PRESETS
from .clock import Clock
from .peer import ask

BASE_PORT = 7600


# ═══════════════════════════════════════════════════════════════════════════════
# Laying one out
# ═══════════════════════════════════════════════════════════════════════════════

def new_testnet(root: str, *, nodes: int = 7, preset: str = "local",
                epoch_millis: int | None = None, base_port: int = BASE_PORT,
                supply=None, force: bool = False) -> dict:
    """Write `genesis.json` and `net.json`.  Seven is the default for a reason:
    n = 3f+1 at f = 2, so the register's 2/3 rule lands on a quorum of 5."""
    root = os.path.abspath(root)
    if os.path.exists(root) and os.listdir(root):
        if not force:
            raise SystemExit(f"{root} already holds a testnet; pass --force")
        shutil.rmtree(root)
    os.makedirs(root, exist_ok=True)

    params = CHAIN_PRESETS[preset]
    hardening = HARDENING_PRESETS.get(preset, HARDENING_PRESETS["local"])
    ids = [f"fin6-n{i:02d}" for i in range(1, nodes + 1)]
    doc = genesis_mod.ratify_all(genesis_mod.draft(
        f"fin6-testnet-{nodes}", ids, params, hardening,
        supply or {"treasury": [1000, 900, 800, 700, 600]},
        epoch_millis=epoch_millis))
    genesis_mod.save(doc, os.path.join(root, "genesis.json"))

    net = {
        "effective_ms": None,        # filled in by `up`, so epoch 1 is next
        "nodes": {nid: {"listen": ["127.0.0.1", base_port + i],
                        "behaviour": "honest", "skew_ms": 0}
                  for i, nid in enumerate(ids)},
    }
    with open(os.path.join(root, "net.json"), "w") as fh:
        json.dump(net, fh, indent=2)
    return {"root": root, "chain_id": doc.chain_id, "nodes": ids,
            "quorum": doc.quorum(), "epoch_millis": doc.epoch_millis}


def load(root: str):
    root = os.path.abspath(root)
    with open(os.path.join(root, "net.json")) as fh:
        net = json.load(fh)
    doc = genesis_mod.load(os.path.join(root, "genesis.json"))
    return root, net, doc


# ═══════════════════════════════════════════════════════════════════════════════
# Running it
# ═══════════════════════════════════════════════════════════════════════════════

class Testnet:
    """Child processes, and the handle to kill them."""

    def __init__(self, root: str):
        self.root, self.net, self.doc = load(root)
        self.procs: dict = {}

    # ── up / down ────────────────────────────────────────────────────────────

    def up(self, only=None, start_in_ms: int = 1500, until_epoch=None):
        if self.net.get("effective_ms") is None:
            self.net["effective_ms"] = int(time.time() * 1000) + start_in_ms
            with open(os.path.join(self.root, "net.json"), "w") as fh:
                json.dump(self.net, fh, indent=2)
        for node_id in (only or sorted(self.net["nodes"])):
            self.start(node_id, until_epoch=until_epoch)
        return self

    def start(self, node_id: str, until_epoch=None):
        if node_id in self.procs and self.procs[node_id].poll() is None:
            return
        cmd = [sys.executable, "-m", "chain.net.node_main", self.root, node_id]
        if until_epoch is not None:
            cmd += ["--until", str(until_epoch)]
        log = open(os.path.join(self.root, f"{node_id}.out"), "a")
        self.procs[node_id] = subprocess.Popen(
            cmd, stdout=log, stderr=subprocess.STDOUT,
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))))

    def down(self):
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs.values():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()

    def kill(self, node_id: str, hard: bool = True):
        """`kill -9` by default: the point is the window between an fsync and a
        broadcast, and a clean shutdown does not have one."""
        proc = self.procs.get(node_id)
        if proc is None or proc.poll() is not None:
            return False
        proc.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
        proc.wait(timeout=5)
        return True

    def pause(self, node_id: str, resume: bool = False):
        proc = self.procs.get(node_id)
        if proc is None or proc.poll() is not None:
            return False
        proc.send_signal(signal.SIGCONT if resume else signal.SIGSTOP)
        return True

    def running(self):
        return sorted(n for n, p in self.procs.items() if p.poll() is None)

    # ── looking at it ────────────────────────────────────────────────────────

    def status(self, timeout=1.5) -> dict:
        out = {}
        for node_id, spec in sorted(self.net["nodes"].items()):
            host, port = spec["listen"]
            try:
                msg = ask(host, port, self.doc.chain_id, "status",
                          timeout=timeout)
                out[node_id] = msg["payload"] if msg else None
            except OSError:
                out[node_id] = None
        return out

    def agreement(self, status=None):
        """(ok, height, detail).  The whole of consensus health."""
        status = status if status is not None else self.status()
        live = {n: s for n, s in status.items() if s}
        if not live:
            return False, None, "no node answered"
        heights = {s["height"] for s in live.values()}
        top = max(heights)
        at_top = {n: s for n, s in live.items() if s["height"] == top}
        roots = {(s["tip"], s["utxo_root"], s["nf_root"],
                  s["registers_root"]) for s in at_top.values()}
        if len(roots) != 1:
            return False, top, f"{len(roots)} different states at height {top}"
        return True, top, f"{len(at_top)}/{len(live)} reporting nodes agree"

    def wait_for_height(self, height: int, timeout=90.0, quorum=None):
        """Block until enough nodes reach a height.  Returns the status map."""
        need = quorum or self.doc.quorum()
        end = time.time() + timeout
        while time.time() < end:
            status = self.status()
            reached = [s for s in status.values() if s and s["height"] >= height]
            if len(reached) >= need:
                return status
            time.sleep(0.5)
        return self.status()

    def clock(self) -> Clock:
        return Clock.from_genesis(self.doc,
                                  effective_ms=self.net.get("effective_ms"))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.down()
        return False


def render_status(status: dict, agreement) -> str:
    ok, height, detail = agreement
    lines = [f"{'node':<12}{'height':>7}  {'tip':<15}{'utxo_root':<15}"
             f"{'registers':<15}{'t':>2}{'mem':>5}  peers"]
    for node_id, s in sorted(status.items()):
        if s is None:
            lines.append(f"{node_id:<12}{'—':>7}  {'—':<15}{'—':<15}"
                         f"{'—':<15}{'—':>2}{'—':>5}  down")
            continue
        behind = "" if s["height"] == height else f"  behind {height - s['height']}"
        lines.append(
            f"{node_id:<12}{s['height']:>7}  {s['tip'][:13]:<15}"
            f"{s['utxo_root'][:13]:<15}{s['registers_root'][:13]:<15}"
            f"{s['tiers']:>2}{s['mempool']:>5}  {s['peers']}{behind}")
    lines.append("")
    lines.append(("agreement:  " if ok else "DISAGREEMENT:  ") + detail
                 + (f" at height {height}" if height is not None else ""))
    return "\n".join(lines)
