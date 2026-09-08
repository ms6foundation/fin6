"""The node process: identity, store, clock, mesh, and one epoch at a time.

    fin6 node run --dir testnet/ --id fin6-n01

What it does every epoch is what `run_tiered_epoch` does in the simulation,
except that it only ever speaks for itself and everything it learns arrives as
bytes:

    wait for the epoch boundary        the clock, from the genesis document
    seat the grid                      deterministic, from the register
    propose        (leader only)       and push the body to its neighbours
    gossip                             envelope headers, until quorum or the deadline
    fetch                              block bodies by hash, once
    apply and commit                   one durable write, per part four

A node that is not at `height + 1` sits the epoch out rather than joining
half-way — it has nothing to attest with and nothing anyone needs. Catching up
is stage 2 and is honestly missing.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time

from .. import genesis as genesis_mod
from ..block import CeremonyMeta
from ..ceremony import Grid
from ..crypto import Signer, h_hex
from ..register import Standing
from ..store.db import ChainStore
from ..tiers import SoloWorkload, run_tiered_epoch
from .clock import Clock
from .peer import Mesh
from .seat import Seat

GOSSIP_INTERVAL = 0.05


class NodeProcess:
    """One fin6 node, running until it is stopped."""

    def __init__(self, root: str, node_id: str, *, keyring=None, quiet=False):
        self.root = os.path.abspath(root)
        self.id = node_id
        self.quiet = quiet
        self.config = json.load(open(os.path.join(self.root, "net.json")))
        self.doc = genesis_mod.load(os.path.join(self.root, "genesis.json"))
        self.settings = self.config["nodes"][node_id]
        self.behaviour = self.settings.get("behaviour", "honest")

        self.dir = os.path.join(self.root, node_id)
        os.makedirs(self.dir, exist_ok=True)
        self.log_path = os.path.join(self.dir, "node.log")

        keyring = keyring or genesis_mod.dev_keyring
        self.signer: Signer = keyring(node_id)
        self.world, self.wallets = genesis_mod.boot(self.doc, keyring=keyring)
        # A node speaks only for itself.  The rest of the roster is a set of
        # public keys and an address, not a set of objects.
        self.validators = {n.node_id: n.public_hex for n in self.doc.nodes}
        self.node = self.world.nodes[node_id]
        self.world.nodes = {node_id: self.node}

        self.store = ChainStore(os.path.join(self.dir, "chain.db"))
        if self.store.is_empty():
            self.store.initialise(self.node.state)
            self.store.save_registers(self.world.registers)
        else:
            self.world.restore_from(self.store)
            self.node = self.world.nodes[node_id]
        self.node.store = self.store

        self.clock = Clock.from_genesis(
            self.doc, skew_ms=self.settings.get("skew_ms", 0),
            effective_ms=self.config.get("effective_ms"))
        self.inbox: queue.Queue = queue.Queue()
        peers = {nid: tuple(spec["listen"])
                 for nid, spec in self.config["nodes"].items() if nid != node_id}
        self.mesh = Mesh(node_id, self.doc.chain_id,
                         tuple(self.settings["listen"]), peers, self.inbox,
                         log=self.log, on_request=self.answer)
        self.seat: Seat | None = None
        self.bodies: dict = {}
        # What a wallet needs and a validator does not: every output the chain
        # has produced, and every nullifier it has published, in height order.
        # Append-only, so the reader thread can serve a slice while the epoch
        # loop is appending to the end.
        self.outputs: list = []            # (height, cm, sealed opening)
        self.spent: list = []              # (height, nullifier)
        self.tx_height: dict = {}          # txid -> height
        self.stop = threading.Event()
        self.epochs_run = 0
        self.last_reason = "not started"

    # ── plumbing ─────────────────────────────────────────────────────────────

    def log(self, message: str):
        line = f"{time.strftime('%H:%M:%S')} {self.id} {message}"
        with open(self.log_path, "a") as fh:
            fh.write(line + "\n")
        if not self.quiet:
            print(line, flush=True)

    def status(self) -> dict:
        state = self.node.state
        return {
            "node_id": self.id,
            "height": state.height,
            "tip": state.tip,
            "utxo_root": str(state.utxo.root),
            "nf_root": str(state.nullifiers.root),
            "registers_root": str(self.world.registers[self.grid_id()].root()),
            "grids": len(self.world.topology.grid_ids()),
            "tiers": 1 if len(self.world.topology.grid_ids()) < 2 else 2,
            "mempool": len(self.node.mempool),
            "peers": len(self.mesh.connected),
            "epoch": self.clock.epoch_now(),
            "epochs_run": self.epochs_run,
            "last": self.last_reason,
            "behaviour": self.behaviour,
        }

    def answer(self, msg):
        """Serve one client request.  Read-only, and never blocks the epoch."""
        kind, payload = msg["kind"], msg["payload"] or {}
        if kind == "status":
            return "status_reply", self.status()
        if kind == "getoutputs":
            start = int(payload.get("from", 0))
            end = int(payload.get("to", 1 << 62))
            return "outputs_reply", {
                "height": self.world.height,
                "outputs": [list(o) for o in self.outputs
                            if start <= o[0] <= end],
                "nullifiers": [list(n) for n in self.spent
                               if start <= n[0] <= end],
            }
        if kind == "txstatus":
            txid = payload.get("txid")
            height = self.tx_height.get(txid)
            if height is not None:
                return "txstatus_reply", {"txid": txid, "state": "in_block",
                                          "height": height,
                                          "tip": self.world.height}
            if txid in self.node.mempool:
                return "txstatus_reply", {"txid": txid, "state": "pending",
                                          "height": None,
                                          "tip": self.world.height}
            return "txstatus_reply", {"txid": txid, "state": "unknown",
                                      "height": None, "tip": self.world.height}
        return None

    def _index(self, block):
        """Record what a wallet will come asking for."""
        height = block.height
        for tx in block.transactions():
            self.tx_height[tx.txid] = height
            sealed = list(tx.output_notes) + [b""] * len(tx.output_cms)
            for cm, blob in zip(tx.output_cms, sealed):
                self.outputs.append((height, cm, blob))
            for nf in tx.nullifiers:
                self.spent.append((height, nf))

    def grid_id(self) -> str:
        return self.world.topology.grid_of(self.id)

    # ── the loop ─────────────────────────────────────────────────────────────

    def run(self, until_epoch: int | None = None):
        self.mesh.start()
        self.log(f"listening on {self.settings['listen']}, "
                 f"chain {self.doc.chain_id[:20]}…")
        last = 0
        try:
            while not self.stop.is_set():
                epoch = self.clock.wait_for_next_epoch(last, self.stop)
                if epoch is None:
                    break
                last = epoch
                if until_epoch is not None and epoch > until_epoch:
                    break
                self.run_epoch(epoch)
        finally:
            self.mesh.stop()
            self.store.close()

    def run_epoch(self, epoch: int):
        """One epoch.  The epoch number comes from the clock; the height comes
        from the chain, and they are allowed to drift apart.

        They must be: an epoch whose leader is dead produces no block, so the
        height does not advance while the clock does.  Tying them together
        looked tidy and was fatal — one missed epoch and every node was
        permanently a number behind, refused to run again, and the network
        stopped for good.  A gap in the epoch numbering is not a gap in the
        chain: `prev_hash` still chains, and the block simply takes the next
        height.
        """
        gid = self.grid_id()
        register = self.world.registers[gid]
        members = self.world.grid_members(gid)
        if self.id not in members:
            self.last_reason = "not seated this epoch"
            self._serve_until(self.clock.commit_deadline(epoch))
            return

        seed = h_hex("view", self.doc.first_seed, epoch, gid, 0)
        # Logged because "no proposal reached this seat" on every node is
        # indistinguishable from a leader that fell over.
        grid = Grid.seat(members, self.world.params.row_size, seed,
                         standing={n: register.standing_of(n) for n in members})
        attesters = [n for n in members
                     if register.standing_of(n) == Standing.ATTESTER]
        workload = SoloWorkload(self.world, gid, epoch,
                                self.world.params.backend_for("local"))
        self.seat = Seat(
            self.node, grid, workload, epoch=epoch,
            height=self.world.height + 1,
            quorum=register.quorum(self.world.params.quorum_num,
                                   self.world.params.quorum_den),
            validators={n: self.validators[n] for n in grid.seats},
            counting=set(attesters), grid_id=gid,
            chain_id=self.doc.chain_id)

        if grid.leader != self.id:
            self.log(f"epoch {epoch}: leader is {grid.leader}")
        if grid.leader == self.id and self.behaviour != "silent":
            meta = CeremonyMeta(epoch=epoch, leader_id=grid.leader,
                                rows=grid.n_rows, row_size=grid.row_size,
                                grid_seed=seed)
            try:
                sp = self.seat.propose(meta)
            except Exception as exc:                     # a leader that cannot
                self.log(f"epoch {epoch}: I am the leader and cannot build a "
                         f"block: {type(exc).__name__}: {exc}")
                self.last_reason = f"could not build a block: {exc}"
                sp = None
            if sp is not None:
                body = self.seat.blocks[sp.block_hash]
                self.bodies[sp.block_hash] = body
                # Push the body to the seats that will need it first.  The
                # header alone would cost them a round-trip before they can
                # validate anything.
                for peer in self.seat.neighbours():
                    self.mesh.send(peer, "block", {"block": body}, epoch=epoch)

        accepted = self._gossip(epoch, grid)
        if accepted is None:
            self.last_reason = f"epoch {epoch}: {self.seat.why_not()}"
            self.log(self.last_reason)
            self._serve_until(self.clock.commit_deadline(epoch), epoch)
            return

        block, cert = accepted
        self.world.pending_rolls[gid] = self.seat.roll(cert)
        self.world.apply_network_block(block)
        self._index(block)
        self.epochs_run += 1
        self.last_reason = "ok"
        self.log(f"epoch {epoch}: height {block.height} "
                 f"{block.hash()[:16]}… {len(cert.attestations)} attestations, "
                 f"{sum(1 for _ in block.transactions())} tx")
        self._serve_until(self.clock.commit_deadline(epoch), epoch)

    def _gossip(self, epoch: int, grid):
        """Exchange until quorum or the deadline.  The rounds are gone."""
        deadline = self.clock.decide_deadline(epoch)
        neighbours = list(self.seat.neighbours())
        last_sent = 0.0
        while self.clock.now_ms() < deadline and not self.stop.is_set():
            self._drain(timeout=0.02)
            self.seat.react()
            got = self.seat.accepted()
            if got is not None:
                return got
            now = time.time()
            if now - last_sent >= GOSSIP_INTERVAL:
                last_sent = now
                self.mesh.broadcast(neighbours, "env", self.seat.wire(),
                                    epoch=epoch)
                for digest in self.seat.missing():
                    self.mesh.broadcast(neighbours, "getblock",
                                        {"hash": digest}, epoch=epoch)
        self.seat.react()
        return self.seat.accepted()

    # ── messages ─────────────────────────────────────────────────────────────

    def _serve_until(self, when_ms: int, epoch: int | None = None):
        """Keep answering after deciding.

        A seat that reaches quorum first and goes quiet takes its attestation
        with it, and the seats still one short never get there — which is how
        the first runs lost two or three nodes an epoch. Deciding is not a
        reason to stop talking; the deadline is.
        """
        last_sent = 0.0
        while self.clock.now_ms() < when_ms and not self.stop.is_set():
            self._drain(timeout=0.02)
            if self.seat is None or epoch is None:
                time.sleep(0.03)
                continue
            now = time.time()
            if now - last_sent >= GOSSIP_INTERVAL:
                last_sent = now
                self.mesh.broadcast(self.seat.neighbours(), "env",
                                    self.seat.wire(), epoch=self.seat.epoch)

    def _drain(self, timeout=0.0):
        while True:
            try:
                who, msg, conn = self.inbox.get(timeout=timeout)
            except queue.Empty:
                return
            timeout = 0.0
            try:
                self._handle(who, msg, conn)
            except Exception as exc:                     # never die on a peer
                self.log(f"dropped a {msg.get('kind')} from {who}: {exc}")

    def _handle(self, who, msg, conn):
        kind, payload = msg["kind"], msg["payload"]
        if kind == "tx":
            tx = payload.get("tx") if isinstance(payload, dict) else None
            if tx is not None and tx.txid not in self.node.mempool:
                ok, why = self.node.submit(
                    tx, backend=self.world.params.backend_for("local"))
                if ok:                                   # flood it onward once
                    self.mesh.broadcast(
                        [p for p in self.mesh.connected if p != who], "tx",
                        {"tx": tx})
            return
        if self.seat is None or msg.get("epoch") != self.seat.epoch:
            return
        if kind == "env":
            self.seat.absorb(payload or {})
        elif kind == "getblock":
            digest = (payload or {}).get("hash")
            body = self.bodies.get(digest) or self.seat.blocks.get(digest)
            if body is not None and who in self.mesh.connected:
                self.mesh.send(who, "block", {"block": body},
                               epoch=self.seat.epoch)
        elif kind == "block":
            body = (payload or {}).get("block")
            if body is not None:
                self.bodies[body.hash()] = body
                self.seat.offer_block(body)


def run_node(root: str, node_id: str, until_epoch=None, quiet=False):
    proc = NodeProcess(root, node_id, quiet=quiet)
    proc.run(until_epoch=until_epoch)
    return proc
