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
from ..crypto import Signer, h_bytes, h_hex
from ..register import AttendanceRoll, Standing
from ..hardening.history import NetworkHistory
from ..hardening.pool import Era
from ..store.db import ChainStore
from ..tiers import SoloWorkload, run_tiered_epoch
from .budget import EpochBudget, Priority, WorkQueue
from .catchup import BATCH, BodyCache, Catchup
from .clock import Clock
from .limits import CLIENT_CAPACITY, CLIENT_RATE, Limiter
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
        # Metering lives at the wire, in front of everything: a request that
        # cannot be afforded costs the node a dictionary lookup, not a proof.
        # `limits` in net.json tightens or loosens the budget per node, which
        # is how the supervisor gets to point a flood at one of them and watch
        # what it does.  Left out, a node uses the defaults, which are set so
        # that an ordinary wallet never meets them.
        limits = self.settings.get("limits") or {}
        self.limiter = Limiter(
            capacity=limits.get("capacity", CLIENT_CAPACITY),
            rate=limits.get("rate", CLIENT_RATE))
        self.mesh = Mesh(node_id, self.doc.chain_id,
                         tuple(self.settings["listen"]), peers, self.inbox,
                         log=self.log, on_request=self.answer,
                         limiter=self.limiter,
                         # A peer's budget is now reachable only by proving the
                         # name it is keyed on, against the roster in the
                         # genesis document.  No new key material: the chain id
                         # is that document's hash.
                         signer=self.signer, validators=self.validators,
                         epoch_now=self.clock.epoch_now)
        self.seat: Seat | None = None
        # Bounded, because it used to be an unbounded dict that every block a
        # node saw was appended to — a leak, and an accidental answer to "how
        # far back can a peer be helped", which deserves a number.  That
        # number is now `catchup.BODY_WINDOW`.
        self.bodies = BodyCache()
        self.catchup = Catchup()
        # What a wallet needs and a validator does not — every output the chain
        # has produced and every nullifier it has published — lives in the
        # store, not in this process.  It is the same rows the ledger already
        # keeps, read back with their heights, so there is no second index to
        # grow without bound or to fall out of step after a restart.
        self.reader = ChainStore(os.path.join(self.dir, "chain.db"),
                                 read_only=True)

        # ── hardening ────────────────────────────────────────────────────────
        # Every node builds the same era from the genesis document, and holds
        # the slice of turns dealt to it.  One node cannot harden a block by
        # itself — it can only stamp the drawn turns that happen to be its own
        # — so the stamps have to be gossiped and assembled, which is exactly
        # the property that makes the pool a distribution of witnesses rather
        # than one operator with a big number.
        self.hardening = self.doc.hardening_params()
        roster = sorted(n.node_id for n in self.doc.nodes)
        self.era = Era(0, h_bytes("era-seed", self.doc.digest()),
                       self.hardening.tree_height, self.hardening.turns,
                       holders={i: roster[i % len(roster)]
                                for i in range(self.hardening.turns)})
        self.owned = {i for i in range(self.hardening.turns)
                      if roster[i % len(roster)] == node_id}
        self.history = NetworkHistory(self.era.spec, self.hardening)
        # And what it had already hardened before it was stopped.  Without
        # this a restart reported weight zero and re-entered history at
        # height 1, which makes fork choice follow whatever it sees first.
        restored = self._restore_history()
        if restored:
            self.log(f"restored {restored} hardened blocks to height "
                     f"{self.history.height}, cumulative "
                     f"{self.history.cumulative_weight:,}")
        self.stamp_pool: dict = {}         # block_hash -> {leaf_index: Stamp}
        self.pending_hard: dict = {}       # height -> the block awaiting turns
        self.stamped: set = set()          # blocks this node has mined for
        self.stop = threading.Event()
        self.epochs_run = 0
        self.last_reason = "not started"
        # Part nine.  Verifying a submitted proof is 25 ms and used to happen
        # inline on `_drain`, which is the loop that has to meet the decide
        # deadline — so a stranger's submission and this node's attestation
        # competed for the same thread, and the stranger did not have to win
        # often.  Expensive work now goes in the queue and is paid for out of
        # the epoch's slack.
        self.budget = EpochBudget(self.clock)
        self.work = WorkQueue()

    def _restore_history(self, page: int = 512) -> int:
        """Page the store's hardened rows back into `self.history`."""
        restored, since = 0, 1
        while True:
            rows, more = self.store.hardened_range(since=since, limit=page)
            if not rows:
                break
            restored += self.history.restore(rows)
            since = int(rows[-1]["height"]) + 1
            if not more:
                break
        return restored

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
            "limiter": self.limiter.stats(),
            "budget": self.budget.stats(),
            "work": self.work.stats(),
            "catchup": self.catchup.stats(),
            "gate": self.mesh.gate.stats(),
            "bodies": len(self.bodies),
            "hardened": self.history.height,
            "weight": self.history.cumulative_weight,
        }

    #: A page of outputs is capped so the reply cannot outgrow a frame.  At the
    #: measured 323 bytes an output row, 8,000 of them is about 2.6 MB against
    #: an 8 MB ceiling, which leaves room for the nullifiers beside them.
    OUTPUT_PAGE = 8000
    HEADER_PAGE = 512

    def answer(self, msg):
        """Serve one client request.  Read-only, and never blocks the epoch."""
        kind, payload = msg["kind"], msg["payload"] or {}
        if kind == "status":
            return "status_reply", self.status()

        if kind == "getoutputs":
            start = int(payload.get("from", 0))
            end = int(payload.get("to", 1 << 62))
            limit = min(int(payload.get("limit", self.OUTPUT_PAGE)),
                        self.OUTPUT_PAGE)
            outs, nfs, next_from = self.reader.outputs(start, payload.get("to"),
                                                       limit=limit)
            scanned = (next_from - 1 if next_from is not None
                       else min(end, self.world.height))
            return "outputs_reply", {
                "height": scanned,
                "tip": self.world.height,
                "outputs": [[h, cm, blob or b"", pos]
                            for h, cm, blob, pos in outs],
                "nullifiers": [[h, nf, pos] for h, nf, pos in nfs],
                "next_from": next_from,
            }

        if kind == "txstatus":
            txid = payload.get("txid")
            height = self.reader.tx_height(txid)
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

        # ── the light client's four ──────────────────────────────────────────

        if kind == "params":
            return "params_reply", {"genesis": self.doc.to_json()}

        if kind == "tip":
            header, cert = self.tip_header()
            return "tip_reply", {"height": self.world.height,
                                 "header": header, "cert": cert}

        if kind == "headers":
            since = max(1, int(payload.get("from", 1)))
            to = payload.get("to")
            rows, more = self.reader.headers(
                since, to, limit=min(int(payload.get("limit",
                                                     self.HEADER_PAGE)),
                                     self.HEADER_PAGE))
            return "headers_reply", {
                "height": self.world.height, "more": more,
                "headers": [h for _, h, _ in rows],
                "certs": [c for _, _, c in rows]}

        if kind == "ancestry":
            height = int(payload.get("height", 0))
            under = payload.get("under")
            proof = self.node.state.history.proof(
                height, under=None if under is None else int(under))
            return "ancestry_reply", {"proof": proof,
                                      "tip": self.world.height}

        if kind == "inclusion":
            cm = payload.get("cm")
            state = self.node.state
            proof = state.utxo.witness_path(cm)
            return "inclusion_reply", {
                "cm": cm, "live": proof is not None, "proof": proof,
                "leaf": state.utxo.witness_leaf(cm) if proof else None,
                "height": state.height,
                "witness_root": state.utxo.witness_root}

        if kind == "tags":
            # The client hands over a detection secret and says how many bits
            # of it to use.  The node can compute the whole tag and does not:
            # that gap is the honest limit of this construction, and it is
            # named in `notes.detection_tag` rather than papered over.
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey)

            from ..notes import TAG_BYTES, tag_from_shared, tag_matches
            bits = max(1, min(int(payload.get("bits", 8)), 8 * TAG_BYTES))
            try:
                secret = X25519PrivateKey.from_private_bytes(
                    bytes.fromhex(payload.get("detect", "")))
            except Exception:
                return "tags_reply", {"error": "that is not a detection key"}
            since = int(payload.get("from", 0))
            to = payload.get("to")
            limit = min(int(payload.get("limit", self.OUTPUT_PAGE)),
                        self.OUTPUT_PAGE)
            rows = self.reader.tagged(since, to, limit=limit)
            hits, scanned = [], 0
            for height, cm, sealed, pos, tag in rows:
                scanned += 1
                if not sealed or not tag:
                    continue
                want = tag_from_shared(secret.exchange(
                    _x25519_public(sealed[:32])))
                if tag_matches(bytes(tag), want, bits):
                    hits.append([height, cm, sealed, pos])
            return "tags_reply", {
                "height": self.world.height, "bits": bits,
                "scanned": scanned, "outputs": hits,
                "from": since, "to": to}

        if kind == "weight":
            since = max(1, int(payload.get("from", 1)))
            rows, more = self.reader.hardened_range(
                since, payload.get("to"),
                limit=min(int(payload.get("limit", 256)), 256))
            spec = self.era.spec
            return "weight_reply", {
                "height": self.world.height,
                "hardened": self.history.height,
                "cumulative": self.history.cumulative_weight,
                "more": more, "blocks": rows,
                # The era a client needs to check the work.  It should build
                # this from the genesis document rather than believe it; it is
                # sent so a client can tell at once that it is talking to a
                # node on another era.
                "era": {"era_id": spec.era_id, "tree_height": spec.tree_height,
                        "turns": spec.turns, "pub_seed": spec.pub_seed.hex(),
                        "root": spec.root.hex()}}

        if kind == "register":
            grid_id = payload.get("grid_id") or self.grid_id()
            reg = self.world.registers.get(grid_id)
            return "register_reply", {
                "grid_id": grid_id,
                "roots": {g: str(r.root())
                          for g, r in self.world.registers.items()},
                "dump": reg.dump() if reg else None,
                "height": self.node.state.height}

        return None

    def tip_header(self):
        """The header at the tip and the certificate that finalised it."""
        rows, _ = self.reader.headers(max(1, self.world.height), None, limit=1)
        if not rows:
            return None, None
        _, header, cert = rows[0]
        return header, cert

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
        # The window this epoch's expensive work is paid for out of.  Opened
        # before the seating check, because an unseated node still serves
        # clients and still must not be talked into spending the epoch on them.
        self.budget.open(epoch)
        # Before seating, not after.  Catching up once the ceremony has been
        # and gone leaves a node permanently one block short: it learns the
        # height from this epoch's proposal, fetches the block, applies it —
        # and by then the proposal it could have attested to has expired.  The
        # target is already known from the epoch before, so the right moment is
        # here, while the seat's height is still to be decided.
        if self.catchup.behind(self.world.height) > 0:
            self._catch_up(self.clock.decide_deadline(epoch))
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
                self.bodies.put(body)
                # Push the body to the seats that will need it first.  The
                # header alone would cost them a round-trip before they can
                # validate anything.
                for peer in self.seat.neighbours():
                    self.mesh.send(peer, "block", {"block": body}, epoch=epoch)

        accepted = self._gossip(epoch, grid)
        if accepted is None:
            self.last_reason = f"epoch {epoch}: {self.seat.why_not()}"
            self.log(self.last_reason)
            # The most common reason a seat cannot reach quorum is that it is
            # the odd one out, and the leader's signed header says so: a
            # proposal for height h proves h-1 exists, whoever else agreed.
            # Minus one because the proposed block is not finalised yet, and
            # asking a peer for a height nobody has applied would be asking
            # for the future.
            # Not minus one: by the end of an epoch the proposed block is
            # either finalised or it is not, and a peer only serves bodies
            # that carry a certificate — so asking for a height nobody agreed
            # costs one unanswered request, while asking for one less leaves
            # this node a block short for ever.
            self.catchup.note_height(self.seat.signed_height())
            self._catch_up(self.clock.commit_deadline(epoch))
            self._serve_until(self.clock.commit_deadline(epoch), epoch)
            return

        block, cert = accepted
        # Explicitly, and not by relying on `Seat.accepted` having set the
        # certificate in place on the object the cache happens to hold: that
        # aliasing is what left peers serving pre-agreement proposals to a
        # node trying to catch up, which then refused every one of them.
        self.bodies.put(block)
        self.world.pending_rolls[gid] = self.seat.roll(cert)
        self.world.apply_network_block(block)
        self._stamp(block)
        self.epochs_run += 1
        self.last_reason = "ok"
        self.log(f"epoch {epoch}: height {block.height} "
                 f"{block.hash()[:16]}… {len(cert.attestations)} attestations, "
                 f"{sum(1 for _ in block.transactions())} tx")
        self._serve_until(self.clock.commit_deadline(epoch), epoch)

    # ── hardening ────────────────────────────────────────────────────────────

    def _stamp(self, block):
        """Record a block as awaiting hardening, then push as far as it goes."""
        self.pending_hard[block.height] = block
        self._advance_hardening()

    def _absorb_stamps(self, payload):
        """Keep stamps for a block, whether or not this node has it yet.

        Buffering rather than dropping matters: a peer that hardens quickly
        broadcasts before a slower node has applied the block at all, and the
        first version of this dropped exactly those stamps and then wondered
        why the threshold was never reached.
        """
        block_hash = payload.get("block_hash")
        if not block_hash:
            return
        height = int(payload.get("height", 0))
        pool = self.stamp_pool.setdefault(block_hash, {})
        # Verified on arrival, not at assembly time.  One bad stamp left in the
        # pool poisons every attempt to assemble that block for ever, and the
        # first version of this spent an entire testnet run doing exactly that.
        from ..hardening.stamp import anchor_bytes, verify_stamp
        anchor = anchor_bytes(block_hash, height, self.era.spec.root)
        for stamp in payload.get("stamps") or ():
            if stamp.leaf_index in pool:
                continue
            ok, _ = verify_stamp(self.era.spec, stamp, anchor,
                                 self.hardening.difficulty_bits)
            if ok:
                pool[stamp.leaf_index] = stamp
        self._advance_hardening()

    def _advance_hardening(self):
        """Harden in order, one height at a time, as far as the stamps allow.

        Strictly in order because the anchor a turn signs is
        `H(block_hash, cumulative(prev), era_root)` — it depends on the weight
        already on the branch.  A node that mined block H+1 while still
        thinking H was unhardened would sign a different anchor from its peers
        and its stamps would verify nowhere.  That is what the first run did,
        and "turn 70: puzzle not solved" is what it looks like from the
        outside.
        """
        while True:
            height = self.history.height + 1
            block = self.pending_hard.get(height)
            if block is None:
                return
            block_hash = block.hash()
            if block_hash not in self.stamped:
                self.stamped.add(block_hash)
                try:
                    mine = self.history.harden(block, self.era,
                                               owned=self.owned)
                except Exception as exc:              # an exhausted pool
                    self.log(f"cannot stamp {block_hash[:14]}…: {exc}")
                    return
                pool = self.stamp_pool.setdefault(block_hash, {})
                for stamp in mine.stamps:
                    pool[stamp.leaf_index] = stamp
                if mine.stamps:
                    self.mesh.broadcast(
                        list(self.mesh.connected), "stamps",
                        {"block_hash": block_hash, "height": height,
                         "stamps": list(mine.stamps)})
            if not self._try_harden(block):
                return

    def _try_harden(self, block) -> bool:
        """Assemble what has arrived and accept it if it is enough.

        Lazy on purpose: the threshold is often reached an epoch or two after
        the block was agreed, and that gap is the honest shape of the thing —
        consensus finality and historical finality are different events, and
        this is the distance between them made visible rather than hidden.
        """
        block_hash = block.hash()
        pool = self.stamp_pool.get(block_hash) or {}
        if len(pool) < self.hardening.threshold:
            return False
        hardened = self.history.assemble(block, pool.values())
        ok, why = self.history.accept(hardened)
        if not ok:
            self.log(f"not hardened {block_hash[:14]}…: {why}")
            return False
        self.store.commit_hardened(hardened)
        self.pending_hard.pop(hardened.height, None)
        self.log(f"hardened height {hardened.height} with "
                 f"{len(hardened.stamps)} stamps, cumulative "
                 f"{hardened.cumulative:,}")
        return True

    def _gossip(self, epoch: int, grid):
        """Exchange until quorum or the deadline.  The rounds are gone."""
        deadline = self.clock.decide_deadline(epoch)
        neighbours = list(self.seat.neighbours())
        last_sent = 0.0
        while self.clock.now_ms() < deadline and not self.stop.is_set():
            self._drain(timeout=0.02)
            self.seat.react()
            self.work.drain(self.budget, self.clock.now_ms, max_items=4)
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
            self._catch_up(when_ms)
            self.work.drain(self.budget, self.clock.now_ms, max_items=8)
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

    def _serve_blocks(self, who: str, payload: dict):
        """Answer a peer that is behind, with what is still held.

        Only a connected peer is answered — a client has the `headers` and
        `hardened` interfaces for the spine, and no business asking a
        validator to replay bodies at it.
        """
        try:
            start = max(1, int(payload.get("from", 1)))
            end = int(payload.get("to", start))
        except (TypeError, ValueError):
            return
        end = min(end, start + BATCH - 1)
        bodies = self.bodies.range(start, end)
        if not bodies:
            return
        self.mesh.send(who, "blocks", {"blocks": bodies})
        self.log(f"catch-up: served {len(bodies)} bodies "
                 f"({start}-{end}) to {who}")

    def _ask_for_blocks(self):
        """Ask every connected peer for the next run of heights we are missing.

        Broadcast rather than chosen: any peer that still holds the range can
        answer, duplicates cost a buffer lookup, and picking a peer well needs
        the peer-quality information the trust list deliberately does not feed
        into anything that matters.
        """
        want = self.catchup.wanted(self.world.height)
        if want is None:
            return False
        start, end = want
        self.log(f"catch-up: behind by "
                 f"{self.catchup.behind(self.world.height)}, asking for "
                 f"{start}-{end}")
        self.mesh.broadcast(self.mesh.connected, "getblocks",
                            {"from": start, "to": end})
        return True

    def _roll_of_epoch(self, gid: str, epoch: int) -> AttendanceRoll:
        """The roll the ceremony of `epoch` produced, recomputed.

        `Seat.roll` is a pure function of the grid's seats, and the seats are a
        pure function of the register and the epoch seed — which is the one
        property of that stopgap worth having: a node that was absent for the
        ceremony can still work out what every node present wrote down.  Called
        with the register as it stands *before* the block is applied, which is
        where the live path calls it from too.
        """
        members = self.world.grid_members(gid)
        register = self.world.registers[gid]
        seed = h_hex("view", self.doc.first_seed, epoch, gid, 0)
        grid = Grid.seat(members, self.world.params.row_size, seed,
                         standing={n: register.standing_of(n)
                                   for n in members})
        return AttendanceRoll(grid_id=gid, epoch=epoch,
                              leader_id=grid.leader,
                              seated=tuple(sorted(grid.seats)),
                              attended=tuple(sorted(grid.seats)))

    def _apply_caught_up(self, block):
        """Validate one fetched block exactly as a seat would, then apply it.

        Nothing here is a shortcut.  The block must chain onto the tip this
        node holds, its certificate must carry the register's own quorum in
        the roster's own keys, and `SoloWorkload.validate` is the same check
        the ceremony runs — so a node adopts by catch-up only what it could
        have agreed to in the epoch it missed.
        """
        header = block.header
        if header.height != self.world.height + 1:
            return False, (f"height {header.height} does not follow "
                           f"{self.world.height}")
        if header.prev_hash != self.world.tip:
            return False, "does not chain onto the tip this node holds"
        if header.chain_id != self.doc.chain_id:
            return False, f"block is for chain {str(header.chain_id)[:20]}…"

        gid = self.grid_id()
        register = self.world.registers[gid]
        quorum = register.quorum(self.world.params.quorum_num,
                                 self.world.params.quorum_den)
        cert = block.quorum_cert
        if cert is None:
            return False, "no quorum certificate"
        ok, why = cert.verify(quorum, block.hash(), validators=self.validators)
        if not ok:
            return False, f"certificate: {why}"

        workload = SoloWorkload(self.world, gid, header.epoch,
                                self.world.params.backend_for("local"))
        ok, why = workload.validate(self.node, block)
        if not ok:
            return False, why

        # Exactly what the live path does at this point, and for the same
        # reason: a block carries the roll of the epoch *before* it, so the
        # roll this epoch produced has to be standing in `pending_rolls` before
        # the block is applied or the next block cannot be validated. Setting
        # it to the roll the block *carries* is the tempting wrong answer — it
        # is one epoch stale, and the next block is then refused with
        # "attendance roll is not the one this grid produced".
        self.world.pending_rolls[gid] = self._roll_of_epoch(gid, header.epoch)
        self.world.apply_network_block(block)
        self.bodies.put(block)
        self._stamp(block)
        self.log(f"catch-up: applied height {block.height} "
                 f"{block.hash()[:16]}…")
        return True, "ok"

    def _catch_up(self, deadline_ms: int) -> int:
        """Apply what has arrived, then ask for more.  Returns blocks applied.

        Run at ceremony priority, which sounds generous and is not: the
        reserve exists so that a proposal can be validated before the decide
        deadline, and a node this far behind cannot validate the proposal at
        all.  Spending that reserve on the one thing that would let it is the
        reserve doing its job.
        """
        if self.catchup.behind(self.world.height) <= 0:
            return 0
        applied = self.catchup.advance(
            self._apply_caught_up, lambda: self.world.height,
            budget=lambda: (self.clock.now_ms() < deadline_ms
                            and self.budget.afford(Priority.CEREMONY)[0]))
        if self.catchup.last_reason and not applied:
            self.log(f"catch-up: {self.catchup.last_reason}")
        self._ask_for_blocks()
        return applied

    def _offer_tx(self, tx, who):
        """Authenticate now, verify later.  Nothing expensive on this thread.

        The cheap half runs inline because it is 0.12 ms and because its answer
        is what decides the priority: a transaction that authenticates was
        built by someone holding spend authority over notes this node's UTXO
        set says are live, and that is the only identity a submission has.
        Everything after it is queued.
        """
        backend = self.world.params.backend_for("local")
        ok, why, auth = self.node.authenticate(tx, backend)
        if not ok:
            return
        if who in self.mesh.connected:
            priority = Priority.PEER
        elif self.node.suspect(tx):
            # A body that has already had proofs fail against it goes to the
            # back rather than being refused, because refusing it would let
            # anyone censor a transaction by splicing bad proofs onto its body.
            priority = Priority.ANON
        else:
            priority = Priority.OWNER

        def verify():
            got, reason = self.node.verify_and_admit(tx, auth, backend)
            if got:                                      # flood it onward once
                self.mesh.broadcast(
                    [p for p in self.mesh.connected if p != who], "tx",
                    {"tx": tx})
            return got

        self.work.offer(verify, priority, key=tx.txid,
                        epoch=self.budget.epoch)

    def _handle(self, who, msg, conn):
        kind, payload = msg["kind"], msg["payload"]
        if kind == "stamps":
            self._absorb_stamps(payload if isinstance(payload, dict) else {})
            return

        if kind == "tx":
            tx = payload.get("tx") if isinstance(payload, dict) else None
            if tx is not None and tx.txid not in self.node.mempool:
                self._offer_tx(tx, who)
            return

        # Catch-up, and both halves have to sit *before* the epoch guard: a
        # node that is behind is by definition not in the epoch its helper is
        # in, and the old guard is exactly why there was no way back.
        if kind == "getblocks":
            if who in self.mesh.connected:
                self._serve_blocks(who, payload if isinstance(payload, dict)
                                   else {})
            return
        if kind == "blocks":
            if who in self.mesh.connected:
                got = self.catchup.absorb(
                    (payload or {}).get("blocks") or [])
                if got:
                    self.log(f"catch-up: {got} block bodies from {who}")
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
                self.bodies.put(body)
                self.seat.offer_block(body)


def run_node(root: str, node_id: str, until_epoch=None, quiet=False):
    proc = NodeProcess(root, node_id, quiet=quiet)
    proc.run(until_epoch=until_epoch)
    return proc


def _x25519_public(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(bytes(raw))
