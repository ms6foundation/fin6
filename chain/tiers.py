"""The three-phase epoch: local grids, super grids, the supreme grid.

    Phase L   every local grid runs a ceremony concurrently   -> CeremonyBlock
    Phase S   the local leaders form super grids              -> SuperBlock
    Phase X   the super leaders form the supreme grid         -> NetworkBlock

Phases are sequential because each tier's membership is only known once the tier
below has finished — a super grid is made of local *leaders*.

The Ceremony machinery is not touched.  Each tier supplies a Workload saying
what its leader builds and what its seats check, and the same grid, envelope,
equivocation detection, quorum and view change run at all three scales.

Tier count follows the roster rather than configuration: with one grid there is
nothing to aggregate and the grid computes the roots itself; with one super grid
the supreme tier collapses onto it.  Otherwise all three run.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from .block import CeremonyMeta
from .ceremony import Ceremony, Grid, HonestLeader
from .crypto import Signer, h_hex, h_field
from .locality import Topology, tx_partition
from .node import Node
from .params import ChainParams
from .register import AttendanceRoll, GridRegister, Standing
from .state import ChainState, UtxoDelta, merge_deltas
from .tiered import (GENESIS_NETWORK, CeremonyBlock, CeremonyBlockHeader,
                     GridFounding, NetworkBlock, NetworkBlockHeader, SuperBlock,
                     SuperBlockHeader, foundings_root, registers_root)
from .store import undo
from .trustlist import TrustList


# ═══════════════════════════════════════════════════════════════════════════════
# The world
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TierWorld:
    params: ChainParams
    nodes: dict
    topology: Topology
    registers: dict
    rolls: dict = field(default_factory=dict)          # roll a block may carry now
    pending_rolls: dict = field(default_factory=dict)  # roll this epoch produced
    trust: dict = field(default_factory=dict)
    height: int = 0
    tip: str = GENESIS_NETWORK

    # ── views ────────────────────────────────────────────────────────────────

    def grid_members(self, grid_id: str):
        """Seated members of a grid: attesters and apprentices, not suspended."""
        reg = self.registers[grid_id]
        return [n for n in self.topology.members(grid_id)
                if reg.standing_of(n) in (Standing.ATTESTER, Standing.APPRENTICE)]

    def roll_for(self, grid_id: str) -> AttendanceRoll:
        return self.rolls.get(grid_id) or AttendanceRoll(grid_id, -1, "")

    def register_roots(self) -> dict:
        return {gid: reg.root() for gid, reg in self.registers.items()}

    def submit(self, tx, backend: str | None = None):
        """Route a transaction to the grid that owns its partition."""
        K = self.topology.n_partitions
        part = tx_partition(tx, K)
        if part is None:
            return False, "inputs span partitions; no grid may include it", None
        grid_id = next(g for g in self.topology.grid_ids()
                       if self.topology.partition_of(g) == part)
        backend = backend or self.params.backend_for("local")
        accepted = 0
        for nid in self.topology.members(grid_id):
            # A networked node holds only itself; its peers are elsewhere.
            peer = self.nodes.get(nid)
            if peer is None:
                continue
            ok, why = peer.submit(tx, backend=backend)
            accepted += ok
        return accepted > 0, f"{accepted} members admitted it", grid_id

    # ── advancing ────────────────────────────────────────────────────────────

    def apply_network_block(self, block: NetworkBlock):
        """Every node applies the finalised block; every register takes its roll.

        This is the epoch's only durable moment.  Phases L and S produced real
        signed objects, but nothing below tier 2 touches the ledger, so a node
        with a store treats the whole epoch as a journal and commits once, here.
        A crash anywhere earlier costs the epoch and nothing else.
        """
        deltas = [c.delta for c in block.ceremony_blocks()]
        merged, _ = merge_deltas(deltas)
        touched = sorted({c.header.grid_id for c in block.ceremony_blocks()
                          if c.roll is not None and c.roll.epoch >= 0})
        # Captured before anything moves: an undo record is a photograph of the
        # state the block is about to replace.
        pre = [self.registers[g] for g in touched]
        records = {nid: undo.capture(node.state, merged,
                                     height=block.header.height,
                                     block_hash=block.hash(), registers=pre)
                   for nid, node in self.nodes.items() if node.store}
        for node in self.nodes.values():
            node.state.apply_delta(merged)
            node.state.record_block(block.header.height, block.hash())
            for tx in block.transactions():
                node._evict(tx.txid)
        for child in block.ceremony_blocks():
            reg = self.registers[child.header.grid_id]
            if child.roll is not None and child.roll.epoch >= 0:
                reg.apply(child.roll)
        for founding in block.foundings:
            self._found_grid(founding)
        self.height = block.header.height
        self.tip = block.hash()
        self.rolls = dict(self.pending_rolls)
        self.pending_rolls = {}
        if block.foundings:
            self.reroute_mempools()
        for nid, record in records.items():
            node = self.nodes[nid]
            node.store.commit(block=block, delta=merged, state=node.state,
                              undo=record,
                              registers={g: self.registers[g] for g in touched})

    # ── growing ──────────────────────────────────────────────────────────────

    def _found_grid(self, founding):
        """Apply one founding: move the cohort, records intact.

        After the rolls, not before — the cohort was chosen from the state the
        epoch started in, and the epoch's own attendance still belongs to the
        grid it was earned in.
        """
        donor = self.registers[founding.donor_id]
        movers = donor.release(founding.cohort)
        self.registers[founding.grid_id] = GridRegister.found(
            founding.grid_id, movers, founding.donor_id, epoch=donor.epoch,
            attend_threshold=self.params.attend_threshold,
            forgiveness=self.params.forgiveness)
        self.topology.found_grid(founding.donor_id, founding.grid_id,
                                 founding.cohort)
        # The roll this epoch just produced still names the movers as seats of
        # the donor grid, and a register admits anyone a roll names — so
        # without this the cohort would be re-admitted to the grid it just
        # left, as apprentices, and exist in two registers at once.  Trimming
        # costs the movers credit for the ceremony they spent in a grid they
        # were leaving, which is the right way round: every node performs the
        # same trim, so the roots still agree.
        roll = self.pending_rolls.get(founding.donor_id)
        if roll is not None:
            gone = set(founding.cohort)
            self.pending_rolls[founding.donor_id] = replace(
                roll,
                seated=tuple(n for n in roll.seated if n not in gone),
                attended=tuple(n for n in roll.attended if n not in gone))

    def reroute_mempools(self):
        """K moved, so every pending transaction has a new home.

        `nf mod K` is the routing rule and K is the number of grids, so a
        founding re-homes everything in flight — not just what crosses the new
        boundary.  On a real network this is re-gossip; here it is one pass,
        and transactions that no longer belong anywhere reachable are dropped
        rather than left to sit in a mempool that will never include them.
        """
        pending = {}
        for node in self.nodes.values():
            for txid, tx in node.mempool.items():
                pending.setdefault(txid, tx)
            for txid in list(node.mempool):
                node._evict(txid)
        rerouted = 0
        for tx in pending.values():
            ok, _, _ = self.submit(tx)
            rerouted += ok
        return rerouted, len(pending)

    def admit(self, node_id: str, region: str, signer=None):
        """A node joins after genesis: seated by the seed, apprentice at zero.

        Which grid it lands in is `H(tip, node_id)`, not its own choice — free
        choice of grid is how an adversary funnels its nodes into one.
        """
        if node_id in self.nodes:
            raise ValueError(f"{node_id} is already in the network")
        gid = self.topology.assign_newcomer(node_id, region, self.tip)
        self.registers[gid].admit(node_id)
        template = self.nodes[sorted(self.nodes)[0]].state
        self.nodes[node_id] = Node(
            node_id, signer or Signer.from_seed(f"validator:{node_id}"),
            self.params, template.copy())
        self.trust[node_id] = TrustList(node_id)
        return gid

    # ── persistence ──────────────────────────────────────────────────────────

    def persist(self, store, node_ids=None):
        """Give one or more nodes a store, writing genesis if it is empty.

        The world simulates many nodes in one process; a store belongs to one
        operator, so which nodes get one is the caller's choice and usually one.
        """
        ids = list(node_ids or [sorted(self.nodes)[0]])
        if store.is_empty():
            store.initialise(self.nodes[ids[0]].state)
            store.save_registers(self.registers)
        for nid in ids:
            self.nodes[nid].store = store
        return store

    def restore_from(self, store):
        """Replace every node's ledger and the registers with what is on disk.

        The mempools, the trust lists and the topology are not restored: the
        first two are rebuilt by watching the network, and the third is derived
        from the seed.  Losing them costs an epoch, which is why none of them
        is worth an fsync.
        """
        state = store.load_state(self.params)
        for node in self.nodes.values():
            node.state = state.copy()
            node.mempool.clear()
            node._verified.clear()
            node._reserved_nf.clear()
            node._reserved_cm.clear()
        self.registers = store.load_registers()
        self.height = state.height
        self.tip = state.tip
        return self


def bootstrap_world(node_regions: dict, endowments: dict, params: ChainParams,
                    seed: str = "genesis", asset: str = "USD",
                    newcomers: dict | None = None, signers: dict | None = None,
                    note_seed: str | None = None):
    """Build a tiered network: topology, genesis registers, wallets, nodes.

    The founding cohort of every grid starts as attesters — it has to, since a
    grid of pure apprentices can never reach quorum and so can never run the
    ceremony that would promote anyone.  The bootstrap is a trusted setup.
    `newcomers` are seated afterwards as apprentices, at zero.
    """
    from .network import Wallet
    from .notes import Note, note_id, note_vector

    topology = Topology.build(node_regions, params.grid_size, seed)

    # Genesis holders get wallet keys rather than a bare signer, so a real
    # `chain.wallet.Wallet` can be reconstructed for them later.  The issuance
    # itself still carries no sealed openings — genesis mints outside a
    # transaction, which is exactly the gap part five §2 describes.
    from .keys import WalletKeys
    wallets = {name: Wallet(name=name,
                            signer=WalletKeys.from_phrase(f"genesis:{name}").signer,
                            params=params)
               for name in endowments}
    genesis = ChainState(params)
    for name, values in sorted(endowments.items()):
        w = wallets[name]
        for i, value in enumerate(values):
            if note_seed is None:
                note = Note.create(value, w.public_hex, params, asset=asset)
            else:
                # Deterministic issuance.  Without it every process computes a
                # different genesis state from the same document, because the
                # note randomness is drawn fresh — which one process can never
                # notice and seven immediately do.  The openings are therefore
                # derivable by anyone holding the document: fine for a testnet,
                # and another reason the genesis mint of design §2 is the real
                # answer.
                note = Note.create(
                    value, w.public_hex, params, asset=asset,
                    rho=h_field("genesis-rho", note_seed, name, i),
                    blinders=tuple(
                        h_field("genesis-blind", note_seed, name, i, j)
                        for j in range(params.note_blinders)))
            genesis.issue(note_id(note_vector(note, params)))
            w.receive(note)
    genesis.height = 0
    genesis.tip = GENESIS_NETWORK

    def signer_for(nid):
        # A launched network hands each node its own key; the seeded default is
        # for demos and tests, where reproducibility is the point.
        return (signers or {}).get(nid) or Signer.from_seed(f"validator:{nid}")

    nodes = {nid: Node(nid, signer_for(nid), params, genesis.copy())
             for nid in node_regions}
    registers = {
        gid: GridRegister.genesis(gid, topology.members(gid),
                                  attend_threshold=params.attend_threshold,
                                  forgiveness=params.forgiveness)
        for gid in topology.grid_ids()}

    world = TierWorld(params=params, nodes=nodes, topology=topology,
                      registers=registers,
                      trust={nid: TrustList(nid) for nid in node_regions})

    for nid, region in sorted((newcomers or {}).items()):
        gid = topology.assign_newcomer(nid, region, seed)
        registers[gid].admit(nid)
        nodes[nid] = Node(nid, signer_for(nid), params, genesis.copy())
        world.trust[nid] = TrustList(nid)
    return world, wallets


# ═══════════════════════════════════════════════════════════════════════════════
# Workloads — what each tier builds and checks
# ═══════════════════════════════════════════════════════════════════════════════

def plan_foundings(world: "TierWorld", epoch: int) -> tuple:
    """Which grid founds a child this epoch, and who moves.

    Every input is committed state — grid membership, the register, and the
    previous network block's hash — so the leader proposes nothing and every
    seat derives the same answer.  Seeding the draw from the *previous* block
    is the same trick the hardening committee uses: whoever assembles this
    block cannot grind the roster it selects.

    Two conditions, and the second is the one that keeps both sides alive:

      * the donor is over size, by the rule `Topology.needs_split` already had;
      * it has at least twice the cohort in unfaulted attesters, so the half
        that stays can still reach its own quorum.

    At most one founding an epoch.  K is the modulus in `nf mod K`, so every
    founding re-homes every transaction in flight; doing two at once would
    double that churn for no gain.
    """
    params = world.params
    size = params.founding_cohort
    for gid in world.topology.grid_ids():
        if not world.topology.needs_split(gid, params.grid_size):
            continue
        reg = world.registers[gid]
        seated = set(world.topology.members(gid))
        eligible = [n for n in reg.attesters()
                    if n in seated and not reg.members[n].faults]
        if len(eligible) < 2 * size:
            continue
        new_id = world.topology.next_grid_id(world.topology.spec(gid).region)
        ranked = sorted(eligible,
                        key=lambda n: h_hex("found", world.tip, gid, new_id, n))
        return (GridFounding(donor_id=gid, grid_id=new_id, epoch=epoch,
                             cohort=tuple(sorted(ranked[:size]))),)
    return ()


class LocalWorkload:
    """Tier 0.  Produces a delta and a register root, never a ledger root."""

    name = "local"

    def __init__(self, world: TierWorld, grid_id: str, epoch: int, backend: str):
        self.world = world
        self.grid_id = grid_id
        self.epoch = epoch
        self.backend = backend
        self.partition = world.topology.partition_of(grid_id)
        self.n_partitions = world.topology.n_partitions

    def _header(self, chosen, delta, roll, register_root, chain_id):
        from .seal import seal_root
        return CeremonyBlockHeader(
            grid_id=self.grid_id, partition=self.partition,
            n_partitions=self.n_partitions, epoch=self.epoch, chain_id=chain_id,
            prev_network_hash=self.world.tip,
            tx_root=seal_root("tx", [tx.txid for tx in chosen]),
            delta_digest=delta.digest(), roll_digest=roll.digest(),
            register_root=register_root)

    def _register_after(self, roll):
        reg = self.world.registers[self.grid_id].clone()
        if roll.epoch >= 0:
            reg.apply(roll)
        return reg.root()

    def build(self, leader: Node, meta, limit=None) -> CeremonyBlock:
        chosen, seen_nf, seen_cm, seen_out = [], set(), set(), set()
        for tx in leader.mempool.values():
            if limit is not None and len(chosen) >= limit:
                break
            if tx_partition(tx, self.n_partitions) != self.partition:
                continue
            ok, _ = leader.state.check_transaction(
                tx, verify_proof=False, seen_nf=seen_nf, seen_cm=seen_cm)
            if not ok or set(tx.output_cms) & seen_out:
                continue
            chosen.append(tx)
            seen_nf.update(tx.nullifiers)
            seen_cm.update(tx.input_cms)
            seen_out.update(tx.output_cms)

        delta = UtxoDelta.from_txs(chosen)
        roll = self.world.roll_for(self.grid_id)
        header = self._header(chosen, delta, roll, self._register_after(roll),
                              leader.chain_id)
        return CeremonyBlock(header=header, transactions=tuple(chosen),
                             delta=delta, roll=roll)

    def validate(self, node: Node, block: CeremonyBlock):
        h = block.header
        if h.grid_id != self.grid_id:
            return False, f"block is for grid {h.grid_id}, not {self.grid_id}"
        if h.epoch != self.epoch:
            return False, f"block epoch {h.epoch} != {self.epoch}"
        if h.chain_id != node.chain_id:
            return False, "wrong chain"
        if h.prev_network_hash != self.world.tip:
            return False, "does not follow the last network block"
        if h.partition != self.partition or h.n_partitions != self.n_partitions:
            return False, "wrong partition"
        if h.tx_root != block.compute_tx_root():
            return False, "tx_root does not match the transaction list"

        ok, why, delta = node.state.check_ceremony_txs(
            block.transactions, self.partition, self.n_partitions,
            already_verified=node.already_verified, backend=self.backend)
        if not ok:
            return False, why
        if delta.digest() != h.delta_digest or block.delta.digest() != h.delta_digest:
            return False, "delta digest does not match the transactions"

        roll = self.world.roll_for(self.grid_id)
        if block.roll is None or block.roll.digest() != roll.digest():
            return False, "attendance roll is not the one this grid produced"
        if h.roll_digest != roll.digest():
            return False, "roll digest does not match the roll"
        if h.register_root != self._register_after(roll):
            return False, "register_root does not follow from the roll"
        return True, "ok"


class SuperWorkload:
    """Tier 1.  Bundles its constituent grids' blocks and drops collisions."""

    name = "super"

    def __init__(self, world: TierWorld, super_id: str, children: dict,
                 epoch: int, owner_of: dict):
        self.world = world
        self.super_id = super_id
        self.children = dict(children)      # grid_id -> CeremonyBlock
        self.epoch = epoch
        self.owner_of = dict(owner_of)      # node_id -> grid_id it led

    def _assemble(self, limit=None):
        ordered = [self.children[g] for g in sorted(self.children)]
        if limit is not None:
            ordered = ordered[:limit]
        _, dropped_idx = merge_deltas([c.delta for c in ordered])
        bad = {i for i, _ in dropped_idx}
        kept = tuple(c for i, c in enumerate(ordered) if i not in bad)
        dropped = tuple((ordered[i].hash(), why) for i, why in dropped_idx)
        return kept, dropped

    def build(self, leader: Node, meta, limit=None) -> SuperBlock:
        kept, dropped = self._assemble(limit)
        block = SuperBlock(header=None, children=kept, dropped=dropped)
        header = SuperBlockHeader(
            super_id=self.super_id, epoch=self.epoch, chain_id=leader.chain_id,
            prev_network_hash=self.world.tip,
            child_root=block.compute_child_root(),
            dropped_root=block.compute_dropped_root())
        return SuperBlock(header=header, children=kept, dropped=dropped)

    def validate(self, node: Node, block: SuperBlock):
        h = block.header
        if h.super_id != self.super_id or h.epoch != self.epoch:
            return False, "super block is for another grid or epoch"
        if h.prev_network_hash != self.world.tip:
            return False, "does not follow the last network block"
        if h.child_root != block.compute_child_root():
            return False, "child_root does not match the children"
        if h.dropped_root != block.compute_dropped_root():
            return False, "dropped_root does not match"

        for child in block.children:
            if child.quorum_cert is None:
                return False, f"{child.header.grid_id}: no quorum certificate"
            reg = self.world.registers.get(child.header.grid_id)
            quorum = reg.quorum(self.world.params.quorum_num,
                                self.world.params.quorum_den) if reg else 1
            ok, why = child.quorum_cert.verify(quorum, child.hash())
            if not ok:
                return False, f"{child.header.grid_id}: {why}"
            for tx in child.transactions:
                if tx_partition(tx, child.header.n_partitions) != child.header.partition:
                    return False, (f"{child.header.grid_id} included a "
                                   f"transaction outside its partition")

        # Local knowledge: this seat led a grid, so it knows its own block.
        mine = self.owner_of.get(node.id)
        if mine is not None and mine in self.children:
            if not any(c.header.grid_id == mine for c in block.children):
                if not any(hsh == self.children[mine].hash()
                           for hsh, _ in block.dropped):
                    return False, f"my grid {mine} was silently omitted"

        _, dropped = merge_deltas([c.delta for c in block.children])
        if dropped:
            return False, "kept children still collide"
        return True, "ok"


class SoloWorkload:
    """All three tiers at once, because there is only one grid.

    One grid means there is nothing to aggregate and no sibling to collide
    with, so the super and supreme tiers would be the same seats doing the same
    work twice more.  The tempting shortcut is to run part one's single-grid
    ceremony instead — but that emits a `Block`, not a `NetworkBlock`, so the
    chain would carry two incompatible kinds of history and the move to three
    tiers would be a format change in the middle of it.  Every archive,
    snapshot and verifier would have to know both, forever.

    So the hierarchy degenerates and the format does not.  One ceremony emits
    the full nesting — a NetworkBlock over a SuperBlock over the CeremonyBlock
    — and the quorum certificate lands on the network block, because that is
    the object the seats actually agreed.  The inner blocks carry none, and
    `tiers=1` in the header is what says so out loud.
    """

    name = "solo"

    def __init__(self, world: TierWorld, grid_id: str, epoch: int, backend: str):
        self.world = world
        self.grid_id = grid_id
        self.epoch = epoch
        self.local = LocalWorkload(world, grid_id, epoch, backend)

    @property
    def super_id(self) -> str:
        return f"solo-{self.grid_id}"

    def _wrap(self, node: Node, child: CeremonyBlock):
        """Nest one ceremony block up to a network block, roots and all."""
        sup = SuperBlock(header=None, children=(child,))
        sup = SuperBlock(
            header=SuperBlockHeader(
                super_id=self.super_id, epoch=self.epoch,
                chain_id=node.chain_id, prev_network_hash=self.world.tip,
                child_root=sup.compute_child_root(),
                dropped_root=sup.compute_dropped_root()),
            children=(child,))
        merged, _ = merge_deltas([child.delta])
        shadow = node.state.copy()
        ok, why = shadow.can_apply_delta(merged)
        if not ok:
            return None, None, why
        shadow.apply_delta(merged)
        foundings = plan_foundings(self.world, self.epoch)
        block = NetworkBlock(header=None, supers=(sup,), foundings=foundings)
        header = NetworkBlockHeader(
            height=self.world.height + 1, epoch=self.epoch,
            chain_id=node.chain_id, prev_hash=self.world.tip,
            utxo_root=shadow.utxo.root, nf_root=shadow.nullifiers.root,
            super_root=block.compute_super_root(),
            registers_root=registers_root(
                {self.grid_id: child.header.register_root}),
            tiers=1, foundings_root=block.compute_foundings_root(),
            witness_root=shadow.utxo.witness_root,
            history_root=shadow.history.root)
        return NetworkBlock(header=header, supers=(sup,),
                            foundings=foundings), shadow, "ok"

    def build(self, leader: Node, meta, limit=None) -> NetworkBlock:
        child = self.local.build(leader, meta, limit)
        block, _, why = self._wrap(leader, child)
        if block is None:
            raise RuntimeError(f"solo leader cannot apply the epoch: {why}")
        return block

    def validate(self, node: Node, block: NetworkBlock):
        h = block.header
        if h.tiers != 1:
            return False, f"header claims {h.tiers} tiers, this epoch ran 1"
        if len(block.supers) != 1 or len(block.supers[0].children) != 1:
            return False, ("a one-tier block wraps exactly one grid; this one "
                           f"wraps {sum(1 for _ in block.ceremony_blocks())}")
        if block.dropped:
            return False, "nothing can be dropped when there is one grid"
        child = block.supers[0].children[0]
        if child.quorum_cert is not None:
            return False, ("the inner blocks of a one-tier block carry no "
                           "certificate; the network block carries it")

        # The seats verify the transactions themselves, exactly as they would
        # in a local ceremony — the collapse changes who signs, never who checks.
        ok, why = self.local.validate(node, child)
        if not ok:
            return False, why

        ok, why = _check_foundings(self.world, self.epoch, block)
        if not ok:
            return False, why

        expected, _, why = self._wrap(node, child)
        if expected is None:
            return False, f"epoch does not apply: {why}"
        if expected.header != h:
            return False, "the header does not match the block it wraps"
        return True, "ok"


class SupremeWorkload:
    """Tier 2.  The only tier that can compute the global roots."""

    name = "supreme"

    def __init__(self, world: TierWorld, supers: dict, epoch: int,
                 owner_of: dict, tiers: int = 3):
        self.world = world
        self.supers = dict(supers)          # super_id -> SuperBlock
        self.epoch = epoch
        self.owner_of = dict(owner_of)
        self.tiers = tiers

    def _apply(self, state: ChainState, supers):
        deltas = [c.delta for s in supers for c in s.children]
        merged, dropped = merge_deltas(deltas)
        shadow = state.copy()
        ok, why = shadow.can_apply_delta(merged)
        if not ok:
            return None, None, why
        shadow.apply_delta(merged)
        return shadow, dropped, "ok"

    def build(self, leader: Node, meta, limit=None) -> NetworkBlock:
        ordered = [self.supers[s] for s in sorted(self.supers)]
        if limit is not None:
            ordered = ordered[:limit]
        shadow, dropped, why = self._apply(leader.state, ordered)
        if shadow is None:
            raise RuntimeError(f"supreme leader cannot apply the epoch: {why}")
        roots = {c.header.grid_id: c.header.register_root
                 for s in ordered for c in s.children}
        foundings = plan_foundings(self.world, self.epoch)
        block = NetworkBlock(header=None, supers=tuple(ordered),
                             foundings=foundings)
        header = NetworkBlockHeader(
            height=self.world.height + 1, epoch=self.epoch,
            chain_id=leader.chain_id, prev_hash=self.world.tip,
            utxo_root=shadow.utxo.root, nf_root=shadow.nullifiers.root,
            super_root=block.compute_super_root(),
            registers_root=registers_root(roots), tiers=self.tiers,
            foundings_root=block.compute_foundings_root(),
            witness_root=shadow.utxo.witness_root,
            history_root=shadow.history.root)
        return NetworkBlock(header=header, supers=tuple(ordered),
                            dropped=tuple(f"{i}:{w}" for i, w in dropped),
                            foundings=foundings)

    def validate(self, node: Node, block: NetworkBlock):
        h = block.header
        if h.epoch != self.epoch:
            return False, "network block is for another epoch"
        if h.prev_hash != self.world.tip:
            return False, "does not follow the tip"
        if h.height != self.world.height + 1:
            return False, f"height {h.height} does not follow {self.world.height}"
        if h.super_root != block.compute_super_root():
            return False, "super_root does not match the super blocks"
        if h.tiers != self.tiers:
            return False, (f"header claims {h.tiers} tiers, this epoch ran "
                           f"{self.tiers}")
        ok, why = _check_foundings(self.world, self.epoch, block)
        if not ok:
            return False, why

        for sup in block.supers:
            if sup.quorum_cert is None:
                return False, f"{sup.header.super_id}: no quorum certificate"
            ok, why = sup.quorum_cert.verify(1, sup.hash())
            if not ok:
                return False, f"{sup.header.super_id}: {why}"

        mine = self.owner_of.get(node.id)
        if mine is not None and mine in self.supers:
            if not any(s.header.super_id == mine for s in block.supers):
                return False, f"my super grid {mine} was omitted"

        shadow, _, why = self._apply(node.state, block.supers)
        if shadow is None:
            return False, f"epoch does not apply: {why}"
        if shadow.utxo.root != h.utxo_root:
            return False, "utxo_root does not match the applied epoch"
        if shadow.nullifiers.root != h.nf_root:
            return False, "nf_root does not match the applied epoch"
        if shadow.utxo.witness_root != h.witness_root:
            return False, "witness_root does not match the applied epoch"
        if shadow.history.root != h.history_root:
            return False, "history_root does not match the spine"

        roots = {c.header.grid_id: c.header.register_root
                 for s in block.supers for c in s.children}
        if registers_root(roots) != h.registers_root:
            return False, "registers_root does not match the grids' registers"
        return True, "ok"


# ═══════════════════════════════════════════════════════════════════════════════
# The epoch
# ═══════════════════════════════════════════════════════════════════════════════

def _deal(items, size: int):
    """Split into ceil(n/size) groups, round-robin so none is left a singleton."""
    items = list(items)
    if not items:
        return []
    n_groups = max(1, -(-len(items) // size))
    groups = [[] for _ in range(n_groups)]
    for i, item in enumerate(items):
        groups[i % n_groups].append(item)
    return groups


@dataclass
class PhaseResult:
    tier: str
    ceremonies: dict = field(default_factory=dict)
    blocks: dict = field(default_factory=dict)
    skipped: dict = field(default_factory=dict)

    @property
    def finalised(self):
        return {k: r for k, r in self.ceremonies.items() if r.finalised}

    def __repr__(self):
        return (f"PhaseResult({self.tier}, {len(self.finalised)}/"
                f"{len(self.ceremonies)} finalised, {len(self.skipped)} skipped)")


@dataclass
class TieredEpochResult:
    epoch: int
    status: str
    reason: str
    tiers: int
    local: PhaseResult
    supers: PhaseResult
    supreme: object = None
    block: NetworkBlock | None = None

    @property
    def finalised(self) -> bool:
        return self.status == "finalised"

    def stats(self) -> dict:
        return {
            "grids": len(self.local.ceremonies),
            "grids_finalised": len(self.local.finalised),
            "super_grids": len(self.supers.ceremonies),
            "tiers": self.tiers,
            "transactions": (sum(1 for _ in self.block.transactions())
                             if self.block else 0),
            # At one tier the same ceremony is both the local one and the
            # supreme one, so counting each phase would report it twice.
            "ceremonies": (1 if self.tiers == 1 else
                           len(self.local.ceremonies)
                           + len(self.supers.ceremonies)
                           + (1 if self.supreme else 0)),
            "directed_messages": (
                (self.supreme.directed_messages if self.supreme else 0)
                if self.tiers == 1 else
                sum(r.directed_messages for r in self.local.ceremonies.values())
                + sum(r.directed_messages for r in self.supers.ceremonies.values())
                + (self.supreme.directed_messages if self.supreme else 0)),
        }

    def __repr__(self):
        return (f"TieredEpochResult(epoch={self.epoch}, {self.status}, "
                f"{self.tiers} tiers, {self.local and len(self.local.finalised)} grids) "
                f"— {self.reason}")


def _check_epoch(world: "TierWorld", epoch: int):
    """The tiered path advances the epoch number and the height together.

    Every ceremony is constructed with `height=epoch` while the network block
    takes `world.height + 1`, so a caller that skips an epoch produces
    attestations over one height and a proposal over another — and the symptom
    is a ceremony that mysteriously never sees a proposal.  Say so instead.
    """
    if epoch != world.height + 1:
        raise ValueError(
            f"epoch {epoch} does not follow height {world.height}: the tiered "
            f"path advances them together, so the next epoch is "
            f"{world.height + 1}")


def _check_foundings(world: "TierWorld", epoch: int, block: NetworkBlock):
    """Every seat re-derives the founding and refuses anything else.

    There is nothing to negotiate here — the plan is a function of state every
    seat already holds — so a leader that proposes a different cohort is not
    exercising discretion, it is lying about the state.
    """
    if block.header.foundings_root != block.compute_foundings_root():
        return False, "foundings_root does not match the block"
    expected = plan_foundings(world, epoch)
    if tuple(f.digest() for f in block.foundings) != \
            tuple(f.digest() for f in expected):
        return False, ("the founding in this block is not the one the state "
                       "calls for")
    return True, "ok"


def _run_solo_epoch(world: TierWorld, epoch: int, base_seed: str,
                    behaviours: dict, tx_limit, rounds) -> TieredEpochResult:
    """One grid, one ceremony, one certificate — and a network block all the
    same.  See SoloWorkload for why this is a collapse rather than a shortcut."""
    params = world.params
    _check_epoch(world, epoch)
    gid = world.topology.grid_ids()[0]
    reg = world.registers[gid]
    members = world.grid_members(gid)
    attesters = [n for n in members if reg.standing_of(n) == Standing.ATTESTER]
    empty = PhaseResult(tier="local")
    if len(members) < 2 or not attesters:
        empty.skipped[gid] = (f"{len(members)} seated, {len(attesters)} "
                              f"attesters — cannot form a grid")
        return TieredEpochResult(epoch, "aborted", "the only grid cannot seat",
                                 1, empty, PhaseResult(tier="super"))

    standing = {n: reg.standing_of(n) for n in members}
    seed = h_hex("view", base_seed, epoch, gid, 0)
    grid = Grid.seat(members, params.row_size, seed, standing=standing)
    # The single grid is doing the local tier's job — it verifies every
    # transaction — so it uses the local tier's proof system, not the supreme
    # tier's, whatever the block it ends up emitting is called.
    ceremony = Ceremony(
        grid, {n: world.nodes[n] for n in members}, params,
        height=epoch, epoch=epoch, rounds=rounds,
        quorum=reg.quorum(params.quorum_num, params.quorum_den),
        workload=SoloWorkload(world, gid, epoch, params.backend_for("local")),
        counting=set(attesters), grid_id=gid)
    result = ceremony.run(behaviours.get(grid.leader, HonestLeader()),
                          limit=tx_limit)

    local = PhaseResult(tier="local")
    local.ceremonies[gid] = result
    world.pending_rolls[gid] = result.roll
    atts = ({a.node_id: a for a in result.quorum_cert.attestations}
            if result.quorum_cert else {})
    head = result.block.hash() if result.block else None
    for nid in grid.seats:
        world.trust[nid].observe(result.roll, head, atts)

    if not result.finalised:
        return TieredEpochResult(epoch, "aborted", f"the only grid: {result.reason}",
                                 1, local, PhaseResult(tier="super"), result)
    local.blocks[gid] = result.block.supers[0].children[0]
    return TieredEpochResult(epoch, "finalised", "ok", 1, local,
                             PhaseResult(tier="super"), result, result.block)


def run_tiered_epoch(world: TierWorld, epoch: int, base_seed: str,
                     behaviours: dict | None = None, tx_limit=None,
                     rounds: int | None = None) -> TieredEpochResult:
    """One pass up the tree, ending at the supreme mempool."""
    params = world.params
    behaviours = behaviours or {}
    topo = world.topology
    _check_epoch(world, epoch)
    if len(topo.grid_ids()) < 2:
        return _run_solo_epoch(world, epoch, base_seed, behaviours, tx_limit,
                               rounds)

    # ── Phase L ──────────────────────────────────────────────────────────────
    local = PhaseResult(tier="local")
    for gid in topo.grid_ids():
        reg = world.registers[gid]
        members = world.grid_members(gid)
        attesters = [n for n in members if reg.standing_of(n) == Standing.ATTESTER]
        if len(members) < 2 or not attesters:
            local.skipped[gid] = (f"{len(members)} seated, {len(attesters)} "
                                  f"attesters — cannot form a grid")
            continue
        standing = {n: reg.standing_of(n) for n in members}
        seed = h_hex("view", base_seed, epoch, gid, 0)
        grid = Grid.seat(members, params.row_size, seed, standing=standing)
        ceremony = Ceremony(
            grid, {n: world.nodes[n] for n in members}, params,
            height=epoch, epoch=epoch, rounds=rounds,
            quorum=reg.quorum(params.quorum_num, params.quorum_den),
            workload=LocalWorkload(world, gid, epoch,
                                   params.backend_for("local")),
            counting=set(attesters), grid_id=gid)
        result = ceremony.run(behaviours.get(grid.leader, HonestLeader()),
                              limit=tx_limit)
        local.ceremonies[gid] = result
        world.pending_rolls[gid] = result.roll
        if result.finalised:
            local.blocks[gid] = result.block

        # Every seat folds what it watched into its own private trust list.
        atts = ({a.node_id: a for a in result.quorum_cert.attestations}
                if result.quorum_cert else {})
        head = result.block.hash() if result.block else None
        for nid in grid.seats:
            world.trust[nid].observe(result.roll, head, atts)

    if not local.blocks:
        return TieredEpochResult(epoch, "aborted", "no local grid finalised", 1,
                                 local, PhaseResult(tier="super"))

    # ── Phase S ──────────────────────────────────────────────────────────────
    led_by = {r.grid.leader: gid for gid, r in local.ceremonies.items()
              if r.finalised}
    leader_ids = sorted(led_by)
    supers = PhaseResult(tier="super")

    for j, members in enumerate(_deal(leader_ids, params.grid_size)):
        sid = f"super-{j}"
        children = {led_by[n]: local.blocks[led_by[n]] for n in members}
        if len(members) < 2:
            supers.skipped[sid] = "single leader — nothing to agree with"
            continue
        seed = h_hex("view", base_seed, epoch, sid, 0)
        grid = Grid.seat(members, params.row_size, seed)
        ceremony = Ceremony(
            grid, {n: world.nodes[n] for n in members}, params,
            height=epoch, epoch=epoch, rounds=rounds,
            quorum=params.quorum_size(len(members)),
            workload=SuperWorkload(world, sid, children, epoch, led_by),
            grid_id=sid)
        result = ceremony.run(behaviours.get(grid.leader, HonestLeader()))
        supers.ceremonies[sid] = result
        if result.finalised:
            supers.blocks[sid] = result.block

    if not supers.blocks:
        return TieredEpochResult(epoch, "aborted", "no super grid finalised", 2,
                                 local, supers)

    # ── Phase X ──────────────────────────────────────────────────────────────
    super_led_by = {r.grid.leader: sid for sid, r in supers.ceremonies.items()
                    if r.finalised}
    super_leaders = sorted(super_led_by)
    if len(super_leaders) >= 2:
        supreme_members, tiers = super_leaders, 3
    else:
        # One super grid: the supreme tier collapses onto it, exactly as the
        # sizing rule says it should below g^2 nodes.
        only = next(iter(supers.finalised.values()))
        supreme_members, tiers = sorted(only.grid.seats), 2

    seed = h_hex("view", base_seed, epoch, "supreme", 0)
    grid = Grid.seat(supreme_members, params.row_size, seed)
    ceremony = Ceremony(
        grid, {n: world.nodes[n] for n in supreme_members}, params,
        height=epoch, epoch=epoch, rounds=rounds,
        quorum=params.quorum_size(len(supreme_members)),
        workload=SupremeWorkload(world, supers.blocks, epoch, super_led_by,
                                 tiers=tiers),
        grid_id="supreme")
    supreme = ceremony.run(behaviours.get(grid.leader, HonestLeader()))

    if not supreme.finalised:
        return TieredEpochResult(epoch, "aborted",
                                 f"supreme grid: {supreme.reason}", tiers,
                                 local, supers, supreme)

    return TieredEpochResult(epoch, "finalised", "ok", tiers, local, supers,
                             supreme, supreme.block)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase H — hardening the agreed block into history
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HistoryResult:
    epoch: TieredEpochResult
    hardened: object = None
    accepted: bool = False
    reason: str = "not attempted"

    @property
    def finalised(self):
        return self.epoch.finalised and self.accepted

    def __repr__(self):
        return (f"HistoryResult(epoch={self.epoch.epoch}, "
                f"{'hardened' if self.accepted else 'not hardened'}"
                f"{'' if self.accepted else ': ' + self.reason})")


def run_epoch_to_history(world: TierWorld, history, era, epoch: int,
                         base_seed: str, apply_block: bool = True,
                         owned=None, absent=(), **kw) -> HistoryResult:
    """A full epoch: consensus through phase X, then hardening into history.

    The supreme grid produces an agreed block; that block is reversible until
    turns have burned themselves on it.  Only once the hardened block is accepted
    does the world advance.
    """
    result = run_tiered_epoch(world, epoch, base_seed, **kw)
    if not result.finalised:
        return HistoryResult(epoch=result, reason=result.reason)

    hardened = history.harden(result.block, era, owned=owned, absent=absent)
    ok, why = history.accept(hardened)
    if ok and apply_block:
        world.apply_network_block(result.block)
    return HistoryResult(epoch=result, hardened=hardened, accepted=ok,
                         reason=why)
