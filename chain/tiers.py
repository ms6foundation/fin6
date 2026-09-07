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

from dataclasses import dataclass, field

from .block import CeremonyMeta
from .ceremony import Ceremony, Grid, HonestLeader
from .crypto import Signer, h_hex
from .locality import Topology, tx_partition
from .node import Node
from .params import ChainParams
from .register import AttendanceRoll, GridRegister, Standing
from .state import ChainState, UtxoDelta, merge_deltas
from .tiered import (GENESIS_NETWORK, CeremonyBlock, CeremonyBlockHeader,
                     NetworkBlock, NetworkBlockHeader, SuperBlock,
                     SuperBlockHeader, registers_root)
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
            ok, why = self.nodes[nid].submit(tx, backend=backend)
            accepted += ok
        return accepted > 0, f"{accepted} members admitted it", grid_id

    # ── advancing ────────────────────────────────────────────────────────────

    def apply_network_block(self, block: NetworkBlock):
        """Every node applies the finalised block; every register takes its roll."""
        deltas = [c.delta for c in block.ceremony_blocks()]
        merged, _ = merge_deltas(deltas)
        for node in self.nodes.values():
            node.state.apply_delta(merged)
            node.state.height = block.header.height
            node.state.tip = block.hash()
            for tx in block.transactions():
                node._evict(tx.txid)
        for child in block.ceremony_blocks():
            reg = self.registers[child.header.grid_id]
            if child.roll is not None and child.roll.epoch >= 0:
                reg.apply(child.roll)
        self.height = block.header.height
        self.tip = block.hash()
        self.rolls = dict(self.pending_rolls)
        self.pending_rolls = {}


def bootstrap_world(node_regions: dict, endowments: dict, params: ChainParams,
                    seed: str = "genesis", asset: str = "USD",
                    newcomers: dict | None = None):
    """Build a tiered network: topology, genesis registers, wallets, nodes.

    The founding cohort of every grid starts as attesters — it has to, since a
    grid of pure apprentices can never reach quorum and so can never run the
    ceremony that would promote anyone.  The bootstrap is a trusted setup.
    `newcomers` are seated afterwards as apprentices, at zero.
    """
    from .network import Wallet
    from .notes import Note, note_id, note_vector

    topology = Topology.build(node_regions, params.grid_size, seed)

    wallets = {name: Wallet(name=name, signer=Signer.from_seed(f"wallet:{name}"),
                            params=params)
               for name in endowments}
    genesis = ChainState(params)
    for name, values in endowments.items():
        w = wallets[name]
        for value in values:
            note = Note.create(value, w.public_hex, params, asset=asset)
            genesis.issue(note_id(note_vector(note, params)))
            w.receive(note)
    genesis.height = 0
    genesis.tip = GENESIS_NETWORK

    nodes = {nid: Node(nid, Signer.from_seed(f"validator:{nid}"), params,
                       genesis.copy())
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
        nodes[nid] = Node(nid, Signer.from_seed(f"validator:{nid}"), params,
                          genesis.copy())
        world.trust[nid] = TrustList(nid)
    return world, wallets


# ═══════════════════════════════════════════════════════════════════════════════
# Workloads — what each tier builds and checks
# ═══════════════════════════════════════════════════════════════════════════════

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


class SupremeWorkload:
    """Tier 2.  The only tier that can compute the global roots."""

    name = "supreme"

    def __init__(self, world: TierWorld, supers: dict, epoch: int,
                 owner_of: dict):
        self.world = world
        self.supers = dict(supers)          # super_id -> SuperBlock
        self.epoch = epoch
        self.owner_of = dict(owner_of)

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
        block = NetworkBlock(header=None, supers=tuple(ordered))
        header = NetworkBlockHeader(
            height=self.world.height + 1, epoch=self.epoch,
            chain_id=leader.chain_id, prev_hash=self.world.tip,
            utxo_root=shadow.utxo.root, nf_root=shadow.nullifiers.root,
            super_root=block.compute_super_root(),
            registers_root=registers_root(roots))
        return NetworkBlock(header=header, supers=tuple(ordered),
                            dropped=tuple(f"{i}:{w}" for i, w in dropped))

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
            "ceremonies": (len(self.local.ceremonies) + len(self.supers.ceremonies)
                           + (1 if self.supreme else 0)),
            "directed_messages": (
                sum(r.directed_messages for r in self.local.ceremonies.values())
                + sum(r.directed_messages for r in self.supers.ceremonies.values())
                + (self.supreme.directed_messages if self.supreme else 0)),
        }

    def __repr__(self):
        return (f"TieredEpochResult(epoch={self.epoch}, {self.status}, "
                f"{self.tiers} tiers, {self.local and len(self.local.finalised)} grids) "
                f"— {self.reason}")


def run_tiered_epoch(world: TierWorld, epoch: int, base_seed: str,
                     behaviours: dict | None = None, tx_limit=None,
                     rounds: int | None = None) -> TieredEpochResult:
    """One pass up the tree, ending at the supreme mempool."""
    params = world.params
    behaviours = behaviours or {}
    topo = world.topology
    if len(topo.grid_ids()) < 2:
        raise ValueError(
            "the tiered path needs at least two grids; with one grid there is "
            "nothing to aggregate — use chain.ceremony.run_epoch, which is the "
            "one-tier case and computes the roots directly")

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
        workload=SupremeWorkload(world, supers.blocks, epoch, super_led_by),
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
