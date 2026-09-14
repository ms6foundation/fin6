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
from . import protocol
from . import seats as seats_mod
from .tiered import (GENESIS_NETWORK, CeremonyBlock, CeremonyBlockHeader,
                     GridFounding, GridMerge, NetworkBlock,
                     NetworkBlockHeader, SuperBlock, SuperBlockHeader,
                     foundings_root, merges_root, registers_root, tier_service)
from .store import undo
from .trustlist import TrustList


# ═══════════════════════════════════════════════════════════════════════════════
# The world
# ═══════════════════════════════════════════════════════════════════════════════

#: How many views the supreme tier may spend before it gives up on an epoch.
#:
#: A budget rather than a guarantee, the same shape as the network path's
#: `MAX_VIEWS`: if every view fails the epoch produces nothing, exactly as it
#: did before, and the chain recovers at the next one.  Not a `ChainParams`
#: field on purpose — over a network the count is arithmetic from the decide
#: window (`Clock.views_for`) rather than a setting, and a number every node
#: must agree on has no business being configurable per node.  Review C2,
#: Road C.
SUPREME_VIEWS = 3


def _behaviour(behaviours: dict, tier: str, leader: str):
    """What this leader does, at this tier.

    A behaviour keyed by node id applies wherever that node leads, which is
    what the harness wanted while there was one tier.  With three it is too
    blunt to stage the failure C2 is about: silencing the supreme leader also
    silences it in its own grid, so the local phase changes, so the committee
    changes, and the experiment measures something else.  A `(tier, node_id)`
    key aims at one seat in one ceremony; a bare node id still means everywhere.
    """
    return (behaviours.get((tier, leader))
            or behaviours.get(leader)
            or HonestLeader())


@dataclass
class TierWorld:
    params: ChainParams
    nodes: dict
    topology: Topology
    registers: dict
    rolls: dict = field(default_factory=dict)          # roll a block may carry now
    pending_rolls: dict = field(default_factory=dict)  # roll this epoch produced
    #: The certificate that finalised the last network block, and who led the
    #: ceremony that produced it.  Together these are everything the next
    #: block's roll is derived from, and both come off the chain rather than
    #: out of a seat's memory of what it saw.
    prev_certs: dict = field(default_factory=dict)   # grid_id -> QuorumCert
    prev_leaders: dict = field(default_factory=dict)  # grid_id -> node_id
    #: What the last applied block said about service at the tiers above the
    #: grids, as {node_id: (seated, attended, led)}.  Credited into the
    #: registers one block later — the same beat an attendance roll keeps, and
    #: for the same reason: the register root a block commits has to be one
    #: every seat can compute before the block exists.  Review C2 §7.
    prev_service: dict = field(default_factory=dict)
    #: The roster, so a certificate's signatures are checked against the keys
    #: the genesis document names rather than the keys the certificate carries
    #: about itself.  A real node sets this from the document; the simulation
    #: leaves it empty and `roster` derives it from the nodes it holds, which
    #: is the same set and stays right when a newcomer is admitted mid-run.
    validator_keys: dict = field(default_factory=dict)
    #: Fault reports observed in the epoch just finished, waiting to be
    #: carried by the next block.  Not persisted, and the cost is small and
    #: worth stating: an equivocation seen in the last seconds before a
    #: restart is not punished, because the report that would have carried it
    #: was in memory.  Re-observing it needs the leader to do it again.
    pending_faults: tuple = ()
    #: {protocol version: activation height}, from the genesis document.  Both
    #: the builder and the validator read it, so a block's claimed rule set is
    #: checked against the schedule rather than against whatever the producer
    #: happened to be running.  Empty means "version 1 for ever", which is what
    #: a chain that has never scheduled a change looks like.
    activations: dict = field(default_factory=dict)
    trust: dict = field(default_factory=dict)
    height: int = 0
    tip: str = GENESIS_NETWORK

    # ── views ────────────────────────────────────────────────────────────────

    def grid_members(self, grid_id: str):
        """Seated members of a grid: attesters and apprentices, not suspended."""
        reg = self.registers[grid_id]
        return [n for n in self.topology.members(grid_id)
                if reg.standing_of(n) in (Standing.ATTESTER, Standing.APPRENTICE)]

    @property
    def roster(self) -> dict:
        if self.validator_keys:
            return self.validator_keys
        return {nid: n.public_hex for nid, n in self.nodes.items()}

    def roll_for(self, grid_id: str) -> AttendanceRoll:
        """The roll the last epoch's certificate proves, for this grid.

        Derived rather than remembered.  This used to return `self.rolls`,
        which was whatever the seat in this process had assembled from its own
        envelope — objective in the simulation, where one process holds every
        seat, and not objective anywhere else.
        """
        cert = self.prev_certs.get(grid_id)
        if cert is None:
            return AttendanceRoll(grid_id, -1, "")
        return AttendanceRoll.from_cert(grid_id, cert,
                                        self.grid_members(grid_id),
                                        self.prev_leaders.get(grid_id, ""))

    def register_roots(self) -> dict:
        return {gid: reg.root() for gid, reg in self.registers.items()}

    def seat_order(self, grid_id: str) -> tuple:
        """The order a certificate for this grid indexes into.

        The same seated membership `grid_members` returns, sorted — derived
        from the committed register on both sides rather than carried by the
        thing it is supposed to authenticate.
        """
        return seats_mod.canonical_order(self.grid_members(grid_id))

    def seats_root_for(self, grid_ids) -> str:
        return seats_mod.seats_root({gid: self.seat_order(gid)
                                     for gid in grid_ids})

    def quorum_for(self, grid_id: str) -> int:
        """The attestations a ceremony in this grid needs, right now.

        Right now is the operative phrase and the whole of review B4: this is
        the register as the ceremony runs, before the block that carries the
        roll has been applied. A verifier asking the same question after the
        fact gets a different answer across a founding, which is why the number
        is committed in the header rather than re-derived.
        """
        reg = self.registers[grid_id]
        return reg.quorum(self.params.quorum_num, self.params.quorum_den)

    def verify_cert(self, grid_id: str, cert, quorum: int, block_hash: str):
        """A certificate checked against the roster *and* the seats.

        One method rather than two call sites, because the two questions are
        not separable: a signature from a key the genesis document names is not
        evidence that the signer sits in this grid, and quorum is a fraction of
        a grid. Until the seat order was committed this could not be checked
        honestly — a validator would have been comparing against its own idea
        of the membership; now it compares against the header's.
        """
        return cert.verify(quorum, block_hash, validators=self.roster,
                           seats=self.seat_order(grid_id), grid_id=grid_id)

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
        # Before anything moves.  A node that has reached an activation height
        # for a version it does not implement has three options and only one
        # is honest: apply under the rules it knows (a silent fork, and the
        # operator sees a running node), refuse the block as invalid (looks
        # exactly like the network having failed, and invites someone to
        # "fix" it), or stop and say which version it needs.  An outage you
        # can diagnose is cheaper than a fork you cannot see.
        protocol.require(block.header.height, self.activations)

        deltas = [c.delta for c in block.ceremony_blocks()]
        merged, _ = merge_deltas(deltas)
        # What this block says about the tiers above the grids.  Derived from
        # the block rather than carried in it — see `tiered.tier_service` — and
        # read here because the grids it credits are not always the grids that
        # produced a roll, so both have to be in `touched` or a node would
        # write a register it did not save and undo a block it could not
        # reverse.
        service = self.prev_service
        served_in = {self.topology.grid_of(nid) for nid in service
                     if nid in self.topology.assignment}
        touched = sorted({c.header.grid_id for c in block.ceremony_blocks()
                          if c.roll is not None and c.roll.epoch >= 0}
                         | served_in)
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
        from .tiered import faulted_from
        for child in block.ceremony_blocks():
            reg = self.registers[child.header.grid_id]
            if child.roll is not None and child.roll.epoch >= 0:
                # The faulted set comes out of the block, so every node
                # computes the same one and the register root agrees.  This is
                # the first time anything has passed `faulted` at all: the
                # parameter has been on `apply` since part two and the network
                # path always passed nothing, so a provable fault cost its
                # author exactly nothing.
                reg.apply(child.roll,
                          faulted=faulted_from(child.faults, self.params))
        # After the rolls and before the grids move, so a member that is about
        # to be moved by a founding is credited in the grid it served from.
        if service:
            for reg in self.registers.values():
                reg.credit_service(service)
        for founding in block.foundings:
            self._found_grid(founding)
        for merge in block.merges:
            self._merge_grid(merge)
        self.height = block.header.height
        self.tip = block.hash()
        self.rolls = dict(self.pending_rolls)
        self.pending_rolls = {}
        # What the *next* block's roll is derived from.  Taken off the block
        # that was just applied rather than out of a seat's memory, which is
        # what makes a node that was absent for the ceremony able to validate
        # the next one.
        # Per grid, because a grid's roll is proved by *its* certificate. The
        # network block's certificate is the supreme grid's attestations, and
        # crediting a local grid's members from it would credit the wrong
        # seats entirely — which is only invisible when there is one grid and
        # the two are the same thing.
        for child in block.ceremony_blocks():
            gid = child.header.grid_id
            cert = child.quorum_cert or block.quorum_cert
            if cert is not None:
                self.prev_certs[gid] = cert
            if child.header.leader_id:
                self.prev_leaders[gid] = child.header.leader_id
        # A grid that has been merged away must not go on being the source of
        # the next epoch's roll, or a node restarting from the store would
        # find a certificate for a grid that no longer exists.
        for gid in [g for g in self.prev_certs if g not in self.registers]:
            self.prev_certs.pop(gid)
        for gid in [g for g in self.prev_leaders if g not in self.registers]:
            self.prev_leaders.pop(gid)
        # What the *next* block's registers will be credited from, taken off
        # the block that was just applied rather than out of a seat's memory —
        # the same rule `prev_certs` follows two lines above.
        self.prev_service = tier_service(block)
        self.pending_faults = ()
        if block.foundings or block.merges:
            self.reroute_mempools()
        for nid, record in records.items():
            node = self.nodes[nid]
            node.store.commit(block=block, delta=merged, state=node.state,
                              undo=record,
                              # A grid merged away in this block is in
                              # `touched` — it ran a ceremony — and is no
                              # longer a register.  `retired` below is what
                              # removes it; writing it first would be a
                              # KeyError.
                              registers={g: self.registers[g] for g in touched
                                         if g in self.registers},
                              # Written every time, because a block carries the
                              # roll of the epoch before it: a node that comes
                              # back without this cannot validate the next
                              # block, whether it is catching up or was never
                              # behind at all.
                              rolls=self.rolls,
                              # The next block's roll is derived from these,
                              # so a node that comes back without them cannot
                              # validate anything — the same lesson `rolls`
                              # taught, and the same fix.
                              certs=self.prev_certs,
                              leaders=self.prev_leaders,
                              service=self.prev_service,
                              # Upserts alone would leave a merged-away grid
                              # in the store to be resurrected by the next
                              # `load_registers` — with members who are now in
                              # two registers at once.
                              retired=tuple(m.from_id for m in block.merges))

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

    def _merge_grid(self, merge):
        """Apply one merge: the whole grid moves, records intact.

        After the rolls, like a founding, and for the same reason — the epoch's
        attendance was earned in the grid that ran the ceremony, so it is
        credited there before that grid stops existing.

        What it costs is the *next* block's roll for the departing grid: those
        seats will be seated in the target from here on, and a register applies
        one roll per epoch, so the pending roll is dropped rather than
        re-keyed.  That is one ceremony of attendance for everyone who moved —
        the same trade `_found_grid` makes with its trim, deterministic, and
        every node makes it identically.
        """
        gone = self.registers.pop(merge.from_id)
        self.registers[merge.into_id].absorb(gone)
        self.topology.merge_grid(merge.from_id, merge.into_id)
        self.pending_rolls.pop(merge.from_id, None)

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

        Among the grids that still have room: a grid runs at most
        `admit_rate` × its attester count apprenticeships at a time, so the
        composition of a grid changes at a bounded rate rather than all at
        once when a cohort admitted together finishes its gate.  A newcomer
        that arrives when every grid in its region is full is refused, not
        queued — the caller can try again next epoch, by which time promotions
        will have opened seats.  See review C5.
        """
        if node_id in self.nodes:
            raise ValueError(f"{node_id} is already in the network")
        gid = self.topology.assign_newcomer(
            node_id, region, self.tip, has_room=self.has_room)
        self.registers[gid].admit(node_id)
        template = self.nodes[sorted(self.nodes)[0]].state
        self.nodes[node_id] = Node(
            node_id, signer or Signer.from_seed(f"validator:{node_id}"),
            self.params, template.copy())
        self.trust[node_id] = TrustList(node_id)
        return gid

    def has_room(self, grid_id: str) -> bool:
        """Can this grid take on another apprenticeship?  Review C5."""
        return self.registers[grid_id].has_room(self.params.admit_num,
                                                self.params.admit_den)

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

    def adopt(self, state, registers: dict, rolls: dict | None = None,
              certs: dict | None = None, leaders: dict | None = None,
              service: dict | None = None):
        """Take a snapshot's state as this world's, in memory.

        The mirror of `restore_from`, and the difference is where the state
        came from: `restore_from` reads what this node wrote, `adopt` takes
        what a peer sent and a header proved. Everything else is the same, and
        the mempools go for the same reason — they describe a chain this node
        is no longer on.
        """
        for node in self.nodes.values():
            node.state = state.copy()
            node.mempool.clear()
            node._verified.clear()
            node._reserved_nf.clear()
            node._reserved_cm.clear()
        self.registers = dict(registers)
        self.rolls = dict(rolls or {})
        self.prev_certs = dict(certs or {})
        self.prev_leaders = dict(leaders or {})
        self.prev_service = dict(service or {})
        self.pending_rolls = {}
        self.pending_faults = ()
        self.height = state.height
        self.tip = state.tip
        return self

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
        self.rolls = store.load_rolls()
        self.prev_certs, self.prev_leaders = store.load_certs()
        self.prev_service = store.load_service()
        self.pending_rolls = {}
        self.pending_faults = ()
        self.height = state.height
        self.tip = state.tip
        return self


def bootstrap_world(node_regions: dict, endowments: dict, params: ChainParams,
                    seed: str = "genesis", asset: str = "USD",
                    newcomers: dict | None = None, signers: dict | None = None,
                    note_seed: str | None = None, mint_cms=None):
    """Build a tiered network: topology, genesis registers, holders, nodes.

    The founding cohort of every grid starts as attesters — it has to, since a
    grid of pure apprentices can never reach quorum and so can never run the
    ceremony that would promote anyone.  The bootstrap is a trusted setup.
    `newcomers` are seated afterwards as apprentices, at zero.
    """
    from .network import Holder
    from .notes import Note, note_id, note_vector

    topology = Topology.build(node_regions, params.grid_size, seed)

    # A genesis holder's spend key is derived from a phrase the same way a
    # user's is, so a real `wallet.Wallet` can be reconstructed for it later —
    # which is what `fin6 wallet import-genesis` does.  The derivation lives in
    # `crypto` precisely so the ledger can do this without importing `wallet`.
    # The issuance itself still carries no sealed openings: genesis mints
    # outside a transaction, which is the gap part five §2 describes.
    from .crypto import seed_from_phrase, spend_signer
    holders = {name: Holder(name=name,
                            signer=spend_signer(seed_from_phrase(
                                f"genesis:{name}")),
                            params=params)
               for name in endowments}
    genesis = ChainState(params)
    if mint_cms is not None:
        # Minted.  The genesis UTXO set is the mint's commitments and nothing
        # else: every node issues exactly these, so every node computes the
        # same state, and no node learns a value.  The holders here are empty
        # by construction — opening a genesis note needs the published mint
        # artifact and the holder's own key, which is `wallet.genesis_mint`'s
        # job and not the ledger's (review A5).
        for cm in mint_cms:
            genesis.issue(cm)
        genesis.height = 0
        genesis.tip = GENESIS_NETWORK
        return _finish_bootstrap(topology, genesis, holders, node_regions,
                                 params, seed, newcomers, signers)
    for name, values in sorted(endowments.items()):
        w = holders[name]
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
    return _finish_bootstrap(topology, genesis, holders, node_regions, params,
                             seed, newcomers, signers)


def _finish_bootstrap(topology, genesis, holders, node_regions, params, seed,
                      newcomers, signers):
    """Everything after the money: nodes, registers, the world itself.

    One function because there are now two ways to put the money in — issued
    values, or a mint's commitments — and exactly one way to build what holds
    them."""
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
        gid = topology.assign_newcomer(nid, region, seed,
                                       has_room=world.has_room)
        registers[gid].admit(nid)
        nodes[nid] = Node(nid, signer_for(nid), params, genesis.copy())
        world.trust[nid] = TrustList(nid)
    return world, holders


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


def plan_merges(world: "TierWorld", epoch: int) -> tuple:
    """Which grid folds into a sibling this epoch, and who moves.

    The other half of `plan_foundings`, and the answer to the review's
    observation that a network which shrinks keeps grids it cannot fill.
    Derived from the same committed state, so the leader proposes nothing.

    Three conditions:

      * the grid is below half the target size in members that still hold a
        seat, by the rule `Topology.needs_merge` has had since part four and
        nothing called.  Seats rather than rows, because nothing removes a
        node from a topology: a grid shrinks by its members being suspended or
        going dark, never by the table getting shorter;
      * a **sibling in the same region** can take it without going over the
        split threshold — otherwise the merge would oscillate straight back
        into a founding, and the network would churn K every other epoch;
      * no founding is planned this epoch.  Both move K, and doing them
        together would re-home every transaction in flight twice for no gain;
      * and, implicitly, there is more than one grid.  A network that has
        shrunk to a single grid has nothing to merge into and is supposed to
        keep it: one grid is the degenerate case the tiers collapse onto, not
        an error state.

    A grid cannot merge across regions.  Locality is the point of the
    assignment — a grid's members are meant to be near each other — so a region
    whose only grid has emptied keeps it rather than exporting its members.
    """
    params = world.params
    topo = world.topology
    if len(topo.grids) < 2 or plan_foundings(world, epoch):
        return ()
    for gid in topo.grid_ids():
        reg = world.registers[gid]
        if not topo.needs_merge(gid, params.grid_size,
                                live=len(reg.seated_members())):
            continue
        movers = topo.members(gid)
        room = [g for g in topo.grids_in(topo.spec(gid).region)
                if g != gid
                and len(topo.members(g)) + len(movers) <= 2 * params.grid_size]
        if not room:
            continue
        # The smallest sibling, so the merge does not create the next split.
        # The tie-break is the previous block's hash, for the same reason the
        # founding cohort is drawn from it: whoever assembles this block must
        # not be able to choose where a grid's members land.
        target = min(room, key=lambda g: (len(topo.members(g)),
                                          h_hex("merge", world.tip, gid, g)))
        return (GridMerge(from_id=gid, into_id=target, epoch=epoch,
                          movers=tuple(sorted(movers))),)
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

    def _header(self, chosen, delta, roll, register_root, chain_id,
                leader_id="", prev_cert=None, faults=()):
        from .seal import seal_root
        from .tiered import faults_digest, prev_cert_digest
        return CeremonyBlockHeader(
            grid_id=self.grid_id, partition=self.partition,
            n_partitions=self.n_partitions, epoch=self.epoch, chain_id=chain_id,
            prev_network_hash=self.world.tip,
            tx_root=seal_root("tx", [tx.txid for tx in chosen]),
            delta_digest=delta.digest(), roll_digest=roll.digest(),
            register_root=register_root, leader_id=leader_id,
            prev_cert_digest=prev_cert_digest(prev_cert),
            faults_digest=faults_digest(faults),
            quorum=self.world.quorum_for(self.grid_id))

    def roll_from(self, block):
        """The roll a block's own certificate proves, for this grid."""
        if block.prev_cert is None:
            return AttendanceRoll(self.grid_id, -1, "")
        return AttendanceRoll.from_cert(
            self.grid_id, block.prev_cert,
            self.world.grid_members(self.grid_id),
            block.roll.leader_id if block.roll is not None else "")

    def _register_after(self, roll, faulted=()):
        """The root this block commits: the roll applied, then the service.

        Both are functions of the *previous* network block, which every seat
        holds before this one exists, so the root is checkable rather than
        announced.  The order matters and is the same order
        `apply_network_block` uses — a root computed one way here and the other
        way there would be a fork with no author.
        """
        reg = self.world.registers[self.grid_id].clone()
        if roll.epoch >= 0:
            reg.apply(roll, faulted=faulted)
        reg.credit_service(self.world.prev_service)
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

        from .tiered import faulted_from
        delta = UtxoDelta.from_txs(chosen)
        roll = self.world.roll_for(self.grid_id)
        prev_cert = self.world.prev_certs.get(self.grid_id)
        faults = tuple(fr for fr in self.world.pending_faults
                       if fr.verify() and fr.substantiated(self.world.params))
        faulted = faulted_from(faults, self.world.params)
        header = self._header(
            chosen, delta, roll,
            self._register_after(roll, faulted), leader.chain_id,
            leader_id=getattr(meta, "leader_id", "") or leader.id,
            prev_cert=prev_cert, faults=faults)
        return CeremonyBlock(header=header, transactions=tuple(chosen),
                             delta=delta, roll=roll, prev_cert=prev_cert,
                             faults=faults)

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

        # The certificate of the epoch before, and everything that follows
        # from it.  Checked before the roll, because the roll is now derived
        # from it: a certificate that does not belong to this chain cannot be
        # allowed to define who attended.
        from .tiered import faulted_from
        ok, why = self._check_prev_cert(node, block)
        if not ok:
            return False, why
        if h.prev_cert_digest != block.compute_prev_cert_digest():
            return False, "prev_cert digest does not match the certificate"
        if h.faults_digest != block.compute_faults_digest():
            return False, "faults digest does not match the reports"
        for fr in block.faults:
            if not fr.verify():
                return False, f"fault report from {fr.reporter} is not signed"
            if not fr.substantiated(self.world.params):
                # A leader that could have a claim believed without evidence
                # could suspend anyone it disliked, so a report that does not
                # prove itself does not travel — it fails the block.
                return False, (f"fault report from {fr.reporter} does not "
                               f"substantiate itself ({fr.kind})")
        faulted = faulted_from(block.faults, self.world.params)

        # Derived from the certificate *in the block*, not from anything this
        # node assembled: that is what makes it the same for everyone.
        if block.roll is None:
            return False, "no attendance roll"
        roll = self.roll_from(block)
        if block.roll.digest() != roll.digest():
            return False, "attendance roll is not the one the certificate proves"
        if h.roll_digest != roll.digest():
            return False, "roll digest does not match the roll"
        if h.register_root != self._register_after(roll, faulted):
            return False, "register_root does not follow from the roll"
        # Checked against the register *this* node is running the ceremony
        # under, which is the same one the leader used — so among full nodes
        # the committed quorum is verified rather than announced, and anybody
        # reading the block later can take it at the weight of that agreement
        # (review B4).
        if h.quorum != self.world.quorum_for(self.grid_id):
            return False, (f"header claims a quorum of {h.quorum}, this grid "
                           f"needs {self.world.quorum_for(self.grid_id)}")
        return True, "ok"

    def _check_prev_cert(self, node, block):
        """Verify the certificate the block derived its roll from.

        The thing to get right here is *where agreement comes from*, and I got
        it wrong once by assuming it came from every node holding the same
        certificate. It does not, and `Seat.roll` says so: each seat assembles
        its own certificate from its own envelope, so a network of four nodes
        holds four certificates for the same block — three attestations here,
        four there — and nothing assembled after agreement is agreed. Checking
        the leader's certificate against the one this node happened to build
        stalled the network within six epochs.

        Agreement comes from the block *carrying* the evidence. Every node
        derives the roll from the same bytes because they are in the block, so
        there is nothing left to differ about. What this method has to
        establish is only that those bytes are not invented:

          * every attestation verifies, against a key in the roster, for this
            chain, this height, and the block the certificate names;
          * the certificate is for the height this block follows, so a leader
            cannot reach back for an older epoch's attenders.

        What is deliberately *not* checked is the quorum count, and that is
        not laziness. Quorum is over attesters and apprentices get promoted,
        so a grid's attester count rises over its life: a certificate made
        when there were seven attesters met the quorum of seven, and asking
        whether it meets the quorum of fifteen is a question no register this
        node holds can answer. It also does not need answering — this node
        holds the block that certificate finalised, and accepting that block
        required the certificate to carry the quorum of its own epoch.

        The residual, stated rather than buried: a leader may present a
        certificate missing attestations it saw, under-crediting seats that
        did attend. That is griefing and not theft — every node agrees on the
        roll, the harm is one epoch of one seat's attendance streak, and the
        leadership rotates next epoch. The same is true of an omitted shadow
        and of the leader named in the roll, which only moves a counter.
        """
        cert = block.prev_cert
        if self.world.height == 0 or self.world.prev_certs.get(
                self.grid_id) is None:
            # Genesis, or a grid founded this epoch: no ceremony of its own has
            # happened yet, so there is no certificate to follow. Safe to read
            # as "never" rather than "forgotten" only because certificates are
            # persisted.
            if cert is not None:
                return False, ("this grid has produced no block, so it "
                               "follows no certificate")
            return True, "ok"
        if cert is None:
            return False, "no certificate for the previous epoch"
        if cert.chain_id != node.chain_id:
            return False, "previous certificate is for another chain"
        if cert.height != self.world.height:
            return False, (f"certificate is for height {cert.height}, the "
                           f"chain is at {self.world.height}")
        if not cert.signers:
            return False, "previous certificate carries no attestations"
        ok, why = cert.verify(1, cert.block_hash,
                              validators=self.world.roster)
        if not ok:
            return False, f"previous certificate: {why}"
        return True, "ok"


class SuperWorkload:
    """Tier 1.  Bundles its constituent grids' blocks and drops collisions."""

    name = "super"

    def __init__(self, world: TierWorld, super_id: str, children: dict,
                 epoch: int, owner_of: dict, leader_id: str = ""):
        self.world = world
        self.super_id = super_id
        self.children = dict(children)      # grid_id -> CeremonyBlock
        self.epoch = epoch
        self.owner_of = dict(owner_of)      # node_id -> grid_id it led
        self.leader_id = leader_id
        #: Who this ceremony seated as leader.  Every seat derived it from the
        #: same seed, so it is not a claim the block gets to make: a header
        #: naming anybody else is refused.  It is in the header because
        #: standing at this tier is credited from what the block names
        #: (review C2 §7).

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
            dropped_root=block.compute_dropped_root(),
            leader_id=self.leader_id or getattr(meta, "leader_id", "")
            or leader.id)
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
        if self.leader_id and h.leader_id != self.leader_id:
            return False, (f"header names {h.leader_id or 'nobody'} as leader; "
                           f"this view seated {self.leader_id}")

        for child in block.children:
            if child.quorum_cert is None:
                return False, f"{child.header.grid_id}: no quorum certificate"
            # The header's number, after `LocalWorkload.validate` has checked
            # it against the register the ceremony ran under: one place decides
            # what the quorum was, and everything downstream reads it.
            quorum = child.header.quorum or 1
            # `seats` as well as the roster: a signature from a key the
            # genesis document names is not evidence that the signer sits in
            # *this* grid, and quorum is a fraction of a grid.  The order is
            # the one committed in the header, so a validator and a builder
            # cannot be reading different memberships.
            ok, why = self.world.verify_cert(
                child.header.grid_id, child.quorum_cert, quorum, child.hash())
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
        merges = plan_merges(self.world, self.epoch)
        block = NetworkBlock(header=None, supers=(sup,), foundings=foundings,
                             merges=merges)
        header = NetworkBlockHeader(
            height=self.world.height + 1, epoch=self.epoch,
            chain_id=node.chain_id, prev_hash=self.world.tip,
            utxo_root=shadow.utxo.root, nf_root=shadow.nullifiers.root,
            super_root=block.compute_super_root(),
            registers_root=registers_root(
                {self.grid_id: child.header.register_root}),
            seats_root=self.world.seats_root_for([self.grid_id]),
            quorum=self.world.quorum_for(self.grid_id),
            # One tier: the grid's own leader led the only ceremony there was.
            leader_id=child.header.leader_id,
            tiers=1, foundings_root=block.compute_foundings_root(),
            merges_root=block.compute_merges_root(),
            witness_root=shadow.utxo.witness_root,
            history_root=shadow.history.root,
            utxo_count=shadow.utxo.size, nf_count=shadow.nullifiers.size,
            protocol=protocol.expected_version(self.world.height + 1,
                                               self.world.activations))
        return NetworkBlock(header=header, supers=(sup,),
                            foundings=foundings, merges=merges), shadow, "ok"

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
        ok, why = _check_merges(self.world, self.epoch, block)
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
                 owner_of: dict, tiers: int = 3, quorum: int = 0,
                 leader_id: str = ""):
        self.world = world
        self.supers = dict(supers)          # super_id -> SuperBlock
        self.epoch = epoch
        self.owner_of = dict(owner_of)
        self.tiers = tiers
        #: What the supreme grid's own certificate has to reach.  Passed in
        #: rather than derived, because the supreme grid seats the tier below
        #: it rather than a register's members — and committed in the header so
        #: a reader is not left deriving it from a register that has moved
        #: (review B4).
        self.supreme_quorum = quorum
        #: As `SuperWorkload.leader_id`: derived by every seat, named in the
        #: header, refused if it disagrees.
        self.leader_id = leader_id

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
        merges = plan_merges(self.world, self.epoch)
        block = NetworkBlock(header=None, supers=tuple(ordered),
                             foundings=foundings, merges=merges)
        header = NetworkBlockHeader(
            height=self.world.height + 1, epoch=self.epoch,
            chain_id=leader.chain_id, prev_hash=self.world.tip,
            utxo_root=shadow.utxo.root, nf_root=shadow.nullifiers.root,
            super_root=block.compute_super_root(),
            registers_root=registers_root(roots),
            seats_root=self.world.seats_root_for(roots),
            leader_id=self.leader_id or leader.id,
            # The supreme grid seats every super grid's leaders rather than a
            # register's members, so its quorum is a fraction of the seats it
            # drew — `supreme_quorum` is where that is decided, and this is it
            # written down for whoever reads the block later.
            quorum=self.supreme_quorum,
            tiers=self.tiers,
            foundings_root=block.compute_foundings_root(),
            merges_root=block.compute_merges_root(),
            witness_root=shadow.utxo.witness_root,
            history_root=shadow.history.root,
            utxo_count=shadow.utxo.size, nf_count=shadow.nullifiers.size,
            protocol=protocol.expected_version(self.world.height + 1,
                                               self.world.activations))
        return NetworkBlock(header=header, supers=tuple(ordered),
                            dropped=tuple(f"{i}:{w}" for i, w in dropped),
                            foundings=foundings, merges=merges)

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
        if self.leader_id and h.leader_id != self.leader_id:
            return False, (f"header names {h.leader_id or 'nobody'} as leader; "
                           f"this view seated {self.leader_id}")
        ok, why = _check_foundings(self.world, self.epoch, block)
        if not ok:
            return False, why
        ok, why = _check_merges(self.world, self.epoch, block)
        if not ok:
            return False, why

        for sup in block.supers:
            if sup.quorum_cert is None:
                return False, f"{sup.header.super_id}: no quorum certificate"
            ok, why = sup.quorum_cert.verify(1, sup.hash(),
                                             validators=self.world.roster)
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
        if (shadow.utxo.size, shadow.nullifiers.size) != (h.utxo_count,
                                                          h.nf_count):
            return False, "the counts do not match the applied epoch"
        ok, why = protocol.check(h.height, h.protocol, self.world.activations)
        if not ok:
            return False, why

        if self.supreme_quorum and h.quorum != self.supreme_quorum:
            return False, (f"header claims a quorum of {h.quorum}, this "
                           f"supreme grid needs {self.supreme_quorum}")
        roots = {c.header.grid_id: c.header.register_root
                 for s in block.supers for c in s.children}
        if registers_root(roots) != h.registers_root:
            return False, "registers_root does not match the grids' registers"
        if self.world.seats_root_for(roots) != h.seats_root:
            return False, ("seats_root does not match the grids' seated "
                           "membership")
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
    #: How many views the supreme tier needed.  One is the ordinary case; more
    #: than one means a leader did not propose and the tier changed view
    #: instead of losing the epoch for every partition on the network.
    supreme_views: int = 1

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


def _check_merges(world: "TierWorld", epoch: int, block: NetworkBlock):
    """Every seat re-derives the merge and refuses anything else.

    Same argument as `_check_foundings`, with more at stake: a merge the state
    does not call for would move a grid's members into a register chosen by
    whoever assembled the block.
    """
    if block.header.merges_root != block.compute_merges_root():
        return False, "merges_root does not match the block"
    expected = plan_merges(world, epoch)
    if tuple(m.digest() for m in block.merges) != \
            tuple(m.digest() for m in expected):
        return False, ("the merge in this block is not the one the state "
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
    agreed = (set(result.quorum_cert.voters())
              if result.quorum_cert else set())
    head = result.block.hash() if result.block else None
    for nid in grid.seats:
        world.trust[nid].observe(result.roll, head, agreed)

    if not result.finalised:
        return TieredEpochResult(epoch, "aborted", f"the only grid: {result.reason}",
                                 1, local, PhaseResult(tier="super"), result)
    local.blocks[gid] = result.block.supers[0].children[0]
    return TieredEpochResult(epoch, "finalised", "ok", 1, local,
                             PhaseResult(tier="super"), result, result.block)


def run_tiered_epoch(world: TierWorld, epoch: int, base_seed: str,
                     behaviours: dict | None = None, tx_limit=None,
                     rounds: int | None = None,
                     max_views: int | None = None) -> TieredEpochResult:
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
        result = ceremony.run(_behaviour(behaviours, "local", grid.leader),
                              limit=tx_limit)
        local.ceremonies[gid] = result
        world.pending_rolls[gid] = result.roll
        if result.finalised:
            local.blocks[gid] = result.block

        # Every seat folds what it watched into its own private trust list.
        agreed = (set(result.quorum_cert.voters())
                  if result.quorum_cert else set())
        head = result.block.hash() if result.block else None
        for nid in grid.seats:
            world.trust[nid].observe(result.roll, head, agreed)

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
            workload=SuperWorkload(world, sid, children, epoch, led_by,
                                   leader_id=grid.leader),
            grid_id=sid)
        result = ceremony.run(_behaviour(behaviours, "super", grid.leader))
        supers.ceremonies[sid] = result
        if result.finalised:
            supers.blocks[sid] = result.block

    if not supers.blocks:
        return TieredEpochResult(epoch, "aborted", "no super grid finalised", 2,
                                 local, supers)

    # ── Phase X ──────────────────────────────────────────────────────────────
    # Every seat of every super grid that finalised, not one leader each.
    #
    # This is the committee, and the committee is the whole of C2.  Seating
    # only the leaders gave the supreme grid one seat per super grid — seven,
    # at the sizing rule's own example of 343 nodes — so three absent nodes out
    # of 343 stopped the entire network for an epoch, redrawn every epoch.  At
    # a 10% absence rate that is a network-wide stall every 13 minutes; the
    # same rate against 49 seats is one every 82 days.  Nothing about the
    # protocol differs between those two numbers, only how many seats were
    # asked.  See docs/supreme_tier_design.md §2 and §4.
    #
    # It wakes nobody new: these nodes are already in this epoch's ceremony and
    # already hold the super blocks.  What it costs is messages and certificate
    # size, which is what the committed seat order and the bitmap encoding were
    # built for (review A3).
    #
    # `owner_of` follows the same widening.  It answers "was my own super grid
    # left out of this block", and a member that is not a leader has exactly as
    # much right to ask.
    super_owner = {nid: sid for sid, r in supers.ceremonies.items()
                   if r.finalised for nid in r.grid.seats}
    supreme_members = sorted(super_owner)
    # Two or more super grids is the full hierarchy.  One means the supreme
    # tier collapses onto it — which is now the *same* seating rather than a
    # special case, because the union of one super grid's seats is that grid.
    tiers = 3 if len(supers.finalised) >= 2 else 2

    # Views, at the tier where a silent leader costs everybody the epoch.
    #
    # The tier below can lose a grid and carry on; this one cannot lose
    # anything, so a leader that does not propose used to end the epoch for
    # every partition on the network.  Each view reseats the whole committee
    # from a fresh seed and skips the leaders already tried, exactly as
    # `ceremony.run_epoch` has done at tier 0 since part one.
    #
    # What this is *not* is the network protocol.  In one process a ceremony
    # finalises for every seat or for none, so there is no view in which one
    # seat has finalised a block the others are giving up on — which is the
    # failure that makes a retry loop unsafe over sockets, and the reason
    # `chain/viewchange.py` exists.  When the upper tiers run over sockets they
    # need that machinery here; today they run in this function alone.
    # See docs/view_change_design.md §1 and docs/supreme_tier_design.md §6.
    tried, supreme, views = [], None, 0
    for view in range(max(1, SUPREME_VIEWS if max_views is None else max_views)):
        views = view + 1
        seed = h_hex("view", base_seed, epoch, "supreme", view)
        grid = Grid.seat(supreme_members, params.row_size, seed,
                         exclude_leaders=tried)
        ceremony = Ceremony(
            grid, {n: world.nodes[n] for n in supreme_members}, params,
            height=epoch, epoch=epoch, rounds=rounds,
            quorum=params.quorum_size(len(supreme_members)),
            workload=SupremeWorkload(world, supers.blocks, epoch, super_owner,
                                     tiers=tiers,
                                     quorum=params.quorum_size(
                                         len(supreme_members)),
                                     leader_id=grid.leader),
            grid_id="supreme")
        supreme = ceremony.run(_behaviour(behaviours, "supreme", grid.leader))
        if supreme.finalised:
            break
        tried.append(grid.leader)

    if not supreme.finalised:
        return TieredEpochResult(epoch, "aborted",
                                 f"supreme grid: {supreme.reason}", tiers,
                                 local, supers, supreme,
                                 supreme_views=views)

    return TieredEpochResult(epoch, "finalised", "ok", tiers, local, supers,
                             supreme, supreme.block, supreme_views=views)


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
