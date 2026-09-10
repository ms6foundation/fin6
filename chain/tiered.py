"""The three block types the tiered pipeline produces.

    CeremonyBlock   one grid's work.  Carries a *delta*, not roots, plus the
                    attendance roll of the previous ceremony and the register
                    root that follows from it.
    SuperBlock      a bundle of ceremony blocks from one super grid, with the
                    siblings it had to drop.
    NetworkBlock    the supreme grid's output.  The only tier that computes the
                    global utxo_root and nf_root, because it is the only tier
                    that can see every delta.

Each carries the certificates of the tier below, so a transaction can be walked
from the network block to its proof without trusting any single tier.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import h_hex
from .register import AttendanceRoll
from .seal import seal_root
from .state import UtxoDelta

GENESIS_NETWORK = "net:genesis"


@dataclass(frozen=True)
class GridFounding:
    """A new grid, and the cohort that carried its standing across.

    Deterministic from committed state — which grid is over size, and which of
    its attesters the previous block's hash selects — so the leader proposes
    nothing here and every seat re-derives the same record.  It is carried in
    the block and committed in the header anyway, because a grid being founded
    is a governance event: it should be visible in the archive rather than
    inferred from two register roots changing at once.
    """
    donor_id: str
    grid_id: str
    epoch: int
    cohort: tuple = ()

    def digest(self) -> str:
        return h_hex("founding", self.donor_id, self.grid_id, self.epoch,
                     sorted(self.cohort))

    def __repr__(self):
        return (f"GridFounding({self.donor_id} -> {self.grid_id}, "
                f"{len(self.cohort)} founders)")


def foundings_root(foundings) -> int:
    return seal_root("foundings", [f.digest() for f in foundings])


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 0
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CeremonyBlockHeader:
    grid_id: str
    partition: int
    n_partitions: int
    epoch: int
    chain_id: str
    prev_network_hash: str
    tx_root: int
    delta_digest: str
    roll_digest: str
    register_root: int
    #: Who led this ceremony.  Recorded because the roll of epoch e is needed
    #: to validate the block of epoch e+1, and `leader_id` is part of a roll —
    #: so a node that was not present has to be able to read it off the chain
    #: rather than recompute it from a register that has since moved.
    leader_id: str = ""
    #: The certificate of the previous epoch, and the faults it substantiated,
    #: committed here so that neither can be swapped after agreement.
    prev_cert_digest: str = ""
    faults_digest: str = ""

    def hash(self) -> str:
        return "cb:" + h_hex("ceremony-header", self.grid_id, self.partition,
                             self.n_partitions, self.epoch, self.chain_id,
                             self.prev_network_hash, self.tx_root,
                             self.delta_digest, self.roll_digest,
                             self.register_root, self.leader_id,
                             self.prev_cert_digest, self.faults_digest)


@dataclass(eq=False)
class CeremonyBlock:
    header: CeremonyBlockHeader
    transactions: tuple = ()
    delta: UtxoDelta = field(default_factory=UtxoDelta)
    roll: AttendanceRoll | None = None
    quorum_cert: object = field(default=None, repr=False)
    #: The certificate that finalised the *previous* epoch's network block.
    #:
    #: This is the field the roll was always missing.  `Seat.roll` used to
    #: build attendance from whatever that one seat happened to see, and seven
    #: seats see seven different things — which is why the first networked run
    #: died at epoch 2 with "attendance roll is not the one this grid
    #: produced", and why the stopgap that replaced it credits everyone seated
    #: in a ceremony that finalised whether they said anything or not.  A
    #: certificate is the one artefact that is *agreed* about who attested,
    #: because it is what the agreement was made of.
    prev_cert: object = field(default=None, repr=False)
    #: Fault reports from the previous epoch that prove themselves.
    faults: tuple = field(default=(), repr=False)

    def compute_tx_root(self) -> int:
        return seal_root("tx", [tx.txid for tx in self.transactions])

    def compute_prev_cert_digest(self) -> str:
        return prev_cert_digest(self.prev_cert)

    def compute_faults_digest(self) -> str:
        return faults_digest(self.faults)

    def hash(self) -> str:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.epoch

    def __repr__(self):
        return (f"CeremonyBlock({self.header.grid_id}, p{self.header.partition}, "
                f"{len(self.transactions)} txs, {self.hash()[:13]}…)")


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 1
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SuperBlockHeader:
    super_id: str
    epoch: int
    chain_id: str
    prev_network_hash: str
    child_root: int
    dropped_root: int

    def hash(self) -> str:
        return "sb:" + h_hex("super-header", self.super_id, self.epoch,
                             self.chain_id, self.prev_network_hash,
                             self.child_root, self.dropped_root)


@dataclass(eq=False)
class SuperBlock:
    header: SuperBlockHeader
    children: tuple = ()
    dropped: tuple = ()            # (child_hash, reason) for siblings refused
    quorum_cert: object = field(default=None, repr=False)

    def compute_child_root(self) -> int:
        return seal_root("super-children", [c.hash() for c in self.children])

    def compute_dropped_root(self) -> int:
        return seal_root("super-dropped", [f"{h}:{why}" for h, why in self.dropped])

    def hash(self) -> str:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.epoch

    def transactions(self):
        for child in self.children:
            yield from child.transactions

    def __repr__(self):
        return (f"SuperBlock({self.header.super_id}, {len(self.children)} grids, "
                f"{len(self.dropped)} dropped, {self.hash()[:13]}…)")


# ═══════════════════════════════════════════════════════════════════════════════
# Tier 2
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class NetworkBlockHeader:
    height: int
    epoch: int
    chain_id: str
    prev_hash: str
    utxo_root: int
    nf_root: int
    super_root: int
    registers_root: int
    tiers: int = 3
    foundings_root: int = 0
    #: The same UTXO set as `utxo_root`, in the shape an outsider can check.
    #: The seal tree is cheap for a validator to keep current and expensive to
    #: prove one leaf out of; this is the other half of that trade, and it is
    #: what lets a wallet check that its own note is unspent (see
    #: docs/light_client_design.md §3-4).
    witness_root: str = ""
    #: Every block strictly below this one, in a tree.  Turns "does this tip
    #: descend from the header I saw last week" from a walk into a path.
    history_root: str = ""
    #: How many notes and how many nullifiers have ever existed, cumulative.
    #: Two numbers, and they are what makes a *scan* checkable rather than
    #: merely verifiable: a client can check every output it was handed and
    #: still be missing one, unless it can count what it should have been
    #: handed.  Positions are issued in order and never reused, so the
    #: difference between two headers' counts is exactly the number of outputs
    #: the range between them produced.
    utxo_count: int = 0
    nf_count: int = 0
    """How many ceremonies stand behind this block.

    Three is the full hierarchy: a local grid agreed the transactions, a super
    grid agreed the bundle, a supreme grid agreed the roots, and each carries
    the certificates of the tier below.  Below the sizing thresholds the tiers
    collapse onto each other, and at one tier there is a single certificate on
    this block with none on the blocks nested inside it.

    That difference has to be *signed*, not inferred.  Otherwise a reader
    cannot tell a legitimately degenerate block from a forged one whose inner
    certificates were stripped out — the two look identical.
    """

    def hash(self) -> str:
        return "nb:" + h_hex("network-header", self.height, self.epoch,
                             self.chain_id, self.prev_hash, self.utxo_root,
                             self.nf_root, self.super_root,
                             self.registers_root, self.tiers,
                             self.foundings_root, self.witness_root,
                             self.history_root, self.utxo_count,
                             self.nf_count)


@dataclass(eq=False)
class NetworkBlock:
    header: NetworkBlockHeader
    supers: tuple = ()
    dropped: tuple = ()
    foundings: tuple = ()
    quorum_cert: object = field(default=None, repr=False)

    def compute_super_root(self) -> int:
        return seal_root("network-supers", [s.hash() for s in self.supers])

    def compute_foundings_root(self) -> int:
        return foundings_root(self.foundings)

    def hash(self) -> str:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.height

    def ceremony_blocks(self):
        for sup in self.supers:
            yield from sup.children

    def transactions(self):
        for child in self.ceremony_blocks():
            yield from child.transactions

    def __repr__(self):
        return (f"NetworkBlock(h={self.header.height}, {len(self.supers)} supers, "
                f"{sum(1 for _ in self.ceremony_blocks())} grids, "
                f"{sum(1 for _ in self.transactions())} txs, {self.hash()[:13]}…)")


def prev_cert_digest(cert) -> str:
    """A digest over the previous epoch's certificate, or "" when there is
    none — which is only true of the first block after genesis."""
    if cert is None:
        return ""
    return h_hex("prev-cert", cert.chain_id, cert.height, cert.block_hash,
                 cert.epoch, cert.grid_seed,
                 [f"{n}:{s}" for n, s in zip(cert.signers, cert.signatures)],
                 [f"{n}:{s}" for n, s in zip(cert.shadow_signers,
                                             cert.shadow_signatures)])


def faults_digest(faults) -> str:
    """A digest over the fault reports a block carries.  Order-independent,
    because two leaders that saw the same faults in a different order agreed
    about the same thing."""
    return h_hex("faults", sorted(fr.key() for fr in faults or ()))


def faulted_from(faults) -> tuple:
    """Who a block's fault reports prove to be at fault.

    A pure function of the block, which is the whole requirement: the
    `faulted` set feeds `GridRegister.apply` and therefore the register root,
    so every node has to derive the same set from the same bytes.  Only
    self-substantiating reports count — `FaultReport.substantiated` is
    `kind == "equivocation"` and evidence that proves the claim on its own —
    because a claim a validator cannot check is a claim a leader could invent
    about anyone it disliked.
    """
    out = set()
    for fr in faults or ():
        if fr.substantiated() and fr.verify():
            out.add(fr.evidence[0].leader_id)
    return tuple(sorted(out))


def registers_root(register_roots: dict) -> int:
    """One root over every grid's register root, committed in the network block."""
    return seal_root("registers",
                     [f"{gid}:{root}" for gid, root in sorted(register_roots.items())])
