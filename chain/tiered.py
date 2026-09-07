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

    def hash(self) -> str:
        return "cb:" + h_hex("ceremony-header", self.grid_id, self.partition,
                             self.n_partitions, self.epoch, self.chain_id,
                             self.prev_network_hash, self.tx_root,
                             self.delta_digest, self.roll_digest,
                             self.register_root)


@dataclass(eq=False)
class CeremonyBlock:
    header: CeremonyBlockHeader
    transactions: tuple = ()
    delta: UtxoDelta = field(default_factory=UtxoDelta)
    roll: AttendanceRoll | None = None
    quorum_cert: object = field(default=None, repr=False)

    def compute_tx_root(self) -> int:
        return seal_root("tx", [tx.txid for tx in self.transactions])

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

    def hash(self) -> str:
        return "nb:" + h_hex("network-header", self.height, self.epoch,
                             self.chain_id, self.prev_hash, self.utxo_root,
                             self.nf_root, self.super_root, self.registers_root)


@dataclass(eq=False)
class NetworkBlock:
    header: NetworkBlockHeader
    supers: tuple = ()
    dropped: tuple = ()
    quorum_cert: object = field(default=None, repr=False)

    def compute_super_root(self) -> int:
        return seal_root("network-supers", [s.hash() for s in self.supers])

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


def registers_root(register_roots: dict) -> int:
    """One root over every grid's register root, committed in the network block."""
    return seal_root("registers",
                     [f"{gid}:{root}" for gid, root in sorted(register_roots.items())])
