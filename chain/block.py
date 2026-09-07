"""Blocks, and the signed objects the ceremony passes around.

The block hash covers the header only.  The quorum certificate is assembled
*about* a block during the ceremony, so it cannot be inside what it attests to.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import h_bytes, h_hex, verify_sig
from .seal import seal_root

GENESIS_PREV = "genesis"


# ═══════════════════════════════════════════════════════════════════════════════
# Block
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CeremonyMeta:
    """Which ceremony produced this block — enough to re-derive the seating."""
    epoch: int
    leader_id: str
    rows: int
    row_size: int
    grid_seed: str
    attempt: int = 0

    def as_tuple(self):
        return (self.epoch, self.leader_id, self.rows, self.row_size,
                self.grid_seed, self.attempt)


@dataclass(frozen=True)
class BlockHeader:
    height: int
    prev_hash: str
    chain_id: str
    utxo_root: int
    nf_root: int
    tx_root: int
    ceremony: CeremonyMeta

    def hash(self) -> str:
        return "blk:" + h_hex("block-header", self.height, self.prev_hash,
                              self.chain_id, self.utxo_root, self.nf_root,
                              self.tx_root, list(self.ceremony.as_tuple()))


@dataclass(eq=False)
class Block:
    header: BlockHeader
    transactions: tuple = ()
    quorum_cert: "QuorumCert | None" = field(default=None, repr=False)

    def compute_tx_root(self) -> int:
        return seal_root("tx", [tx.txid for tx in self.transactions])

    def hash(self) -> str:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.height

    def __repr__(self):
        return (f"Block(h={self.header.height}, {len(self.transactions)} txs, "
                f"{self.hash()[:14]}…"
                f"{', finalised' if self.quorum_cert else ''})")


# ═══════════════════════════════════════════════════════════════════════════════
# Signed consensus objects
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class SignedProposal:
    """A leader's proposal.  Signed so equivocation leaves evidence."""
    block: Block = field(repr=False)
    leader_id: str
    public_hex: str
    epoch: int
    grid_seed: str
    signature: str

    @property
    def block_hash(self) -> str:
        return self.block.hash()

    @property
    def height(self) -> int:
        # via the block, not the header: the tiered blocks key on epoch and
        # expose height as a property, so this is the one spelling all four
        # block types answer to.
        return self.block.height

    @staticmethod
    def message(chain_id, height, block_hash, epoch, grid_seed) -> bytes:
        return h_bytes("proposal", chain_id, height, block_hash, epoch, grid_seed)

    def verify(self) -> bool:
        msg = self.message(self.block.header.chain_id, self.height,
                           self.block_hash, self.epoch, self.grid_seed)
        return verify_sig(self.public_hex, msg, self.signature)

    def __repr__(self):
        return (f"SignedProposal(by={self.leader_id}, h={self.height}, "
                f"{self.block_hash[:14]}…)")


@dataclass(frozen=True)
class Attestation:
    """One seat's statement that it validated this block itself."""
    node_id: str
    public_hex: str
    chain_id: str
    height: int
    block_hash: str
    epoch: int
    grid_seed: str
    signature: str

    @staticmethod
    def message(chain_id, height, block_hash, epoch, grid_seed) -> bytes:
        return h_bytes("attestation", chain_id, height, block_hash, epoch,
                       grid_seed)

    def digest(self) -> str:
        return h_hex("att-digest", self.node_id, self.chain_id, self.height,
                     self.block_hash, self.epoch, self.grid_seed, self.signature)

    def verify(self) -> bool:
        msg = self.message(self.chain_id, self.height, self.block_hash,
                           self.epoch, self.grid_seed)
        return verify_sig(self.public_hex, msg, self.signature)


@dataclass(frozen=True)
class FaultReport:
    """A signed complaint.

    kind="equivocation" is self-substantiating: the evidence is two validly
    signed proposals from one leader at one height, and any party can check it.

    kind="invalid_block" is only the reporter's word — a recipient that wants to
    act on it re-validates the block itself.  It is carried so a ceremony can
    end promptly rather than waiting out the round schedule.
    """
    reporter: str
    public_hex: str
    kind: str
    height: int
    epoch: int
    detail: str
    evidence: tuple = field(default=(), repr=False)
    signature: str = ""

    @staticmethod
    def message(reporter, kind, height, epoch, detail, evidence_hashes) -> bytes:
        return h_bytes("fault", reporter, kind, height, epoch, detail,
                       list(evidence_hashes))

    def evidence_hashes(self):
        return [sp.block_hash for sp in self.evidence]

    def key(self) -> str:
        return h_hex("fault-key", self.reporter, self.kind, self.height,
                     self.epoch, self.detail, self.evidence_hashes())

    def verify(self) -> bool:
        msg = self.message(self.reporter, self.kind, self.height, self.epoch,
                           self.detail, self.evidence_hashes())
        if not verify_sig(self.public_hex, msg, self.signature):
            return False
        if self.kind == "equivocation":
            return self.substantiated()
        return True

    def substantiated(self) -> bool:
        """True when the attached evidence proves the claim on its own."""
        if self.kind != "equivocation":
            return False
        if len(self.evidence) != 2:
            return False
        a, b = self.evidence
        return (a.verify() and b.verify()
                and a.leader_id == b.leader_id
                and a.public_hex == b.public_hex
                and a.height == b.height == self.height
                and a.epoch == b.epoch == self.epoch
                and a.block_hash != b.block_hash)


@dataclass(frozen=True)
class QuorumCert:
    """The attestations that finalised a block, committed with a seal tree."""
    chain_id: str
    height: int
    block_hash: str
    epoch: int
    grid_seed: str
    attestations: tuple = field(repr=False)
    root: int = 0

    @staticmethod
    def build(chain_id, height, block_hash, epoch, grid_seed, attestations):
        atts = tuple(sorted(attestations, key=lambda a: a.node_id))
        return QuorumCert(chain_id=chain_id, height=height,
                          block_hash=block_hash, epoch=epoch,
                          grid_seed=grid_seed, attestations=atts,
                          root=seal_root("quorum", [a.digest() for a in atts]))

    def verify(self, quorum: int, block_hash: str | None = None,
               validators: dict | None = None):
        """(ok, reason).  validators maps node_id -> public key, when known."""
        if block_hash is not None and block_hash != self.block_hash:
            return False, "certificate is for a different block"
        seen = set()
        for a in self.attestations:
            if not a.verify():
                return False, f"bad attestation signature from {a.node_id}"
            if (a.block_hash != self.block_hash or a.height != self.height
                    or a.epoch != self.epoch or a.chain_id != self.chain_id):
                return False, f"attestation from {a.node_id} is off-statement"
            if a.node_id in seen:
                return False, f"duplicate attestation from {a.node_id}"
            if validators is not None and validators.get(a.node_id) != a.public_hex:
                return False, f"{a.node_id} is not a known validator"
            seen.add(a.node_id)
        if len(seen) < quorum:
            return False, f"{len(seen)} attestations, quorum is {quorum}"
        expect = seal_root("quorum", [a.digest() for a in self.attestations])
        if expect != self.root:
            return False, "certificate root does not match its attestations"
        return True, "ok"

    def __repr__(self):
        return (f"QuorumCert(h={self.height}, {len(self.attestations)} seats, "
                f"{self.block_hash[:14]}…)")
