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
    """The attestations that finalised a block, in the shape an aggregate
    signature needs.

    A certificate used to be a tuple of whole `Attestation` objects, and it was
    almost entirely repetition: each one restated the chain id, the height, the
    block hash, the epoch and the grid seed that the certificate itself states
    once, and carried a 32-byte public key that the roster already holds. 225
    bytes a seat, of which about 70 were load-bearing.

    That is a size problem at scale and it was a *format* problem sooner. Part
    one has listed "quorum signature scheme" as unchosen since the beginning,
    with threshold BLS as the example — and an aggregate signature cannot be a
    list of self-describing attestations. It is one signature plus the identity
    of who is in it, checked against keys the verifier already has. So the
    shape here is `signers` and `signatures` verified against the roster: the
    same information, a third of the bytes, and the seam an aggregate scheme
    drops into. When signatures aggregate, `signatures` becomes length one and
    nothing else about this moves.

    Which is the whole argument for doing it now. Choosing the shape before a
    chain exists costs an afternoon; changing it afterwards is every stored
    certificate, every archive segment and every light client.

    `signers` is sorted, so it is a bitmap over the roster in all but encoding
    — and the codec interns repeated strings, so the ids cost little.
    """

    chain_id: str
    height: int
    block_hash: str
    epoch: int
    grid_seed: str
    #: Seats whose attestations count toward quorum, sorted, with their
    #: signatures aligned to them.
    signers: tuple = ()
    signatures: tuple = field(default=(), repr=False)
    #: Seats that attested without counting — apprentices, whose shadow moves
    #: their own counter and nothing else. Quorum never sees them.
    shadow_signers: tuple = ()
    shadow_signatures: tuple = field(default=(), repr=False)
    root: int = 0

    # ── building ─────────────────────────────────────────────────────────────

    @staticmethod
    def build(chain_id, height, block_hash, epoch, grid_seed, attestations,
              shadow=()):
        """From whole attestations, keeping only what is not already here."""
        atts = sorted(attestations, key=lambda a: a.node_id)
        counting = {a.node_id for a in atts}
        shad = sorted((a for a in shadow if a.node_id not in counting),
                      key=lambda a: a.node_id)
        return QuorumCert(
            chain_id=chain_id, height=height, block_hash=block_hash,
            epoch=epoch, grid_seed=grid_seed,
            signers=tuple(a.node_id for a in atts),
            signatures=tuple(a.signature for a in atts),
            shadow_signers=tuple(a.node_id for a in shad),
            shadow_signatures=tuple(a.signature for a in shad),
            root=QuorumCert.compute_root(
                [a.node_id for a in atts], [a.signature for a in atts]))

    @staticmethod
    def compute_root(signers, signatures) -> int:
        """Over the pairs, so neither a signer nor a signature can be swapped
        for another without the root moving."""
        return seal_root("quorum", [f"{n}:{s}" for n, s
                                    in zip(signers, signatures)])

    # ── reading ──────────────────────────────────────────────────────────────

    def message(self) -> bytes:
        """The statement every signature in this certificate is over.

        One message for the whole certificate, which is exactly why the
        per-attestation copies of it were redundant — and exactly what makes
        aggregation possible later: aggregate schemes need one message and many
        keys.
        """
        return Attestation.message(self.chain_id, self.height, self.block_hash,
                                   self.epoch, self.grid_seed)

    def voters(self) -> tuple:
        return self.signers

    def attended(self) -> tuple:
        """Every seat this certificate proves said something, of either kind."""
        return tuple(sorted(set(self.signers) | set(self.shadow_signers)))

    def __len__(self):
        return len(self.signers)

    def verify(self, quorum: int, block_hash: str | None = None,
               validators: dict | None = None):
        """(ok, reason).  `validators` maps node_id -> public key.

        Required, not optional, and that is the price of the shape: a
        certificate no longer carries the keys it was signed with, so it cannot
        be checked in isolation. That is not a loss — a key carried by the
        thing it authenticates was never evidence of anything, and every caller
        that verified without a roster was checking that a signature matched a
        key the signer had chosen for itself.
        """
        if block_hash is not None and block_hash != self.block_hash:
            return False, "certificate is for a different block"
        if validators is None:
            return False, ("a certificate carries no keys; it can only be "
                           "checked against the roster")
        if len(self.signers) != len(self.signatures):
            return False, "signers and signatures do not correspond"
        if len(self.shadow_signers) != len(self.shadow_signatures):
            return False, "shadow signers and signatures do not correspond"
        msg = self.message()
        seen = set()
        for node_id, signature in zip(self.signers, self.signatures):
            key = validators.get(node_id)
            if key is None:
                return False, f"{node_id} is not a known validator"
            if node_id in seen:
                return False, f"duplicate attestation from {node_id}"
            if not verify_sig(key, msg, signature):
                return False, f"bad attestation signature from {node_id}"
            seen.add(node_id)
        if len(seen) < quorum:
            return False, f"{len(seen)} attestations, quorum is {quorum}"
        # Shadows are checked as carefully as votes, because the register
        # credits them: an unverified shadow would be a way to hand an
        # apprentice a promotion it did not earn. What they cannot do is count
        # — `seen` is not extended, so quorum is untouched.
        for node_id, signature in zip(self.shadow_signers,
                                      self.shadow_signatures):
            key = validators.get(node_id)
            if key is None:
                return False, f"{node_id} is not a known validator"
            if node_id in seen:
                return False, f"{node_id} attested twice, once as a shadow"
            if not verify_sig(key, msg, signature):
                return False, f"bad shadow attestation signature from {node_id}"
            seen.add(node_id)
        if self.compute_root(self.signers, self.signatures) != self.root:
            return False, "certificate root does not match its attestations"
        return True, "ok"

    def __repr__(self):
        return (f"QuorumCert(h={self.height}, {len(self.signers)} seats"
                + (f" +{len(self.shadow_signers)} shadow"
                   if self.shadow_signers else "")
                + f", {self.block_hash[:14]}…)")
