"""Blocks, and the signed objects the ceremony passes around.

The block hash covers the header only.  The quorum certificate is assembled
*about* a block during the ceremony, so it cannot be inside what it attests to.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from .crypto import h_bytes, h_hex, verify_sig
from .seal import seal_root
from .seats import SeatError, from_bits, seats_digest as _seats_digest, to_bits

#: The only signature scheme this build knows.  Named so that the certificate
#: says which scheme it is in rather than leaving every reader to assume.
ED25519 = "ed25519"


def _popcount(bits: str) -> int:
    try:
        return bin(int(bits or "0", 16)).count("1")
    except ValueError:
        return 0

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
    #: The view this proposal is for, and the quorum of view changes that
    #: authorised it.  View 0 carries neither — there is nothing to carry
    #: forward into the first attempt at a height.  See chain/viewchange.py
    #: and docs/view_change_design.md.
    view: int = 0
    view_cert: object = field(default=None, repr=False)

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
    def message(chain_id, height, block_hash, epoch, grid_seed, view: int = 0,
                cert_digest: str = "") -> bytes:
        return h_bytes("proposal", chain_id, height, block_hash, epoch,
                       grid_seed, view, cert_digest)

    def cert_digest(self) -> str:
        return "" if self.view_cert is None else self.view_cert.digest()

    def verify(self) -> bool:
        msg = self.message(self.block.header.chain_id, self.height,
                           self.block_hash, self.epoch, self.grid_seed,
                           self.view, self.cert_digest())
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


#: The kinds whose evidence proves the claim, so a register can act on them.
EQUIVOCATION = "equivocation"
LAZY_ATTESTATION = "lazy_attestation"
INVALID_BLOCK = "invalid_block"
SELF_PROVING = (EQUIVOCATION, LAZY_ATTESTATION)


@dataclass(frozen=True)
class FaultReport:
    """A signed complaint.

    Three kinds, and what separates them is not severity — it is whether a
    third party holding the report can reach the same verdict.

    `equivocation` is self-substantiating: two validly signed proposals from
    one leader at one height, and anybody can see it.

    `lazy_attestation` is self-substantiating too, and that is review B1's
    whole subject. The evidence is an attestation over a block whose own bytes
    contradict each other — see `chain/faults.self_evident_flaw`. The attester
    either did not check or checked and lied, and a verifier a year later
    re-runs exactly the check the reporter ran, because the check needs the
    block and nothing else. The block travels in `subject`, which is what makes
    the report stand on its own and what costs the bytes.

    `invalid_block` is only the reporter's word — the block failed a *contextual*
    check (an input already spent, a tip that has moved), and re-deriving that
    needs a ledger state nobody keeps. It is carried so a ceremony can end
    promptly rather than waiting out the round schedule, and it convicts nobody.
    """
    reporter: str
    public_hex: str
    kind: str
    height: int
    epoch: int
    detail: str
    evidence: tuple = field(default=(), repr=False)
    signature: str = ""
    chain_id: str = ""
    #: The block the evidence is about, when checking the claim means checking
    #: the block. Only `lazy_attestation` carries one: equivocation is proved
    #: by the two proposals alone, and an `invalid_block` report cannot be
    #: proved by anything the report could carry.
    subject: object = field(default=None, repr=False)

    @staticmethod
    def message(chain_id, reporter, kind, height, epoch, detail,
                evidence_hashes, subject_hash: str = "") -> bytes:
        """The statement a reporter signs.

        `chain_id` is first because every other signed statement in this
        codebase binds it — an attestation, a proposal, a hello, a spend — and
        this one did not.  A fault report signed on one fin6 network verified
        on any other: the same replay the hello's `chain_id` field exists to
        stop, in the one signed object that had been left out of the rule.

        Nothing on chain depended on that when it was added, because faults
        were not yet carried in blocks.  They are now (review B1), which is the
        argument for having fixed it then rather than after: the shape of a
        signed statement is a format decision, and it was still free.
        """
        return h_bytes("fault", chain_id, reporter, kind, height, epoch,
                       detail, list(evidence_hashes), subject_hash)

    def evidence_hashes(self):
        return [sp.block_hash for sp in self.evidence]

    def subject_hash(self) -> str:
        return "" if self.subject is None else self.subject.hash()

    def key(self) -> str:
        return h_hex("fault-key", self.chain_id, self.reporter, self.kind,
                     self.height, self.epoch, self.detail,
                     self.evidence_hashes(), self.subject_hash())

    def verify(self) -> bool:
        msg = self.message(self.chain_id, self.reporter, self.kind,
                           self.height, self.epoch, self.detail,
                           self.evidence_hashes(), self.subject_hash())
        if not verify_sig(self.public_hex, msg, self.signature):
            return False
        if self.kind == EQUIVOCATION:
            return self.substantiated()
        if self.kind == LAZY_ATTESTATION:
            # Everything checkable *without* the chain parameters: the report
            # carries a block, the attestations are real and name that block.
            # Whether the block is actually flawed is `substantiated`, because
            # that needs the parameters — and the two questions are separate on
            # purpose, since a seat relaying a report has to be able to tell a
            # malformed one from one it cannot yet judge.
            return self._lazy_well_formed()
        return True

    def accused(self, params=None) -> tuple:
        """Who this report convicts, if it proves itself — and nobody if not.

        A pure function of the report, which is the requirement: the faulted
        set feeds the register root, so every node has to derive the same names
        from the same bytes.
        """
        if not self.substantiated(params):
            return ()
        if self.kind == "equivocation":
            return (self.evidence[0].leader_id,)
        return tuple(sorted({a.node_id for a in self.evidence}))

    def substantiated(self, params=None) -> bool:
        """True when the attached evidence proves the claim on its own.

        `params` is needed only for `lazy_attestation`, because checking a
        block means checking its transactions against the chain's parameters.
        Without them the report is *unproven rather than false* — a caller that
        cannot check has to say so, not vote.
        """
        if self.kind == LAZY_ATTESTATION:
            return self._lazy_substantiated(params)
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

    def _lazy_substantiated(self, params) -> bool:
        """An attestation over a block that contradicts itself.

        Everything here is re-derived: the block is the one the attestations
        name, each attestation verifies under the key it carries, and the block
        really does have a flaw that needs nothing but the block to see. The
        reporter's own signature is checked in `verify`; the reporter's *claim*
        is checked here, and the two are deliberately separate — a report that
        is signed and wrong is worth exactly nothing.
        """
        from .faults import self_evident_flaw

        if params is None or not self._lazy_well_formed():
            return False
        try:
            return self_evident_flaw(self.subject, params,
                                     chain_id=self.chain_id) is not None
        except Exception:
            return False

    def _lazy_well_formed(self) -> bool:
        """The part of a lazy report that needs no chain parameters."""
        if self.subject is None or not self.evidence:
            return False
        try:
            block_hash = self.subject.hash()
            for att in self.evidence:
                if getattr(att, "block_hash", None) != block_hash:
                    return False
                if att.epoch != self.epoch or not att.verify():
                    return False
            return True
        except Exception:
            return False


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
    #: Which signature scheme `signatures` are in.  One value, named rather
    #: than assumed, and checked: a build that does not know a scheme refuses
    #: the certificate instead of verifying it under the wrong rules.  This is
    #: the field that makes an aggregate scheme a *value* later rather than a
    #: format change — see docs/quorum_signature_decision.md.
    scheme: str = ED25519
    #: When set, `signer_bits` and `shadow_bits` carry the seats as a bitmap
    #: over the canonical order this digest names, and `signers` is empty.  The
    #: order lives in the header (`seats_root`), so verifying a compact
    #: certificate needs the seat list passed in, exactly as verifying any
    #: certificate already needs the roster.
    seats_digest: str = ""
    signer_bits: str = ""
    shadow_bits: str = ""

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
                [a.node_id for a in atts], [a.signature for a in atts],
                ED25519))

    @staticmethod
    def compute_root(signers, signatures, scheme: str = ED25519) -> int:
        """Over the pairs, so neither a signer nor a signature can be swapped
        for another without the root moving — and over the scheme, so the
        claim about what those signatures *are* cannot be edited either.

        Computed from the expanded seats, which is why compacting a
        certificate to a bitmap leaves its root alone: the two encodings are
        the same statement, and anything that recorded the root of one still
        recognises the other.
        """
        return seal_root("quorum", [f"scheme:{scheme}"]
                         + [f"{n}:{s}" for n, s in zip(signers, signatures)])

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
        self._require_expanded("voters")
        return self.signers

    def attended(self) -> tuple:
        """Every seat this certificate proves said something, of either kind."""
        self._require_expanded("attended")
        return tuple(sorted(set(self.signers) | set(self.shadow_signers)))

    def __len__(self):
        if self.compact:
            return (_popcount(self.signer_bits))
        return len(self.signers)

    # ── the two encodings ────────────────────────────────────────────────────

    @property
    def compact(self) -> bool:
        """Whether the seats are carried as a bitmap rather than as ids."""
        return bool(self.seats_digest)

    def _require_expanded(self, what: str):
        if self.compact:
            raise SeatError(
                f"{what}() needs the seat order: this certificate carries a "
                f"bitmap over {self.seats_digest[:12]}…, expand it first")

    def compact_form(self, grid_id: str, order) -> "QuorumCert":
        """The same certificate with the seats as a bitmap over `order`.

        `root` is untouched, because the root is over the expanded pairs: the
        two forms are one statement in two encodings, and nothing that stored
        the root of one fails to recognise the other.

        What this does not do is shrink the signatures, which are the other
        90% at any interesting seat count. That needs an aggregate scheme,
        which needs a dependency — docs/quorum_signature_decision.md.
        """
        if self.compact:
            return self
        return replace(
            self,
            signers=(), shadow_signers=(),
            seats_digest=_seats_digest(grid_id, order),
            signer_bits=to_bits(self.signers, order),
            shadow_bits=to_bits(self.shadow_signers, order))

    def expanded_form(self, grid_id: str, order) -> "QuorumCert":
        """The seats named again, checked against the order this was compacted
        over — a mismatch means the reader and the writer disagree about who
        was seated, which is not a thing to resolve silently."""
        if not self.compact:
            return self
        digest = _seats_digest(grid_id, order)
        if digest != self.seats_digest:
            raise SeatError(
                f"this certificate is a bitmap over {self.seats_digest[:12]}…, "
                f"not over {grid_id}'s order {digest[:12]}…")
        return replace(
            self,
            seats_digest="", signer_bits="", shadow_bits="",
            signers=from_bits(self.signer_bits, order),
            shadow_signers=from_bits(self.shadow_bits, order))

    def verify(self, quorum: int, block_hash: str | None = None,
               validators: dict | None = None, seats=None,
               grid_id: str | None = None):
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
        # An unknown scheme is a refusal, not a best effort.  A build that
        # cannot check these signatures has no business deciding they are
        # fine, and the failure has to be loud for the same reason a protocol
        # version this build cannot run halts the node.
        if self.scheme != ED25519:
            return False, (f"certificate is in the {self.scheme!r} signature "
                           f"scheme; this build knows {ED25519!r}")
        if self.compact:
            if seats is None:
                return False, ("certificate carries a seat bitmap; it can "
                               "only be checked against the committed seat "
                               "order")
            try:
                self = self.expanded_form(grid_id or "", seats)
            except SeatError as exc:
                return False, str(exc)
        elif seats is not None:
            stray = [n for n in self.signers if n not in set(seats)]
            if stray:
                return False, f"{stray[0]} is not a seat in this grid"
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
        if self.compute_root(self.signers, self.signatures,
                             self.scheme) != self.root:
            return False, "certificate root does not match its attestations"
        return True, "ok"

    def __repr__(self):
        return (f"QuorumCert(h={self.height}, {len(self.signers)} seats"
                + (f" +{len(self.shadow_signers)} shadow"
                   if self.shadow_signers else "")
                + f", {self.block_hash[:14]}…)")
