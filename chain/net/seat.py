"""One node's participation in one ceremony, driven by messages rather than by
a loop that owns every seat.

`Ceremony.run` in `chain/ceremony.py` is round-synchronous: it holds every
seat's envelope and exchanges all of them in lockstep.  That is the right model
for a simulation and an impossible one for a process that can only see its own
mailbox.  This is the same logic, re-cut so that a single node can run it:

    propose   (leader only)      build a block and sign it
    absorb    (on every frame)   merge what a neighbour knows
    react     (after absorbing)  validate once, then attest or report
    decide    (at the deadline)  quorum reached, or say why not

It is safe to drive this from an asynchronous, lossy transport for one reason,
and it is worth naming: **the envelope is monotone.**  `absorb` is a union and
every statement is checked against the seated validator set and its signature
on the way in, so a duplicate changes nothing, a reordering changes nothing,
and a lost message is recovered by any later exchange over any path.  Delay
costs time, not correctness — which is why `2 x diameter` becomes a deadline
here instead of a step count.

Proposals travel as *headers*.  An envelope carrying a full block would put
542 KB on every edge of every round; the header carries the hash and the
signature (which covers the hash), the body is fetched once, and the proposal
only enters the envelope when its body is in hand and hashes to what was
signed.
"""
from __future__ import annotations

from ..block import Attestation, FaultReport, SignedProposal
from ..ceremony import Envelope
from ..crypto import verify_sig
from ..register import AttendanceRoll


def proposal_header(sp: SignedProposal) -> dict:
    """The part of a proposal that travels every round."""
    return {"leader_id": sp.leader_id, "public_hex": sp.public_hex,
            "epoch": sp.epoch, "grid_seed": sp.grid_seed,
            "signature": sp.signature, "height": sp.height,
            "block_hash": sp.block_hash}


class Seat:
    """This node, in this grid, for this epoch."""

    def __init__(self, node, grid, workload, *, epoch: int, quorum: int,
                 validators: dict, counting=None, grid_id: str = "",
                 chain_id: str | None = None, height: int | None = None):
        self.node = node
        self.grid = grid
        self.workload = workload
        self.epoch = epoch
        # The epoch comes from the clock and the height from the chain, and
        # they are not the same number.  An epoch whose leader is dead makes no
        # block, so the height stops while the clock does not — and from then
        # on a seat that used the epoch as the height rejected the leader's
        # proposal, including the leader rejecting its own, with the
        # spectacularly unhelpful "no proposal reached this seat".
        self.height = epoch if height is None else height
        self.quorum = quorum
        self.grid_id = grid_id
        self.chain_id = chain_id or node.chain_id
        self.env = Envelope(self.height, epoch, grid.seed, grid.leader,
                            self.chain_id, validators, counting)
        self.blocks: dict = {}        # block_hash -> body we hold
        self.pending: dict = {}       # block_hash -> header awaiting a body
        self._signed_height = 0       # highest height a leader signed for
        self.validated = None         # (block_hash, ok, why)
        self.reacted = False

    @property
    def is_leader(self) -> bool:
        return self.grid.leader == self.node.id

    # ── proposing ────────────────────────────────────────────────────────────

    def propose(self, meta, limit=None):
        """Leader only: build, sign, and hold the body."""
        block = self.workload.build(self.node, meta, limit=limit)
        sp = self.node.propose(block, self.epoch, self.grid.seed)
        self.blocks[sp.block_hash] = block
        self.env.add_proposal(sp)
        return sp

    # ── receiving ────────────────────────────────────────────────────────────

    def offer_block(self, block) -> bool:
        """A body arrived.  Keep it only if a header is waiting for exactly it."""
        digest = block.hash()
        header = self.pending.get(digest)
        if header is None or digest in self.blocks:
            return False
        sp = SignedProposal(block=block, leader_id=header["leader_id"],
                            public_hex=header["public_hex"],
                            epoch=header["epoch"],
                            grid_seed=header["grid_seed"],
                            signature=header["signature"])
        if not self.env.add_proposal(sp):
            return False                      # signature, seat or chain wrong
        self.blocks[digest] = block
        self.pending.pop(digest, None)
        return True

    def signed_height(self) -> int:
        """The highest height a verified leader signature has claimed.

        The catch-up trigger, and the reason it cannot be forged: every header
        counted here passed `_take_header`, which checks the roster key and
        the signature before believing anything else about it.
        """
        return self._signed_height

    def absorb(self, payload: dict) -> int:
        """Merge one peer's envelope frame.  Returns how much was new."""
        changed = 0
        for header in payload.get("proposals", ()):
            changed += self._take_header(header)
        for att in payload.get("attestations", ()):
            if isinstance(att, Attestation):
                changed += self.env.add_attestation(att)
        for fault in payload.get("faults", ()):
            if isinstance(fault, FaultReport):
                changed += self.env.add_fault(fault)
        return changed

    def _take_header(self, header) -> int:
        if not isinstance(header, dict):
            return 0
        needed = {"leader_id", "public_hex", "epoch", "grid_seed", "signature",
                  "height", "block_hash"}
        if needed - set(header):
            return 0
        digest = header["block_hash"]
        if digest in self.env.proposals or digest in self.pending:
            return 0
        # Check the signature before believing anything else about it: the
        # message covers the hash, so a header that verifies pins exactly one
        # body, and a peer cannot make us fetch a block nobody proposed.
        if header["public_hex"] != self.env.validators.get(header["leader_id"]):
            return 0
        if header["leader_id"] != self.env.leader_id:
            return 0
        if header["epoch"] != self.epoch or header["grid_seed"] != self.grid.seed:
            return 0
        msg = SignedProposal.message(self.chain_id, header["height"], digest,
                                     header["epoch"], header["grid_seed"])
        if not verify_sig(header["public_hex"], msg, header["signature"]):
            return 0
        # Signed by this epoch's leader, so the height it claims is a fact
        # about the chain and not a claim about it.  A seat that is behind
        # learns so here, and nowhere else it could trust.
        self._signed_height = max(self._signed_height, int(header["height"]))
        body = self.blocks.get(digest)
        if body is not None:
            sp = SignedProposal(block=body, leader_id=header["leader_id"],
                                public_hex=header["public_hex"],
                                epoch=header["epoch"],
                                grid_seed=header["grid_seed"],
                                signature=header["signature"])
            return 1 if self.env.add_proposal(sp) else 0
        self.pending[digest] = dict(header)
        return 1

    def missing(self) -> list:
        """Block bodies this seat has a signed header for and has not got."""
        return sorted(self.pending)

    # ── reacting ─────────────────────────────────────────────────────────────

    def react(self):
        """Validate the sole proposal once, then attest or report.

        Mirrors `Ceremony._react` exactly; the difference is that it runs for
        one seat, when a message arrives, rather than for all of them on a
        clock.
        """
        env, node = self.env, self.node
        evidence = env.equivocation_evidence()
        if evidence and not self.reacted:
            a, b = evidence
            env.add_fault(node.report("equivocation", self.height, self.epoch,
                                      "leader proposed two blocks", (a, b)))
            self.reacted = True
            env.attestations.pop(node.id, None)
            return
        if self.reacted:
            return
        sp = env.sole_proposal()
        if sp is None or self.validated is not None:
            return
        ok, why = self.workload.validate(node, sp.block)
        self.validated = (sp.block_hash, ok, why)
        if ok:
            env.add_attestation(node.attest(sp.block_hash, self.height,
                                            self.epoch, self.grid.seed))
        else:
            env.add_fault(node.report("invalid_block", self.height, self.epoch,
                                      why[:120], (sp,)))
            self.reacted = True

    # ── sending ──────────────────────────────────────────────────────────────

    def wire(self) -> dict:
        """What this seat tells a neighbour: headers, attestations, faults.

        Never a block body.  132 directed messages an epoch times 542 KB is
        71 MB; times two kilobytes it is a rounding error.
        """
        env = self.env
        return {"epoch": self.epoch, "grid_id": self.grid_id,
                "proposals": [proposal_header(sp)
                              for sp in env.proposals.values()]
                             + list(self.pending.values()),
                "attestations": list(env.attestations.values())
                                + list(env.shadow.values()),
                "faults": list(env.faults.values())}

    def neighbours(self):
        """The undirected sync graph, not `Grid.neighbours`.

        `front` and `right` are defined from a seat's own perspective, so the
        leader — alone in row 0 — has neither, and asking it for its
        neighbours returns nothing at all.  The in-process ceremony never
        noticed: it exchanges over `grid.edges()`, which is undirected. A node
        that can only see its own side of the graph has to use the adjacency.
        """
        return sorted(self.grid.adjacency().get(self.node.id, ()))

    # ── deciding ─────────────────────────────────────────────────────────────

    def accepted(self):
        """(block, certificate) once quorum is in, otherwise None."""
        if self.env.substantiated_equivocation() is not None:
            return None
        sp = self.env.sole_proposal()
        if sp is None or self.validated is None or not self.validated[1]:
            return None
        atts = self.env.attestations_for(sp.block_hash)
        if len(atts) < self.quorum:
            return None
        from ..block import QuorumCert
        cert = QuorumCert.build(self.chain_id, self.height, sp.block_hash,
                                self.epoch, self.grid.seed, atts)
        block = self.blocks[sp.block_hash]
        block.quorum_cert = cert
        return block, cert

    def why_not(self) -> str:
        if self.env.substantiated_equivocation() is not None:
            return "leader equivocated"
        if not self.env.proposals:
            if self.pending:
                # Worth distinguishing: a seat that has the leader's signed
                # header and not its body is in a different situation from one
                # that heard nothing, and reporting both as silence sent me
                # looking at the wrong half of the protocol more than once.
                return (f"header seen, waiting for the block body "
                        f"({len(self.pending)} pending)")
            return "no proposal reached this seat"
        if len(self.env.proposals) > 1:
            return "conflicting proposals"
        if self.pending:
            return f"waiting for the block body ({len(self.pending)} pending)"
        if self.validated is None:
            return "not validated yet"
        if not self.validated[1]:
            return f"block rejected: {self.validated[2]}"
        sp = self.env.sole_proposal()
        n = len(self.env.attestations_for(sp.block_hash))
        return f"{n} attestations, quorum is {self.quorum}"

    def roll(self, cert) -> AttendanceRoll:
        """Who attended — and the honest note that this is a stopgap.

        The simulation builds the roll from the *union* of every seat's view,
        which is objective there because one process holds them all.  A real
        node holds one view, and seven views differ. On the first networked run
        epoch 1 finalised and epoch 2 died with "attendance roll is not the one
        this grid produced": one seat had collected five attestations, another
        six, so they wrote different rolls and rejected each other's block.

        The certificate is no better, and that was the second attempt: each
        seat assembles its own certificate from its own envelope, so the certs
        differ too. Nothing assembled *after* agreement is agreed.

        **The real fix is that the block at epoch e carries the certificate of
        epoch e-1**, and a seat validates the roll against that certificate
        rather than against what it happened to see. That is a change to the
        block format and it is not built.

        Until then the network path uses the one function of committed state
        available: everyone seated in a ceremony that finalised. `grid.seats`
        comes from the register and the epoch seed, so every node computes it
        identically. The cost is real and should not be glossed: a seat that
        said nothing still earns attendance, so the gate measures "seated while
        the grid worked" rather than "did the work".
        """
        return AttendanceRoll(grid_id=self.grid_id, epoch=self.epoch,
                              leader_id=self.grid.leader,
                              seated=tuple(sorted(self.grid.seats)),
                              attended=tuple(sorted(self.grid.seats)))

    def __repr__(self):
        return (f"Seat({self.node.id}, epoch={self.epoch}, "
                f"{len(self.env.attestations)}/{self.quorum} attestations)")
