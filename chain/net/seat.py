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
    """The part of a proposal that travels every round.

    The view and its certificate travel with it because the signature covers
    them: a header without them cannot be checked, and a header with the wrong
    ones fails to verify, which is the property that stops a relay pairing a
    proposal with a quorum that would permit a different block.
    """
    return {"leader_id": sp.leader_id, "public_hex": sp.public_hex,
            "epoch": sp.epoch, "grid_seed": sp.grid_seed,
            "signature": sp.signature, "height": sp.height,
            "block_hash": sp.block_hash, "view": getattr(sp, "view", 0),
            "view_cert": getattr(sp, "view_cert", None)}


class Seat:
    """This node, in this grid, for this epoch."""

    def __init__(self, node, grid, workload, *, epoch: int, quorum: int,
                 validators: dict, counting=None, grid_id: str = "",
                 chain_id: str | None = None, height: int | None = None,
                 lazy: bool = False, view: int = 0, lock=None):
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
        self._reported_lazy: set = set()
        # Part three's open item, made runnable and then made costly.  A lazy
        # seat attests without validating: it is in the fault table because the
        # design names it, and `behaviour` had one branch on the network path —
        # `silent` — so nothing could even produce the fault, let alone catch
        # it.  A fault nobody can run is a fault nobody can test, and a fault
        # nobody can prove is a fault nobody can charge for: see `catch_lazy`.
        self.lazy = lazy
        self.validated = None         # (block_hash, ok, why)
        self.reacted = False
        #: Which attempt at this height this is, and what this seat is holding
        #: from earlier ones.  A seat that has attested is *locked*: it carries
        #: that vote into the next view rather than forgetting it, because
        #: forgetting it is how two blocks finalise at one height.  Part eleven
        #: and review C1 — docs/view_change_design.md.
        self.view = view
        self.locked = lock            # (view, block_hash) or None
        self.view_changes: dict = {}  # node_id -> ViewChange, for this view
        self.last_refusal = ""        # why a proposal was not reacted to

    @property
    def is_leader(self) -> bool:
        return self.grid.leader == self.node.id

    # ── proposing ────────────────────────────────────────────────────────────

    def propose(self, meta, limit=None, view: int = 0, view_cert=None):
        """Leader only: build, sign, and hold the body."""
        block = self.workload.build(self.node, meta, limit=limit)
        return self.adopt(block, view=view, view_cert=view_cert)

    def adopt(self, block, view: int = 0, view_cert=None):
        """Sign a block this seat already holds, for this view.

        The other half of `propose`, and the one a view change needs: a leader
        bound by a lock does not get to build anything — its job is to carry
        the block the quorum reported, which it must already have.
        """
        sp = self.node.propose(block, self.epoch, self.grid.seed, view=view,
                               view_cert=view_cert)
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
                            signature=header["signature"],
                            view=header.get("view", 0),
                            view_cert=header.get("view_cert"))
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
        for vc in payload.get("viewchanges", ()):
            changed += self.add_view_change(vc)
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
        cert = header.get("view_cert")
        msg = SignedProposal.message(
            self.chain_id, header["height"], digest, header["epoch"],
            header["grid_seed"], header.get("view", 0),
            "" if cert is None else cert.digest())
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
                                signature=header["signature"],
                                view=header.get("view", 0),
                                view_cert=cert)
            return 1 if self.env.add_proposal(sp) else 0
        self.pending[digest] = dict(header)
        return 1

    def missing(self) -> list:
        """Block bodies this seat has a signed header for and has not got."""
        return sorted(self.pending)

    # ── changing view ────────────────────────────────────────────────────────

    def view_change(self) -> "ViewChange":
        """This seat's statement that it is moving on, and what it holds.

        Produced once per view and kept, so a seat that gossips twice does not
        sign two different statements about the same move.
        """
        from ..viewchange import sign_view_change

        mine = self.view_changes.get(self.node.id)
        if mine is None:
            mine = sign_view_change(self.node, self.height, self.epoch,
                                    self.view, self.locked)
            self.view_changes[mine.node_id] = mine
        return mine

    def add_view_change(self, vc) -> int:
        """Somebody else's, kept if it is for this view and really theirs."""
        from ..viewchange import ViewChange

        if not isinstance(vc, ViewChange):
            return 0
        if (vc.chain_id, vc.height, vc.epoch, vc.view) != \
                (self.chain_id, self.height, self.epoch, self.view):
            return 0
        if vc.public_hex != self.env.validators.get(vc.node_id):
            return 0
        if vc.node_id in self.view_changes or not vc.verify():
            return 0
        self.view_changes[vc.node_id] = vc
        return 1

    def view_cert(self):
        """The quorum this seat can propose under, or None if it is short.

        Deterministic in *which* quorum it picks — the lowest node ids — so two
        leaders assembling from the same messages assemble the same
        certificate. Nothing depends on that, since the certificate travels
        with the proposal, but a certificate that changed between two calls
        would make the leader's own signature a moving target.
        """
        from ..viewchange import ViewChangeCert

        if len(self.view_changes) < self.quorum:
            return None
        chosen = [self.view_changes[nid]
                  for nid in sorted(self.view_changes)][:self.quorum]
        return ViewChangeCert(view=self.view, changes=tuple(chosen))

    def acceptable(self, sp) -> tuple:
        """(ok, reason) — may this seat react to this proposal at all?

        The view rule, checked before the block is validated, because a
        proposal in a later view that is not what the locks require is not a
        block this seat has any business spending 25 ms on.
        """
        from ..viewchange import may_propose

        if getattr(sp, "view", 0) != self.view:
            return False, (f"proposal is for view {getattr(sp, 'view', 0)}, "
                           f"this seat is in view {self.view}")
        cert = getattr(sp, "view_cert", None)
        if self.view > 0:
            if cert is None:
                return False, "a proposal after view 0 must carry its view change"
            ok, why = cert.check(chain_id=self.chain_id, height=self.height,
                                 epoch=self.epoch, view=self.view,
                                 quorum=self.quorum,
                                 validators=self.env.validators)
            if not ok:
                return False, why
        return may_propose(cert, sp.block_hash, self.view)

    def release_or_keep(self, cert) -> bool:
        """Take the certificate's word for what this height is holding.

        A seat locked on a block the quorum does not carry forward releases it
        — which is safe for exactly the reason §2.4 of the design gives: a
        block that *finalised* was locked by a quorum, any later quorum shares
        an honest seat with that one, so a certificate that omits it cannot
        exist. A lock this rule can release is one that never finalised, and
        overriding it is the whole point, or one crashed seat's half-finished
        vote would stall the height for ever.
        """
        required = cert.required_block() if cert is not None else None
        if self.locked is None:
            return False
        if required is None or required != self.locked[1]:
            self.locked = None
            return True
        return False

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
        ok, why = self.acceptable(sp)
        if not ok:
            # Not a fault: a seat and a leader can legitimately be in different
            # views for a moment.  It is a refusal to attest, and the reason is
            # what `why_not` will say if the view ends here.
            self.last_refusal = why
            return
        if self.lazy:
            # The whole of the behaviour: sign the statement without checking
            # it.  Cheaper than honesty, indistinguishable from it while every
            # block happens to be valid, and self-incriminating the moment one
            # is not — see `catch_lazy`.
            self.validated = (sp.block_hash, True, "not checked")
            self.locked = (self.view, sp.block_hash)
            env.add_attestation(node.attest(sp.block_hash, self.height,
                                            self.epoch, self.grid.seed))
            return
        ok, why = self.workload.validate(node, sp.block)
        self.validated = (sp.block_hash, ok, why)
        if ok:
            self.locked = (self.view, sp.block_hash)
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
                "view": self.view,
                "proposals": [proposal_header(sp)
                              for sp in env.proposals.values()]
                             + list(self.pending.values()),
                "attestations": list(env.attestations.values())
                                + list(env.shadow.values()),
                "viewchanges": list(self.view_changes.values()),
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
        cert = QuorumCert.build(
            self.chain_id, self.height, sp.block_hash, self.epoch,
            self.grid.seed, atts,
            shadow=[a for a in self.env.shadow.values()
                    if a.block_hash == sp.block_hash])
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
            return self.last_refusal or "not validated yet"
        if not self.validated[1]:
            return f"block rejected: {self.validated[2]}"
        sp = self.env.sole_proposal()
        n = len(self.env.attestations_for(sp.block_hash))
        return f"{n} attestations, quorum is {self.quorum}"

    def roll(self, cert) -> AttendanceRoll:
        """Who attended, from the certificate that finalised the block.

        This method used to carry a long apology, and part nine spent it. The
        history is worth keeping because it explains the shape:

        The simulation built the roll from the *union* of every seat's view,
        which is objective there because one process holds them all. A real
        node holds one view, and seven views differ — on the first networked
        run epoch 1 finalised and epoch 2 died with "attendance roll is not
        the one this grid produced", because one seat had collected five
        attestations and another six. The certificate was no better as a
        *local* object, and that was the second attempt: each seat assembles
        its own from its own envelope, so the certs differ too.

        What was missing was not a better local view but a place to put the
        evidence. The block at epoch e now carries the certificate of e-1, so
        the roll is derived from bytes every node reads out of the same block
        rather than from anything a seat remembers. Nothing assembled after
        agreement is agreed — so the thing that decides attendance is no
        longer assembled after agreement, it is carried into the next one.

        This is still the seat's own certificate, and it is still what this
        node will offer if it leads next epoch. The difference is that it is
        no longer what this node *checks against*: `LocalWorkload.roll_from`
        derives the expected roll from the block's copy.
        """
        return AttendanceRoll.from_cert(
            self.grid_id, cert, self.grid.seats, self.grid.leader)

    def catch_lazy(self):
        """Attesters that signed a block this seat found invalid.

        The one thing that *can* be proved about laziness, and it has the same
        shape as equivocation: a signed statement its author could not have
        made honestly. An attestation names a block hash and is signed by a
        roster key; if that block does not validate, then either the attester
        did not check it or it checked and lied.

        What separates a name in a log from a name in the register is whether
        a third party can re-run the check. Review B1 is the whole of that
        distinction:

        * the block's own bytes contradict each other — a `tx_root` that is not
          the root of the transactions under it, a transaction that does not
          authenticate — and then anybody holding the block reaches the same
          verdict, this epoch or next year. The report carries the block, it
          proves itself, and `faulted_from` suspends the attesters.
        * the block failed a *contextual* check — an input already spent, a tip
          that has moved — and then nobody can re-derive the verdict later.
          The names go in the log and no report travels, because a claim a
          validator cannot check is a claim a leader could invent about anyone
          it disliked.

        Returns the names either way; the difference is what gets filed.

        The honest limit on top of that: laziness is only catchable when there
        is something to catch. A lazy seat in a network whose blocks are all
        valid attests to valid blocks and is invisible, which is also to say it
        has done no harm.
        """
        from ..faults import reportable, self_evident_flaw

        if self.validated is None or self.validated[1]:
            return ()
        block_hash, _, why = self.validated
        block = self.blocks.get(block_hash)
        culprits = []
        for att in list(self.env.attestations.values()) + \
                list(self.env.shadow.values()):
            if att.block_hash != block_hash or att.node_id == self.node.id:
                continue
            if att.node_id in self._reported_lazy:
                continue
            self._reported_lazy.add(att.node_id)
            culprits.append(att)
        if not culprits:
            return ()

        flaw = (None if block is None
                else self_evident_flaw(block, self.node.params,
                                       chain_id=self.chain_id))
        if flaw is not None and reportable(block):
            self.env.add_fault(self.node.report(
                "lazy_attestation", self.height, self.epoch,
                f"attested to a block that contradicts itself: {flaw[:70]}",
                tuple(culprits), subject=block))
        return tuple(a.node_id for a in culprits)

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
