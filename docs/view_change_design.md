# Changing view when the leader does not answer

*Part eleven. Review C1.*

In process, a view change is a retry loop: `run_epoch` reseats the grid from a
fresh seed, skips leaders already tried, and runs the ceremony again. Every
seat sees every message and the whole thing is synchronous, so "the block did
not finalise" is a fact everybody agrees on before anybody acts on it.

On a network it is none of those things. A leader that has not proposed is
indistinguishable from a leader whose proposal has not arrived yet; seats reach
that conclusion at different moments; and — the part that makes this a protocol
rather than a loop — **a block may have finalised at one seat while the others
are giving up on it**. Retrying naively is not slow, it is unsafe.

Today the network path seats at view 0 and never moves. A dead leader costs the
whole epoch, and the next epoch's leader is drawn from a different seed, so the
chain recovers on its own in 19.75 s. That is liveness by rotation, and it is
why C1 is class C rather than class A: nothing is broken, the recovery is just
an order of magnitude slower than it needs to be, and it rewards a leader that
stalls deliberately with a whole epoch of everybody's time.

## 1. What makes it unsafe

Quorum is `ceil(2n/3)`. Two quorums intersect in more than `n/3` seats, so at
least one honest seat is in both — which is exactly why two different blocks
cannot both finalise **in one view**: that seat would have had to attest twice.

Across views the argument evaporates. Suppose in view 0 five of seven seats
attest to block **B**, and one seat sees all five: **B is final for that seat**.
The other seats time out, move to view 1, and the new leader proposes **C**.
Nothing said so far stops them finalising it. Two blocks, one height, no
misbehaviour anywhere — just a message that did not arrive in time.

The fix is the classical one and there is no cheaper correct answer: a seat that
has attested is **locked**, a view change **collects the locks**, and the new
leader is **bound by them**.

## 2. The protocol

**Views.** View `v` of epoch `e` in grid `g` seats from
`h("view", first_seed, e, g, v)`, excluding the leaders of earlier views so
each view gets a new one. Attestations already sign `grid_seed`, so an
attestation is bound to its view for free, and so is the certificate that
collects them.

**Locking.** A seat that attests to `B` in view `v` records `locked = (v, B)`.
It will not attest to anything else at that height unless a view change
releases it (§2.4).

**The view-change message.** On timeout a seat broadcasts a signed
`ViewChange`: chain id, height, epoch, the view it is moving *to*, and its lock
— `(locked_view, locked_block)`, or none. Signed over all of it, so a lock
cannot be edited in flight, and bound to one view so it cannot be replayed into
the next.

**The new leader's obligation.** The leader of view `v` collects a quorum of
`ViewChange` messages for `v` — call it the **view-change certificate** — and
proposes with it attached. If any message in that certificate reports a lock,
the leader **must** re-propose the locked block with the highest locked view.
Only if none does may it propose something new.

**Accepting a proposal in view v > 0.** A seat checks the certificate before
the block: a quorum of distinct seated signers, every message for this height,
epoch and view, every signature valid. Then it applies the same rule the leader
was bound by, against the same set of messages — the certificate travels with
the proposal precisely so both sides evaluate the identical evidence — and
refuses a proposal that is not what the locks require.

### 2.4 Why a lock can be released, and when it is safe

A seat that is locked on `B` will attest to `C` if the certificate says so:
it releases its lock when the quorum it just saw reports a higher lock for a
different block, or reports no lock at all.

That sounds like it gives back what §1 took, and it does not. If `B` *finalised*
in view `v`, a quorum attested to it, and every one of them locked it. Any
view-change certificate for a later view holds a quorum too, and two quorums
share at least one honest seat — so a certificate that could release a lock on
`B` cannot exist: every one of them contains somebody reporting `(v, B)`, and
`B` has the highest locked view among them. A lock that *can* be released is
one that never finalised, and overriding it is the whole point, because
otherwise a single crashed seat's half-finished vote would stall the height for
ever.

## 3. Timeouts are the clock, not a negotiation

Every node already derives the epoch from wall time; the schedule is the one
thing nobody has to agree about because everybody computes it. Views get the
same treatment: the decide window is divided into `max_views` slices, and a
seat that has not accepted a block when its slice ends moves to the next view.
No timer negotiation, no exponential back-off, no view-change-of-the-view-change.

The cost is honest: the protocol's liveness now depends on the clock skew the
deployment already assumes for its epochs, and a seat whose clock is far enough
out attests into a view nobody else is in. That is a fault the harness can
already stage — `skew_ms` exists for exactly this — rather than a new
assumption.

## 4. What this does not do

- **No pipelining.** A view is a whole attempt at one height, not a stage in a
  chained protocol. The epoch ends when it ends.
- **No view change at the super or supreme tier.** Those are C2's problem, and
  the supreme grid stalling is a different failure — everything stops, rather
  than one grid's height not advancing.
- **No proposal without a body.** A leader bound to re-propose a locked block it
  does not hold cannot; the view fails and the next one tries. Bodies are
  gossiped, so this is rare and it is safe — it costs a view, never a fork.
- **`max_views` is a budget, not a guarantee.** If every view in an epoch fails,
  the epoch produces nothing, exactly as it does today. The chain recovers at
  the next epoch, which is the behaviour this change is an improvement on rather
  than a replacement for.
