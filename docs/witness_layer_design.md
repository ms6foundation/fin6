# Superseded

This file framed the final stage — moving a block from the supreme mempool into
network history — as a **verification** layer: 70,000 one-shot verifier-only
nodes checking blocks and sampling transaction proofs.

That was the wrong reading. The final stage is **hardening**, and the analogy is
Bitcoin mining: the turns are not there to check that a block is valid (three
tiers already did that), they are there to make an agreed block expensive to
unsay.

See **`hardening_design.md`** for the current design.

What carried over unchanged: the one-time-key structure (a turn that stamps two
blocks leaks its own key), the ungrindable committee draw seeded from the
previous block, consume-on-draw so denial cannot steer selection, the spent-turn
set as a nullifier set, and era rollover chaining through the blocks.

What changed: the layer's purpose, the fork-choice rule, the coupling between
block interval and era length, and the central security property — a rewrite is
now bounded absolutely by the attacker's share of a finite pool rather than
probabilistically by hash rate.
