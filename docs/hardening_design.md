# Hardening a block into history — fin6 design sketch, part three

The last stage: how a block leaves the supreme mempool and becomes network
history. Follows `private_chain_design.md` and `tiered_ceremony_design.md`
(implemented in `chain/`).

Supersedes the earlier `witness_layer_design.md`, which framed this stage as
verification. It is not: it is hardening, and the analogy is Bitcoin mining.

## 0. Two kinds of final

The ceremony decides what is true. Hardening decides that it stays true.

Parts one and two produce **consensus finality**: a supreme grid agrees a network
block, a quorum certificate proves it, and the block lands in the supreme
mempool. That is instant and it is enough — right up until the moment the
consensus itself was wrong. A captured supreme grid, a quorum breach, a roster
that drifted: in every one of those cases the certificate is valid and the
history is not.

This stage adds **historical finality**, which accrues. Once agreed, a block is
stamped by virtual nodes spending single-use turns, and the accumulated weight of
those turns is what an attacker would have to out-spend to say something
different about that height. Same job Bitcoin's proof of work does — and none of
the other jobs mining does (leader election, Sybil resistance, fork choice among
honest peers), because the tiers below already handle those.

```
supreme mempool          hardening              network history
(agreed, reversible) --> w turns spend    -->   (weight accumulates,
                         themselves             cost to unsay grows)
```

## 1. What hardening is actually for

Under normal operation the hardening layer **decides nothing**. The supreme grid
has already agreed exactly one block for the height; there is no competing
candidate; the turns stamp the only thing on offer.

**This layer exists for the case where the ceremony was wrong.** If the tiers
below never fail, hardening is pure insurance and nobody notices it. If they do
fail, hardening is what stops the bad history from sticking, because replacing it
means burning turns the honest majority will not give up.

Two independent scarcities, neither sufficient alone:

- **The turns bound who.** Only a holder of an unspent turn can add weight, and
  only once. Influence is capped by the roster, not by hardware. Relies on the
  roster being honestly distributed.
- **The work bounds how fast.** Each stamp costs real computation, so weight
  accumulates at a rate anyone can measure without trusting a clock. Relies on
  nothing but arithmetic.

Turns alone would rest the whole layer on the roster — the very thing a consensus
failure calls into question. Work alone would let anyone with enough hardware
rewrite anything. Together, an attacker needs a majority of the unspent pool *and*
the machines to spend it, and the first is not for sale.

## 2. A turn, spent

```
anchor = H(block_hash, cumulative_weight(h-1), era_root)

stamp  = { leaf_index,          # which turn this was
           auth_path[17],       # proves it belongs to the era
           nonce,               # H(anchor || leaf || nonce) < target
           ots_signature }      # one-time, over all of the above
```

The puzzle is the work. The one-time signature makes the turn spendable only
once: signing two different anchors with one WOTS+ key reveals the private key,
so a turn that stamps two competing blocks publishes its own forgery material and
both stamps are discarded. Nobody has to catch it; the arithmetic catches it.

Enforcing "exactly once" needs a spent-set the network agrees on — the nullifier
set again, the same `SealAccumulator` in `chain/seal.py`. A note spent twice and a
turn spent twice are the same problem.

**Cheap to check, expensive to make.** A stamp verifies in ~520 hashes (one for
the puzzle, 17 for the auth path, ~500 for WOTS+), so a block of 32 stamps checks
in ~17,000 hashes — microseconds. Producing one costs whatever difficulty says.

## 3. Drawing the turns

```
turns(h) = first w unspent leaves in the order induced by
           H(prev_hardened_hash, h, era_root)
```

Seeding from *h* would let whoever assembles *h* grind it until the draw landed
on turns they control. Seeding from the previous hardened block costs one block
of foreknowledge (~40 s) and removes grinding entirely.

A drawn turn is **consumed whether or not it stamps**. Otherwise an attacker
could stall selectively until a committee it owned came up. Consuming on draw
means denial cannot steer selection — it only burns the pool faster.

## 4. Accumulation and fork choice

```
weight(h)     = sum of difficulty over the valid stamps on block h
cumulative(h) = cumulative(h-1) + weight(h)

fork choice   : greatest cumulative weight
                a branch reusing any spent turn is invalid outright
```

A block enters network history once it carries at least `t` valid stamps (2/3 of
`w`), and gets harder to displace as later blocks pile weight on top.

## 5a. What implementation changed — the threshold compounds

The sketch below argues a rewrite is bounded by the attacker's share of the pool,
Bitcoin-style. Building it showed the **first** line of defence is different and
stronger.

An attacker does not choose which turns stamp its fork — the draw does, from the
previous block's hash — so it can only stamp the drawn turns it happens to own,
and it must clear the 2/3 threshold on a **fresh unbiased draw every block**. The
requirement compounds instead of averaging:

| attacker share | P(one block) | P(six consecutive) |
|---|---|---|
| 10% | 2.4e-15 | ~0 |
| 33% | 3.8e-05 | ~0 |
| 50% | 2.5e-02 | 2.5e-10 |
| 67% | 5.0e-01 | 1.6e-02 |
| 80% | 9.6e-01 | 7.8e-01 |

The practical bar is around 80% of the pool, not 51%. The finite-pool ceiling
below is the *second* line, bounding depth if the first is ever cleared.

The cost is liveness: below 2/3 participation the honest chain stalls too, and
each stalled attempt consumes a committee, so the pool drains faster. Threshold
is a trade, not a free win — and it is now a tunable
(`HardeningParams.threshold_num/den`) rather than an assumption.

## 5. The rewrite ceiling

In Bitcoin a deep rewrite is improbable. Here it is impossible, and the
difference is the finite pool.

To replace the block at depth *d*, an attacker must build a branch carrying more
weight than the honest chain's `d × w` stamps. Every stamp has to come from a
turn the attacker **owns** and that is **still unspent** — the honest chain's
turns are burned on the honest history and can never be re-cast.

```
max fork depth  =  (attacker's unspent turns) / w
```

At `w = 32` and a 39.5 s interval:

| attacker share | turns held | deepest possible rewrite | wall clock |
|---|---|---|---|
| 5% | 3,500 | 109 blocks | 1.2 h |
| **10%** | **7,000** | **219 blocks** | **2.4 h** |
| 25% | 17,500 | 547 blocks | 6.0 h |
| 33% | 23,333 | 729 blocks | 8.0 h |

Upper bounds — the honest chain keeps extending during the attempt, so real reach
is shorter.

**A failed attack is permanently disarming.** In Bitcoin an attacker who fails
still owns the hardware and can try again next week. Here the turns are consumed
in the attempt and cannot be reissued, so every failure shrinks the attacker's
maximum future reach. Capacity is spent, not rented.

## 6. Interval and era are the same knob

The finite pool couples two things that are independent in Bitcoin. Spending `w`
turns per block against 70,000 fixes the era at `70,000 / w` blocks, so choosing
an era duration fixes the block interval:

```
block_interval  =  era_duration * w / 70,000
```

| w | blocks per era | era = 1 hour | era = 1 day | era = 1 week |
|---|---|---|---|---|
| 4 | 17,500 | 0.2 s | 4.9 s | 34.6 s |
| 8 | 8,750 | 0.4 s | 9.9 s | 69 s |
| 16 | 4,375 | 0.8 s | 19.7 s | 2.3 m |
| **32** | **2,187** | **1.6 s** | **39.5 s** | **4.6 m** |
| 64 | 1,093 | 3.3 s | 79 s | 9.2 m |

Wide hardening, fast blocks, long eras: pick two. Recommendation is `w = 32`,
`t = 22`, difficulty targeting **39.5 s** and a one-day era — slow enough that
rollover is a scheduled background job, wide enough that a 10% adversary tops out
at a couple of hours of reach.

Difficulty retargets on observed interval as Bitcoin's does, and does the same
second job: it is the network's clock, working without trusting timestamps.

**Rollover.** The pool runs out on a schedule, so the next era's tree must be
built and its root published in a block hardened by the outgoing era — eras
chain. Building a root means deriving 131,072 leaf public keys, ~132 million hash
operations: seconds in C, and something to precompute before the boundary.

## 7. What the work should be

A plain hash puzzle — `H(anchor || leaf || nonce) < target`.

| candidate | what it buys | why not here |
|---|---|---|
| hash puzzle | simple, tunable, cheap to verify, no setup | **chosen** |
| verifiable delay function | unparallelisable | the turns already cap an attacker's rate; and practical constructions need groups of unknown order, which are not post-quantum |
| proof of sequential work | same, from hashes alone | same redundancy, much more machinery |
| memory-hard puzzle | levels the field against custom hardware | a permissioned roster already decides who may participate |

The reasoning turns on one observation: **an attacker's rate is capped by turn
ownership, not by hardware**, so the usual reason to reach for unparallelisable
work is already handled by the roster. That leaves the puzzle with the narrower
job of making weight measurable and costly, which the simplest construction does
best.

Caveat: Grover gives a quantum adversary a quadratic speedup on preimage search,
so *n* bits of difficulty is worth *n/2* against one. A bounded degradation, fixed
by doubling the bits — unlike the group-based alternatives, where quantum removes
the guarantee rather than halving it.

## 8. What hardening fixes, and what it cannot

**Fixed by construction**

- *Deep rewrites* — bounded absolutely by the attacker's share of the pool.
- *Repeat attempts* — every failure permanently shrinks the attacker's reach.
- *Turn equivocation* — stamping two blocks leaks the one-time key, voids both.
- *Grinding the draw* — the committee is fixed by the previous hardened block.
- *Selective stalling* — turns are consumed on draw, so denial burns the pool
  instead of steering it.

**Not fixed**

- **A lazy stamper.** Nothing forces a turn-holder to check the block before
  stamping. A holder that stamps whatever it is handed is donating its turn to
  whoever asks — a sharper statement of the problem than "lazy verifier", because
  the donation is quantifiable.
- **"Virtual" needs hosts.** 70,000 turns on 200 machines is 200 points of
  failure. The pool's distribution across independent operators *is* the security
  parameter.
- **Shallow reorgs.** A block one deep has one block of weight on it. Hardening
  is a gradient, not a switch — same as Bitcoin.
- **Energy.** This is proof of work, with proof of work's costs, chosen
  deliberately for a permissioned chain that could have avoided them.

## 9. What this adds to `chain/`

| module | change |
|---|---|
| `hardening/pool.py` | *new* — era one-time key tree, seed-derived leaves, auth paths, precomputed rollover |
| `hardening/draw.py` | *new* — committee selection over unspent turns, consume-on-draw, threshold extension |
| `hardening/stamp.py` | *new* — build and verify a stamp |
| `hardening/weight.py` | *new* — cumulative weight, difficulty retarget, fork choice |
| `chain/seal.py` | unchanged — `SealAccumulator` serves the spent-turn set as it serves nullifiers |
| `chain/tiered.py` | `HardenedBlock` wrapping a `NetworkBlock` with stamps and weight |
| `chain/tiers.py` | a phase H after phase X; the epoch is not over until the block is hardened |

Nothing in `ceremony.py`, `register.py` or the grid machinery moves. The
hardening layer sits above the hierarchy and never reaches into it — which is
what keeps it usable as a backstop for that hierarchy's own failures.

## 10. Open items

| item | why it is open |
|---|---|
| How the 70,000 turns are distributed | Still the most important unanswered question, and now quantitative: the attacker's share of the pool *is* the rewrite ceiling. Needs a mapping across independent operators, and a way to verify it. |
| The lazy stamper | A turn stamped without checking is a turn donated. Committing to sampled proof digests proves fetching, not checking. The *attester* half of this is now provable — see `Seat.catch_lazy`: an attestation over a block that does not validate is a signed statement its author could not have made honestly, which is the same shape as equivocation. The stamper half is not, because a stamp commits to a block hash and nothing about having checked it. |
| Difficulty in a permissioned setting | Retargeting assumes a competitive rate to measure. With a known roster and consume-on-draw the rate is closer to fixed; the retarget rule may need to be schedule-driven rather than race-driven. |
| Interaction with instant consensus finality | The supreme grid says a block is final; hardening says it becomes final. Applications need a stated rule for which to act on, and at what depth. |
| Era genesis | Era n+1 is authorised by era n; era 0 is a trusted setup and should be named as one. |
| Stateful signing | One-time keys must never be reused; a holder restored from backup can destroy its own turn. |
| Reorg mechanics | If a fork does win, ledger state has to roll back. Part four added undo records and `ChainStore.rollback`, kept to `retention_depth` — 729 blocks at a third of the pool. Beyond that ceiling there is nothing, and a node that cannot roll back that far diverges permanently from one that can. |

## Implemented

`chain/hardening/` — `wots.py`, `pool.py`, `draw.py`, `stamp.py`, `history.py`,
`params.py`, plus phase H in `chain/tiers.py` (`run_epoch_to_history`) and 28
tests in `chain/tests/test_hardening.py`. `python3 -m chain.demo_hardening` runs
consensus through to hardened history.

Measured: WOTS keygen 1.0 ms, sign/verify 0.5 ms, signature 2,144 B; a production
era tree (2^17 leaves, 70,000 turns) builds in ~131 s of pure-Python hashing;
84 KB of stamps per block at width 32.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/aa0c5d95-924d-4ea0-a300-03bf4c3aec73
