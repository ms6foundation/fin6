# fin6 private chain

A private, **transaction-based** ledger whose transactions are verified with
`mq/ms6` (MQ-hardened commitments + the 5-pass SSH zero-knowledge proof), and
whose blocks are agreed by a **scheduled grid ceremony** rather than proof of
work.

```
python3 -m chain.demo            # one grid: transfers, ceremony, Byzantine leaders
python3 -m chain.demo_tiers      # many grids: register, partitions, three phases
python3 -m chain.demo_hardening  # consensus through to hardened network history
python3 -m chain.tests.run_all   # 135 tests, ~20 s
```

Both are run from the repository root (the same place `examples/` imports
`mq.ms6` from).

---

## Module map

| file | what it holds |
|---|---|
| `params.py` | `ChainParams`, the `DEMO` and `STRONG` presets |
| `crypto.py` | domain-separated hashing, field helpers, Ed25519 signer |
| `notes.py` | the note (this chain's UTXO), its MQ commitment, its nullifier form |
| `txsystem.py` | `TxSystem` — the per-transaction MQ map |
| `transaction.py` | build / prove / verify a spend |
| `seal.py` | deterministic seal-tree root and the append-and-tombstone accumulator |
| `state.py` | `ChainState`: UTXO set, nullifier set, block application |
| `block.py` | block, header, and the signed consensus objects |
| `ceremony.py` | `Grid`, `Envelope`, `Ceremony`, leader behaviours, view change |
| `node.py` | a validating node: mempool, block production, attestation |
| `network.py` | bootstrapping a test network; wallets |
| `demo.py` | the single-grid walkthrough |
| **tiered path** | |
| `proofs.py` | proof backends over `mq/`: `ssh5`, `ssh3`, `mpcith` — all three real |
| `register.py` | `GridRegister` — attendance as rooted state, not opinion |
| `trustlist.py` | each node's private view; structurally barred from quorum |
| `locality.py` | persistent grids, seeded enrolment, nullifier partitioning |
| `tiered.py` | `CeremonyBlock` / `SuperBlock` / `NetworkBlock` |
| `tiers.py` | the three-phase epoch scheduler and per-tier workloads |
| `demo_tiers.py` | the tiered walkthrough |
| **hardening (phase H)** | |
| `hardening/wots.py` | Winternitz one-time signatures — hash-based, post-quantum |
| `hardening/pool.py` | the era: 70,000 single-use turns in a Merkle tree |
| `hardening/draw.py` | ungrindable committee selection, consume-on-draw |
| `hardening/stamp.py` | the puzzle, the one-time signature, verification |
| `hardening/history.py` | cumulative weight, spent turns, fork choice |
| `demo_hardening.py` | the full pipeline through to history |

---

## The ledger

State is a set of **notes**, never a table of balances. A note is a vector of
field coordinates

```
x_note = [ value, asset, owner, rho, blinder_0 … ]
v_note = NOTE_SYS.F(x_note)        NOTE_SYS = MQSystem(n_note)   # public, fixed
cm     = note_id(v_note)                                          # ledger id
```

Binding is MQ hardness; hiding comes from the blinders. The commitment is an MQ
map rather than a hash for one reason: the transaction proof has to *reason
about it*. `TxSystem` embeds one copy of `NOTE_SYS`'s rows per note slot, so a
single proof can relate a note's hidden value to the very commitment the ledger
stores. A hash commitment is not expressible in that language.

Two accumulators, both `ms6` seal trees: `utxo_root` over live notes,
`nf_root` over published nullifiers.

## A transaction

One spend, one polynomial map, one proof. What the proof establishes at once:

- each slot's hidden coordinates really commit to the declared `cm` — the note
  rows of `v` **are** that note's commitment vector
- `sum(inputs) − sum(outputs) = fee` (sum row)
- every note carries the same asset (asset rows)
- every **output** value lies in `[0, 2^B)` (recomp + bit rows)
- each nullifier is the public nullifier form evaluated at the note being spent
- each spending key matches the owner slot of the note it spends, so the
  attached signature authorises this spend
- the whole thing is welded to this transaction body (bind row)

Input values need no range rows: every note in the UTXO set was issued at
genesis or was a range-proven output of an accepted transaction, and with `k, m`
small and `B ≪ 255` the sum row cannot wrap the field.

`prove_hidden`'s Fiat–Shamir statement is `(v, known)` and nothing else, so the
binding scalar is passed as a *revealed* coordinate. That is what stops a proof
from being lifted onto a different transaction body — see
`test_proof_cannot_be_lifted_onto_another_transaction`.

## The ceremony

Seating: row 0 is the leader alone, rows 1..R hold up to C seats,
`R = ceil((N−1)/C)`, only the last row may be short. Seats come from sorting
node ids under a keyed hash of `grid_seed`, so seating is deterministic for
everyone and unpredictable before the previous block fixed the seed.

Edges, for every seat `(r, c)` with `r ≥ 1`:

```
front(r, c) = (r−1, c)              row 1 fronts to the leader
right(r, c) = (r, (c+1) mod C_r)    the rightmost seat wraps to the leftmost
```

Every row is a ring; each ring is fed vertically by the row in front of it.
Degree is 2 per seat regardless of N, so a round costs `O(N)` messages.

A round is a **bidirectional merge** evaluated from a snapshot of every seat's
envelope, so information moves exactly one hop per round and the run is
deterministic. Merging is a union, and everything absorbed is checked against
the validator registry as well as its signature.

Detection is structural: a leader that sends different blocks into different
columns has them meet inside a row's ring. Any seat holding two validly signed
proposals from one leader at one height files an equivocation report whose
evidence stands on its own — two signatures, one leader, one height, two hashes.

Finality: a seat accepts when it validated the block **itself** and holds
`ceil(2N/3)` attestations for it. The certificate is those attestations
committed with a seal tree, verifiable by anyone against the validator set.

---

## Costs, measured

Pure Python 3.10, no gmpy2, on the machine this was built on.

| | DEMO | STRONG |
|---|---|---|
| note coordinates (of which random) | 8 (4) | 48 (44) |
| range bits | 12 | 32 |
| ZK rounds | 80 | 80 |
| hidden dimension `h`, 1-in/2-out | 48 | 208 |
| rows `m` | 65 | 237 |
| build a transaction | 24 ms | 0.33 s |
| verify a transaction | 15 ms | 0.20 s |
| proof size | 191 KB | 0.75 MB |

Ceremony, 13 validators, `C = 5` (rows 5/5/2, diameter 4): 8 rounds, 368
directed messages, ~0.1 s excluding transaction verification. Full suite: 59
tests in ~7 s.

## Security scope — read this before believing anything above

**What is real.** Value conservation, range, nullifier derivation, spend
authorisation and body binding are all enforced by one MQ proof at 2⁻⁸⁰
soundness, checked by the independent `vs6` verifier as well as `ms6`
(`verify_transaction_vs6`). Consensus safety rests on each seat validating
independently plus a 2/3 quorum, with equivocation evidence anyone can check.

**What is not.**

1. **`DEMO` note parameters are not secure.** 8 coordinates with 4 random ones
   puts the note-commitment MQ instance inside Gröbner range. `STRONG` (48
   coordinates, 44 random) is sized per `mq/mq.md`'s own guidance and costs
   0.33 s per transaction — there is no real reason to run `DEMO` outside tests.

2. **The spend graph is public.** An input's commitment vector is carried in
   `v`, so which note is being spent is visible. Amounts, output owners and note
   randomness are hidden. This is the Mimblewimble / confidential-transactions
   model, not the Zcash one.

3. **Ed25519 is an inconsistency.** The rest of the stack is post-quantum by
   construction; the attestation and spend signatures are not. `crypto.Signer`
   is the seam where a PQ scheme drops in.

4. **Fees are burned**, not paid to the leader.

5. **No wire format.** Objects are passed in-process. `serialize_proof` exists
   for size accounting only.

---

## What implementation changed about the design

Five things the design sketch got approximately right and the code had to pin
down:

1. **Round schedule.** The sketch's `T = R + C` is the *one-way* dissemination
   bound. Finality needs attestations to come back too, so the default is
   `2 × diameter` of the sync graph. The two agree at demo size and separate
   sharply as the grid grows, with neither dominating every shape:

   | seats | C | R | R+C | diameter | 2·diameter |
   |---|---|---|---|---|---|
   | 13 | 5 | 3 | 8 | 4 | 8 |
   | 51 | 5 | 10 | 15 | 11 | 22 |
   | 101 | 5 | 20 | 25 | 21 | 42 |
   | 26 | 10 | 3 | 13 | 5 | 10 |
   | 401 | 20 | 20 | 40 | 25 | 50 |

   `2 × diameter` is the safe default because it is derived from the graph that
   actually exists rather than from the grid's shape; `R + C` under-schedules
   every tall grid in the table.

2. **Accumulators cannot be `ms6.Commitment`.** `Commitment` draws a fresh
   random salt per item, which makes it hiding — and makes its root
   non-deterministic. Two nodes holding the same UTXO set would compute
   different roots and could never agree. These sets hold already-public values,
   so they use `_SealTree` over deterministic leaves instead: binding and
   canonical, with hiding neither needed nor claimed.

3. **Envelopes must check the validator registry.** Signature-checking alone
   lets a Byzantine seat invent node ids and push the attestation count past
   quorum. Found while writing `test_forged_attestations_cannot_reach_quorum`.

4. **Mempools need conflict reservations.** Without them a node holds two
   transactions spending the same note; block building skips the conflict so the
   chain stays safe, but the node gossips something that can never be included.

5. **Range proofs on outputs only.** The sketch implied both sides; induction
   over accepted blocks makes input range rows redundant, which roughly halves
   the hidden dimension.

## Open items

Carried from the design sketch:

- **Adversary bound per row** — the 2/3 quorum is implemented, but nothing pins
  how many faulty seats a single row can hold before it stalls the rows behind
  it.
- **Row capture** — a row entirely controlled by one adversary can block
  everything below it. Skip-edges (`front` from `r−2` as well as `r−1`) would
  fix it; not implemented.
- **Grid resize across epochs** — reseating is implemented; join/leave is not.
- **Proof cost at scale** — measured above; MPC-in-the-head is now implemented
  (`mq/ms6/mpcith.py`) and is the smallest of the three by 3x.
- **Quorum signature scheme** — see caveat 3.

Added by the implementation:

- **Anonymity set** — hiding *which* note is spent needs a membership proof
  inside the MQ statement, which needs an algebraically expressible accumulator;
  the seal tree is hash-based.
- **Fee payout** — needs a minted output the sum row accounts for.
- **Wire format and real transport** — the ceremony is a synchronous
  simulation; a deployment needs timeouts, retries and partial synchrony.
- **Genesis issuance is trusted** — `ChainState.issue` proves nothing about the
  value it puts into circulation.


---

# The tiered path

Parts two of the design, implemented up to the supreme mempool.  What happens
after that — moving a block into network history — is deliberately not here.

```
Phase L   every local grid runs a ceremony concurrently   -> CeremonyBlock
Phase S   the local leaders form super grids              -> SuperBlock
Phase X   the super leaders form the supreme grid         -> NetworkBlock
```

`Grid`, `Envelope`, `Ceremony` and `QuorumCert` are unchanged: each tier supplies
a **Workload** saying what its leader builds and what its seats check, and the
same seating, equivocation detection, quorum and view change run at all three
scales.  Tier count follows the roster — with one super grid the supreme tier
collapses onto it, and a single-grid topology is refused with a pointer to
`chain.ceremony.run_epoch`, which is the one-tier case.

## What each tier commits to

```
CeremonyBlock  = { grid_id, partition, txs, utxo_delta, attendance_roll,
                   register_root, cert }
SuperBlock     = { super_id, [CeremonyBlock...], dropped[], cert }
NetworkBlock   = { height, [SuperBlock...], utxo_root, nf_root,
                   registers_root, cert }
```

A local grid **cannot compute `utxo_root`** — it cannot see what the other grids
spent this epoch.  It commits a *delta*; the supreme tier applies every surviving
delta in canonical order and computes the roots once.  The register root is the
exception: it is local state, so it is finalised at tier 0.

## The grid register

Attendance is state, not opinion.  Every seat recomputes
`apply(previous, roll, faults)` and the leader's claimed `register_root` must
match or the block is refused — the same discipline the ledger roots already
follow.  A block at height *h* carries the roll of *h-1*, because a roll is only
complete once its ceremony has ended.

Promotion at `attend_threshold` (40 by default; the demo uses 3).  The founding
cohort of each grid starts as attesters — it has to, since a grid of pure
apprentices can never reach quorum and so never runs the ceremony that would
promote anyone.  **That bootstrap is a trusted setup.**

Because the counter lives in the *grid's* register, relocating restarts it at
zero, so capturing a particular grid costs 40 ceremonies per node, in the open.

## Apprentices sit in the back rows

`Grid.seat(..., standing=...)` orders attesters before apprentices.  A seat's
`front` is the same column one row up, which is always earlier in the seating
order, so no counting seat ever depends on an apprentice to relay.  Their shadow
attestations still ride back up the same edges into the attendance roll —
`test_apprentices_are_seated_behind_attesters` asserts the property directly.

## Partitioning

A grid may only include transactions whose input nullifiers all fall in its
partition (`nf mod K`).  Cross-grid double spends become structurally impossible
rather than merely detectable.  The merge tiers still check partition compliance
and dedupe, because compliance is a rule a Byzantine leader can break.

A transaction spending notes from two partitions has no home and is refused at
submission — consolidation first is the v1 answer.

## Trust lists are powerless by construction

`TrustList` is subjective and never consulted for quorum.
`test_consensus_never_reads_a_trust_list` replaces every node's list with a
tripwire that raises on read and asserts the epoch still finalises.

## Proof systems per tier

| tier | backend | rounds / reps for 2^-80 | proof at h=48 |
|---|---|---|---|
| local | `mpcith` (N=16) | 20 | 62 KB |
| super | `ssh5` | 80 | 185 KB |
| supreme | `ssh3` | 137 | 295 KB |

This is the designed policy, and it is the running one: `ChainParams.DEMO`
carries all three backends and `proof_policy` maps each tier to its own. A
transaction built for the full policy carries ~542 KB of proof and takes 0.09 s
to build; the local tier verifies its `mpcith` proof in 0.026 s.

**The 3-pass had to be written.** `mq/ms6/core.py` dropped its 3-pass path when
it moved to 5-pass — only the `rounds_for_security` helper survived, computing
the 137 rounds that error 2/3 needs.  `mq/ms6/ssh3.py` implements it on the same
gamma-batched form, so the identity a seat checks on challenge 1 is

    G(t0, r1) + e0  =  t - q(r1) + c - G(t1, r1) - e1

with challenge 0's whole response derivable from the round seed.  Every pair of
the three systems rejects the others' proofs, which is what makes the diversity
real rather than nominal.

**MPC-in-the-head had to be written too.** `mq/mq.md` specifies stages 1-3 of
an MQOM-style proof in a module (`ms6acc_mpcith.py`) that is not in this
repository, so `mq/ms6/mpcith.py` builds it from that spec: gamma-batched
quadratic form, additive sharing over a binary seed tree, sacrifice check, and
three-phase Fiat-Shamir (`h1` -> gamma, `h2` -> epsilon, `h3` -> the hidden
party `i*`). Two deviations from the spec are documented in the module: the
party broadcast computes `<alpha, [w]_i>` as `<A^T alpha, [z]_i>`, which drops
prover cost from `tau*N*h^2` to `tau*(h^2 + N*h)` — 40x less arithmetic at
N=256, h=48 — and there is no correction term for the mask `a`, which is
unconstrained, so every party draws its share from its own seed.

Party count is the size/time dial (h=48, 2^-80):

| N | reps | proof | prove | verify |
|---|---|---|---|---|
| 8 | 27 | 80.3 KB | | |
| **16** | **20** | **63.2 KB** | 0.03 s | 0.03 s |
| 64 | 14 | 44.7 KB | | |
| 256 | 10 | 32.3 KB | 0.22 s | 0.20 s |

N=16 is the shipped default: still 3x smaller than 5-pass while staying the
fastest of the three both ways.

## Costs

40 validators, 8 grids of 5, `attend_threshold=3`: one epoch is 11 ceremonies,
580 directed messages, **0.2 s**.  A transaction carrying both proofs is 499 KB
and builds in 60 ms.  Full suite: 107 tests in ~15 s.

## What is not implemented

- Grid split and merge (predicates exist, restructuring does not).
- Cross-partition transactions.
- Enrolment is a signed object with a double-enrolment detector, but nothing
  yet drives suspensions from it automatically.
- Real transport: the ceremony remains a synchronous simulation with no clock.


---

# Phase H — hardening

Part three, implemented. The ceremony decides what is true; hardening decides it
stays true. A block leaves the supreme mempool agreed but reversible, and enters
history when turns from a finite single-use pool have burned themselves on it.

```python
era     = Era(0, master_seed, tree_height=17, turns=70_000)
history = NetworkHistory(era.spec, PRODUCTION)
result  = run_epoch_to_history(world, history, era, epoch, "seed")
```

## Two eras a day

`era_seconds = 43,200`. The pool is finite, so interval and era length are one
knob:

```
block_interval = era_seconds * width / turns = 43200 * 32 / 70000 = 19.75 s
```

| preset | width | threshold | blocks/era | interval |
|---|---|---|---|---|
| `PRODUCTION` | 32 | 22 | 2,187 | 19.75 s |
| `FAST` | 16 | 11 | 4,375 | 9.87 s |

Building a 2^17 tree of 70,000 turns costs ~131 s of hashing (measured, pure
Python) — precomputed, which a 12-hour era gives ample room for. Leaves past
`turns` are retired constants rather than keys, so the tree costs 70,000 key
generations rather than 131,072.

## A stamp

```
anchor = H(block_hash, cumulative_weight(h-1), era_root)
puzzle = H(anchor, leaf_index, nonce) < target
stamp  = { leaf_index, nonce, auth_path, ots_signature over the puzzle }
```

Verification does membership and signature **in one step**: the public key is
*recovered* from the signature and opened against the era root, so a bad
signature recovers a key that simply is not in the tree. 2,700 B per stamp at
production tree height; 84 KB per block at width 32.

Stamping two blocks means signing two messages with one Winternitz key.
`test_two_signatures_leak_more_of_the_key_than_one` measures the leak rather than
asserting it, and `equivocation_evidence` builds the self-substantiating proof.

## What an attacker actually faces

The design sketch argued a rewrite is bounded by the attacker's share of the
pool. Implementing it showed the **first** line of defence is stronger and
different: the committee is redrawn every block, and an attacker does not choose
it — so it can only stamp the drawn turns it happens to own, and must clear the
2/3 threshold on a fresh unbiased draw **every block**. The requirement compounds
rather than averaging.

| attacker share | P(one block) | P(six consecutive) |
|---|---|---|
| 10% | 2.4e-15 | ~0 |
| 33% | 3.8e-05 | ~0 |
| 50% | 2.5e-02 | 2.5e-10 |
| 67% | 5.0e-01 | 1.6e-02 |
| 80% | 9.6e-01 | 7.8e-01 |

So the practical bar is around 80% of the pool, not the 51% the mining analogy
suggests. The finite-pool ceiling (`max fork depth = owned turns / width`) is the
*second* line — it bounds how deep an attacker could reach if it ever cleared the
first, and every attempt burns the turns it drew.

That cuts the other way for liveness: below 2/3 participation the honest chain
also stalls, and each stalled attempt consumes a committee, so the pool drains
faster. Threshold is a real trade, not a free win.

## Costs

Measured: 320-turn pool builds in 0.29 s; a full epoch — three consensus tiers
plus hardening — runs in 0.2–0.3 s at demo scale. 28 hardening tests in ~4 s.

**Both halves of `mq` carry all three.** `mq/vs6/ssh3.py` and `mq/vs6/mpcith.py`
are generated from the `ms6` originals by `mq/sync_vs6.py`, which drops the
provers and every import `vs6` does not need — the verifier package contains no
prover and imports nothing from `ms6`. `chain/proofs.py` exposes this as
`ProofBackend.verify_independent`, and `chain/tests/test_mq_backends.py` asserts
the copied verifier sources are byte-identical to the originals and that both
verifiers agree on every proof.
