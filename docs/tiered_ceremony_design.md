# Many ceremonies, one network — fin6 design sketch, part two

Follows `private_chain_design.md` (transaction-based ledger, single grid ceremony),
now implemented in `chain/`.

## 0. What changes

The ceremony mechanism does not change. What is new is a tree of grids, a
register that records who showed up, and three proof systems standing behind
each other:

- **Assignment** — which local grid a node belongs to, given it should be nearby
  and must be exactly one.
- **The register** — each grid keeps an objective record of attendance, which is
  what the 40-ceremony gate counts against.
- **Trusted lists** — separately, each node builds its own list from what it
  watched. The two are deliberately not the same thing.
- **Aggregation** — leaders promote to a super grid, super leaders to the supreme
  grid, blocks climb from a local mempool to the network mempool, and each tier
  verifies with a different proof system.

## 1. The epoch: three phases, one ladder of certificates

```
Phase L   local grids run concurrently      MPC-in-the-head  -> CeremonyBlock -> local mempool
Phase S   super grids of local leaders      5-pass SSH       -> SuperBlock    -> super mempool
Phase X   supreme grid of super leaders     3-pass SSH       -> NetworkBlock  -> network mempool
```

Phases run in sequence, because each tier's membership is only known once the
tier below has finished — a super grid is made of local *leaders*.

Each tier signs a quorum certificate over what it agreed and carries the
certificates below it, so a network block contains a **ladder** that lets anyone
walk a transaction to finality without trusting any single tier.

**Naming, precisely.** "Committed to the local mempool" means *this grid agreed
on this bundle* — not that it is final. Only the supreme grid puts anything in
the network mempool.

## 2. Joining a grid

A grid is a persistent entity with a name and a memory, not a per-epoch
grouping. This follows directly from counting attendance in a *grid* register:
the grid must outlive the ceremony. A node enrols in one grid and stays; the grid
runs one ceremony per epoch; the register accumulates. Seating *within* the grid
still reshuffles from the epoch seed each ceremony, so leadership and seat
position stay unpredictable — but membership is sticky.

At enrolment, locality proposes and the seed disposes:

1. **Candidate set** — grids within the node's locality (a region tag, or the `k`
   nearest by measured RTT).
2. **Grid** — `H(epoch_seed, node_id) mod |candidates|`.

Locality keeps ceremonies fast; the seed removes the choice, because free choice
of grid is a self-selection attack.

### The apprenticeship does more than vet

Because the counter lives in the grid's register and a node that relocates starts
a new record at zero, **moving grids costs 40 ceremonies**. An adversary that
wants to capture a particular grid cannot simply redirect nodes into it — it must
commit them for 40 epochs, in the open, seated in the back rows, while every
member watches. The 40-ceremony gate stops being a vetting delay and becomes the
thing that makes grid capture slow and visible. This follows from putting the
counter in the grid rather than in the node.

**Exactly one grid.** Signed enrolments `(epoch, node_id, grid_id)` are carried in
each ceremony's certificate. Two enrolments in one epoch is a provable fault with
the same shape as leader equivocation, surfacing at the merge tier where two
sibling rolls name the same node.

**Voluntary vs involuntary moves.** A grid past `2g` splits; one below `g/2`
merges. Nodes carried by a split or merge keep their counters; a node that asks
to re-home starts at zero. Reset punishes choice, not circumstance.

## 3. The grid register

The objective record — not any node's opinion, but a state root every seat
recomputes and the leader cannot fake.

```
GridRegister
  grid_id, epoch
  members: { node_id -> MemberRecord }
  MemberRecord = { joined_epoch, standing, consecutive, total_attended,
                   last_seen_epoch, faults[], led_count }
  root = seal_root("register", canonical serialisation)
```

Updated once per ceremony by a deterministic function of (previous register,
attendance roll, fault evidence) — exactly how `utxo_root` is updated today, with
the same seal-tree machinery. Every seat computes it; the leader's claimed
`register_root` must match or the block is invalid.

The root climbs with the block:

```
register_root -> CeremonyBlock -> SuperBlock -> NetworkBlock
```

So standing is **grid-local in how it is earned and global in how it is checked** —
verifiable from the network block by other grids and by light clients that never
watched the grid.

Update rule:

- Seated and present in the roll with a valid shadow attestation →
  `consecutive += 1`, `total_attended += 1`
- Enrolled but absent → `consecutive = 0` (or one unit of a forgiveness budget)
- `consecutive >= 40` → standing becomes **attester**
- Provable fault → **suspended**, `consecutive = 0`, evidence appended
- Voluntary re-home → record closed here, opens at zero in the new grid

## 4. Standing, and where apprentices sit

| state | seat | attestation counts | reached by |
|---|---|---|---|
| Observer | none | no | synced, not enrolled |
| Apprentice | back rows | no (shadow only) | enrolled |
| Attester | front rows | yes | 40 consecutive in this grid's register |
| Leader-eligible | any, incl. (0,0) | yes | attester, clean record over M epochs |

### Apprentices sit in the back rows

The grid already flows proposals down and attestations up, so attesters take the
front rows and apprentices the rows behind. An apprentice's `front` is always an
attester that already holds the proposal, so **no counting seat depends on an
apprentice to relay** — a withholding apprentice can only starve other
apprentices. Their shadow attestations still ride back up the same edges, which
is what puts them in the attendance roll and moves their counter.

**Consecutive vs sliding window.** Strict consecutiveness means one dropped packet
in ceremony 39 costs a node all of it. `40 of the last 45` keeps the intent.
Either way it lives in the register's update rule, so every grid applies it
identically.

## 5. Two ledgers of trust, doing different jobs

| | the grid register | the node's own list |
|---|---|---|
| scope | shared, rooted, identical everywhere | private, unrooted, different per node |
| contents | attendance, standing, provable faults | who was present, fast, reliable, familiar |
| evidence | portable and self-checking | cannot be proven to a third party |
| decides | **whose vote counts** | **preferences, never quorum** |

Provable faults: equivocation, an invalid block, a double enrolment, an
attestation contradicting a certificate the node itself signed.

What the private list is for, once the register handles standing: which peers to
keep and relay to first; which nearby grid to request when enrolling or
re-homing; how to rank leader candidates; whether to spend effort auditing a
particular node. All real, all local, none able to fork the chain.

Where a node's subjective view should influence a shared outcome, it does so by
being **aggregated into the register** — preference hints collected in the
ceremony, leader ordering a deterministic function of the aggregate — never as a
local override. Subjectivity is an input to an objective function, not a private
veto.

**Why the split is the right call.** If each node's trusted list determined its
quorum, this would become Federated Byzantine Agreement (Stellar's model), where
safety depends on a *quorum intersection* condition across every honest node's
slices, and drifting lists split the network into disjoint quorums that each
believe they are final with nothing detecting it from inside. Counting attendance
in the grid register removes that failure mode while keeping the "trust built over
time" intent intact.

## 6. A different proof system at each tier

All three prove the same kind of statement — knowledge of a witness `z` with
`F(embed(known, z)) = v` over a transaction's `TxSystem` — under the same MQ
hardness assumption. What differs is the machinery, and therefore the
implementation surface where a soundness bug could hide.

| tier | protocol | rounds/reps | why here | DEMO h=48 | STRONG h=208 |
|---|---|---|---|---|---|
| local | MPC-in-the-head | τ=10, N=256 | smallest proof, verifies every transaction | ~48 KB* | ~200 KB* |
| super | 5-pass SSH | 80 | middle ground | 192 KB | 0.75 MB |
| supreme | 3-pass SSH | 137 | simplest analysis, fewest verifications, irreversible output | 316 KB | ~1.3 MB* |

\* estimated from `mq.md`'s per-repetition formula and our measured per-round
size; 5-pass figures measured on the current implementation. Round counts follow
`mq.md`: 2^-80 needs 137 rounds at error 2/3 for 3-pass, 80 at error ~1/2 for
5-pass.

### The ordering is deliberate in two directions

**Size against volume.** Proof size runs MPCitH << 5-pass < 3-pass; verification
volume runs local > super > supreme. Smallest proof where the most verifying
happens keeps total bytes bounded.

**Simplicity against consequence.** 3-pass has the fewest moving parts and the
least subtle Fiat-Shamir analysis — `mq.md` has to argue specifically that the
Kales-Zaverucha grinding attack on Fiat-Shamir'd 5-pass schemes gains nothing here
because α lives in a 255-bit field, and MPCitH brings seed trees, party simulation
and a three-phase transcript, by far the most code to get wrong. The supreme
grid's output is network-final and irreversible, so it gets the protocol with the
fewest sharp edges; the local tier's mistakes still have two tiers above them.

### The real prize: protocol diversity

A transaction reaching network finality has been accepted by three *independent*
proof systems. A soundness bug in any one — historically where these
constructions fail, not in the hardness assumption — is caught by the other two.

The precision that matters: diversity protects against *proof-system* failure,
not against MQ failure. All three rest on the same hardness assumption, so a break
there breaks every tier at once. Diversity buys implementation robustness, not
cryptographic redundancy.

### Making it affordable: prove once per system, audit by sample

Only the spender holds the witness, so only the spender can prove — a higher tier
can re-verify but never re-prove. So the spender produces the statement in each
system it will meet, and tiers verify at different densities:

- **Local** — every seat verifies the MPCitH proof of every transaction.
- **Super** — every super seat verifies child certificates plus the 5-pass proof
  of a *seeded sample* of each grid's transactions.
- **Supreme** — the same with 3-pass, at a smaller sample.

The sample is drawn from the epoch seed, so nobody knows in advance which
transactions face the second and third verifier. Heavier proofs can be fetched on
demand from the originating grid rather than carried by every block.

### Scope — updated after implementation

`chain/proofs.py` now ships **two** of the three. The 5-pass wraps
`mq/ms6`'s existing `prove_hidden`/`verify_hidden`; the **3-pass was written**
against the same gamma-batched form (`mq/ms6` had dropped its 3-pass path when it
moved to 5-pass, leaving only the `rounds_for_security` helper). Measured at
2^-80: 5-pass 192 KB in 80 rounds, 3-pass 316 KB in 137. The two reject each
other's proofs, so the diversity is real.

**MPCitH was not implemented.** The module `mq.md` refers to is not in this
repository and its stage 3 was never written; hand-rolling an MPC-in-the-head
prover with no reference to validate against would be worse than shipping
nothing. It is registered as a backend that raises, and `ChainParams.DESIGNED`
still names it at the local tier so the intent stays visible in configuration.

## 7. Concurrency: the problem that actually bites

Two grids run at once and cannot see each other; both can include a transaction
spending the same note.

**Recommendation: partition the nullifier space, and keep the late check anyway.**
A grid may only include transactions whose input nullifiers all fall in its
partition: `nf mod K == grid_index`. The nullifier is already a deterministic
field element computed inside the proof, so the partition is free and conflicts
become structurally impossible rather than merely detectable.

Partition compliance is a rule a Byzantine leader can break, so merge tiers must
verify each ceremony block stayed inside its partition *and* dedupe nullifiers
across siblings. The partition is the design; the merge check is the enforcement.

Costs: a transaction spending notes from two partitions has no home (require
consolidation in v1; two-phase cross-partition later), and `K` changes when grids
split or merge, so announce it one epoch ahead.

## 8. What each tier can actually commit to

```
CeremonyBlock  = { grid_id, partition, txs, utxo_delta, attendance_roll,
                   register_root, cert(MPCitH-verified) }
SuperBlock     = { super_id, [CeremonyBlock...], dropped[], register_roots[],
                   cert(5-pass sample) }
NetworkBlock   = { height, [SuperBlock...], roster_delta, utxo_root, nf_root,
                   registers_root, cert(3-pass sample) }
```

A local grid **cannot compute `utxo_root`** — it does not know what other grids
spent this epoch. It can only commit to: these transactions verified, each input
was unspent as of the last network block, every nullifier lay in my partition.
That is a *delta*, not a root.

Worth noticing the asymmetry: **the register root is local state and can be
finalised at tier 0; the ledger roots are global state and cannot.** Global roots
are computed once at the supreme tier by applying every surviving delta in
canonical order. So the state machine splits — per-grid delta validation vs.
tier-2 global application. In the current code `ChainState.check_block` does both
at once and would need separating.

## 9. Sizing: three tiers wants about g^3 nodes

| nodes | g | grids | super grids | supreme seats | verdict |
|---|---|---|---|---|---|
| 125 | 5 | 25 | 5 | 5 | balanced |
| 1000 | 10 | 100 | 10 | 10 | balanced |
| 8000 | 20 | 400 | 20 | 20 | balanced |
| 60 | 10 | 6 | 1 | 1 | degenerate — collapse a tier |

Operational rule: **three tiers above `g^2` nodes, two between `g` and `g^2`, one
below.** Tier count should follow roster size automatically.

Interaction with the apprenticeship: a grid needs enough *attesters* to make
quorum, and apprentices do not count. A grid of `g` seats where half are serving
their 40 ceremonies has an effective quorum base of `g/2`, so `g` should be sized
against expected attester density, not headcount.

### Latency

| seats | C | rows | diameter | rounds/tier | 3 tiers | at 50 ms RTT |
|---|---|---|---|---|---|---|
| 10 | 5 | 2 | 3 | 6 | 18 | 0.9 s |
| 20 | 5 | 4 | 5 | 10 | 30 | 1.5 s |
| 30 | 10 | 3 | 5 | 10 | 30 | 1.5 s |
| 50 | 10 | 5 | 7 | 14 | 42 | 2.1 s |

Wider rows beat taller grids. Throughput moves the other way and scales with the
number of grids, since they all run at once.

## 10. What this changes in `chain/`

`Grid`, `Envelope`, `Ceremony` and `QuorumCert` are already parameterised over a
node set and a quorum, so they run at all three tiers unchanged.

| module | change |
|---|---|
| `register.py` | *new* — `GridRegister`, `MemberRecord`, deterministic update rule, rooted serialisation |
| `trustlist.py` | *new* — each node's private, unrooted view; explicitly forbidden from touching quorum |
| `locality.py` | *new* — locality tags, candidate grids, seeded enrolment, split/merge rules |
| `tiers.py` | *new* — epoch scheduler; phases L, S, X; assembles super and network blocks |
| `proofs/` | *new* — backend interface over `prove`/`verify`; existing 5-pass wired in, 3-pass and MPCitH to be written |
| `ceremony.py` | `Grid.seat` takes standing from the register; shadow attestations collected separately from quorum |
| `block.py` | three block types; attendance roll and `register_root` in the certificate |
| `state.py` | split: per-grid delta validation vs. tier-2 global application |
| `transaction.py` | carry a proof per system; verifier selected by tier |
| `node.py` | three mempools, grid membership, register replica, private trust list |

## 11. Open items

The five from part one still stand. These are what the tiers, the register and
the three protocols add:

| item | why it is open |
|---|---|
| Two of three provers do not exist | Only gamma-batched 5-pass ships. 3-pass needs writing; MPCitH needs writing including the stage 3 `mq.md` designs but never built, and the module it refers to is not in this repository. |
| Three proof systems, three audit surfaces | Diversity protects against a bug in one system and multiplies the code that could contain one. Worth it only if all three are actually reviewed. |
| Sample rates at the upper tiers | How much of a grid's work super and supreme re-verify decides both cost and catch probability. Unset. |
| Register handling on split and merge | Counters survive involuntary restructuring by design, but which register a split's records land in, and how two merged registers reconcile, needs a concrete rule. |
| Apprentice density per grid | Apprentices hold seats but cannot make quorum, so a grid admitting too many at once stalls. Needs an admission rate limit tied to attester count. |
| Cross-partition transactions | A spend touching two partitions has no grid that may include it. |
| Aggregate signatures become mandatory | The ladder now carries attendance rolls as well as attestations. At 1000 nodes that is tens of KB of Ed25519 per epoch before any payload. |
| The supreme grid is a global stall point | If it aborts, nothing finalises anywhere that epoch. |
| Apprenticeship is a rate limiter, not Sybil resistance | 40 ceremonies costs time, not identities. Fine while permissioned, fatal if opened. |
| Locality tags are self-declared | A node claiming to be everywhere-adjacent widens its candidate set. |
| Epoch clock | Three phase-locked tiers need a shared notion of when a phase ends; today's ceremony is a synchronous simulation with no timeouts. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/a818d8b4-4f3b-43a7-baa6-4a25b350fd99
