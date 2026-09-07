# Genesis — fin6 design sketch, part five

How a fin6 network starts, and what it has to be trusted about when it does.
Follows `private_chain_design.md`, `tiered_ceremony_design.md`,
`hardening_design.md` and `persistence_design.md`, all implemented in `chain/`.

## 0. Six trusted setups, in four files

Each layer named its own trusted setup honestly and then moved on. Nobody has
put them side by side, and side by side is the only way to see that they are not
equally dangerous and do not last equally long.

| # | what is assumed | where | what a dishonest founder gets |
|---|---|---|---|
| 1 | the issued supply is what was claimed | `ChainState.issue` | invisible inflation, forever |
| 2 | the founding cohort attests honestly | `GridRegister.genesis` | every quorum in every grid, for 40 ceremonies |
| 3 | era 0's keys are distributed | `Era(master_seed)` | every turn, so any rewrite, at any depth |
| 4 | the seating seed was not chosen for effect | `Topology.build` | a grid of its own, which is a block of its own |
| 5 | the parameters are the ones everyone agreed | `ChainParams` | a different chain wearing the same name |
| 6 | time zero and the first difficulty | nowhere | the schedule, and the clock that measures it |

The sixth has no home in the code at all, which is its own kind of answer.

## 1. Name the chain after its genesis

`chain_id` is currently the string `"fin6-private-v1"`. It is threaded through
every signature in the system — proposals, attestations, fault reports, the
binding scalar inside every proof — so it is already doing the work of saying
*which chain this statement is about*. It just is not saying anything checkable.

```
genesis document  ──H──▶  chain_id = "fin6:" + H(document)
                              │
                              ├── every attestation signs it
                              ├── every proposal signs it
                              ├── every proof binds to it
                              └── every store refuses a different one
```

Make the identity a commitment and two things follow for free. Two networks
become structurally unable to confuse each other, including a network and its own
rehearsal. And every signature in the system becomes a statement about one
specific setup rather than about a name someone typed.

The document itself, encoded with `store/codec.py` because that is already
canonical:

| field | why it is in the identity |
|---|---|
| `params_digest` | over the full `ChainParams` and `HardeningParams` — a chain with different range bits is a different chain |
| `roster` | node id, public key, region, for every founder |
| `topology_commitment` | the commit half of §5's commit-reveal |
| `n_partitions` | K, because a transaction's home grid is `nf mod K` |
| `era0` | the `EraSpec` — root, tree height, turns — and the holder map |
| `era0_difficulty` | there is no history to retarget from |
| `supply` | the genesis mint transaction of §2, proof and all |
| `effective_time`, `epoch_seconds` | §6 |
| `ratifications` | founder signatures over everything above |

`GENESIS_PREV` and `GENESIS_NETWORK` stop being the literals `"genesis"` and
`"net:genesis"` and become `"nb:" + H(document)`, so height 1 points at the setup
rather than at a word.

## 2. The supply cannot be checked, and that is a bug

Values are hidden. `issue()` puts commitments into the UTXO set with no proof of
anything, and `txsystem.py` says so plainly: every note is in range because it
"was either issued at genesis (checked by the issuer) or was an output of an
accepted transaction". The induction is sound and its base case is a promise.

So a reader of the genesis document can see how many notes were issued and not
what they are worth. Whether the chain was born holding ten million units or ten
billion is not a checkable fact about it.

**Make genesis a transaction rather than an exception.** The machinery is
already there and already proved three ways. The sum row says

```
sum(inputs) - sum(outputs) = fee            fee is public
```

A mint is a transaction with no inputs, so the row reads `-sum(outputs) = fee`:
a **negative public fee is a declared supply**. The range rows already prove
every output lies in `[0, 2^B)`, so the mint proves exactly what is wanted —
that the declared total is the sum of the hidden values, and that none of them
is a wrapped negative.

The policy is one line: a negative fee is legal only at height 0, and only for
the one transaction the genesis document names. What it buys:

- supply is publicly verifiable from block 0 by the same verifier that checks
  everything else, in the same three proof systems;
- the issuance sits *inside* a block, so `tx_root` covers it, the archive keeps
  it, and a snapshot-synced node inherits a checkable claim rather than a
  convention;
- `ChainState.issue` — the one call in the ledger that mutates state with no
  proof — can go.

The constraint to respect is the field: `sum(outputs)` must not wrap `P`, so the
number of genesis outputs times `2^B` has to stay far below 2^255. At any
plausible supply it is not close.

## 3. The apprenticeship is thirteen minutes long

`GridRegister.genesis` seats the founding cohort as attesters with
`consecutive = attend_threshold`, and the docstring is right that it has to: a
grid of pure apprentices can never reach quorum, so it can never run the ceremony
that would promote anyone. The gate is waived exactly once.

The question is how long that matters, and the answer is a surprise:

```
attend_threshold  = 40 ceremonies
one ceremony      = one epoch = one network block = 19.75 s
                    (70,000 turns, width 32, two eras a day)

40 ceremonies     = 13.2 minutes
```

Two conclusions, pulling in opposite directions.

**The founding window is mercifully short.** Thirteen minutes after the first
ceremony, nodes that were not founders can carry quorum. The trust assumption
does not need to survive the life of the chain, only the first quarter of an
hour.

**And that is because the gate is weak.** Forty ceremonies was described as a
serious apprenticeship. At the designed cadence it costs a new node thirteen
minutes of uptime. Its real cost is *visibility* — forty ceremonies of being
watched by nodes building their own trust lists — not time, and the design should
say so rather than implying a duration is doing the work. If the gate is meant to
be a cost, it has to be denominated in something scarcer than a quarter of an
hour: ceremonies *led* rather than attended, or a threshold that scales with how
fast the grid is growing.

For the founding window itself, three candidate mitigations, none free:

| mitigation | what it costs |
|---|---|
| provisional quorum — founders need 3/4, not 2/3, until the first non-founder is promoted | a stall if founders are also the ones absent |
| founder standing decays — `consecutive` starts at the threshold and falls if unattended | complicates a register rule that is deliberately total and deterministic |
| staggered admission — apprentices seated in waves so promotion is continuous | needs an admission-rate rule the register does not have |

## 4. Era 0 should never have a master seed

`Era(era_id, master_seed, tree_height, turns, holders)` derives all 70,000 WOTS
keys from one seed. `holder_of()` maps a turn index to an operator, and the
hardening sketch is explicit that this distribution *is* the security parameter —
but it is a model of distribution, not custody. Whoever runs that constructor can
sign every turn in the era, which is to say can rewrite history to any depth,
which is the one thing the hardening layer promises is impossible.

The fix is available because the keys are hash-based and independent — there is
nothing to combine, so there is nothing to combine *badly*:

```
each holder:   slice_seed  (private, never leaves)
               leaf_pk[i] = WOTS.public_key(slice_seed, pub_seed, i)
               publishes only the leaf public keys for its indices

everyone:      era_root = Merkle(leaf_pk[0] … leaf_pk[2^17 - 1])
               in canonical index order, retired leaves as constants
```

No party ever holds the whole seed, and the genesis document records both the
root and who holds which indices — so the rewrite ceiling stops being an
assumption about one operator's discipline and becomes a fact about the roster.
Era n+1 still chains from era n's root, published in a block the outgoing era
hardened; each holder simply derives its own next slice.

In code this splits `Era` into two objects that are currently one: a private
`TurnHolder` that owns a slice and can sign, and a public `EraSpec` that owns the
root, the holder map, and nothing secret. `EraSpec` already exists and already
carries no secret; it just needs to stop being derived from something that does.

## 5. Whoever picks the seating seed picks the grids

`Topology.build(node_regions, grid_size, seed)` deals nodes into grids by keyed
hash — "chosen by nobody", as `locality.py` puts it, which is true of the
*dealing* and not of the seed.

Grid capture is precisely the attack locality exists to prevent: a grid is a
block, and a grid you own outright is a block you own outright. So the seed
cannot be a name someone picked, and it cannot simply be `H(document)` either —
the document contains the roster, and an adversary who can add one filler node
can grind the roster until the derived seating suits it.

**Commit-reveal among the founders**, one extra round at setup:

```
setup:     each founder publishes  c_i = H(r_i, node_id_i)   -> in the document
effective: each founder reveals    r_i
seed:      H("topology", sorted (node_id_i, r_i))
```

The last revealer can withhold, not grind — and withholding is visible, so the
answer to it is a stated rule (proceed with the reveals present after a timeout,
recorded in the first block) rather than a cryptographic one. If that is judged
too heavy for a permissioned launch, the honest alternative is to say the seating
is chosen by the founders, and to lean on the fact that grid *membership*
re-decides on split and merge — except that split and merge are not implemented,
so today the founding seating is permanent, which makes this the sharpest of the
six.

## 6. Time zero

The ceremony is scheduled and the code has no clock. Hardening's difficulty
retarget is the clock afterwards — that is one of the two jobs it does — but
before the first hardened block there is no interval to measure and nothing to
retarget from. So the genesis document has to declare what would otherwise be
derived:

- **effective time**, the wall-clock instant the first ceremony opens;
- **epoch cadence**, so that seats know when to expect each other;
- **era 0 difficulty**, since the first block cannot inherit one;
- **the first draw seed**. Turns are drawn from
  `H(prev_hardened_hash, h, era_root)`, and block 1 has no previous hardened
  block — so it uses the genesis digest, which is fixed before any founder knows
  who will hold what.

## 7. What is *not* a trusted setup, and should be said out loud

The proof system. `note_system` is `MQSystem(n_note, fold_degree=2, …,
seed="fin6-note-sys")`: every coefficient is derived by hashing a public string.
There is no common reference string, no toxic waste, no ceremony to run and no
secret anyone must be trusted to have destroyed. For a chain whose whole security
argument is about who has to be trusted with what, that is worth stating in the
place people look for it rather than leaving implicit in a constructor call.

Two caveats, both small. The seed string should be an explicable
nothing-up-my-sleeve constant rather than a name, because "derived by hashing" is
only reassuring if the input is too. And the system is deliberately shared across
every fin6 network — one system for everyone to audit — with cross-network replay
prevented by the binding scalar rather than by giving each chain its own
coefficients.

## 8. Ratifying a genesis

What a joining node checks, in order, before it will apply block 1:

1. the document decodes, and re-encoding it reproduces the bytes it was given
   (`codec.py` is canonical, so this is a real check);
2. `chain_id` equals `"fin6:" + H(document)`;
3. every ratification verifies against a roster key, and the ratifying set meets
   whatever threshold the document itself declares;
4. the parameters match the build — a node that would compute different roots
   should refuse rather than fork quietly;
5. the genesis mint verifies, in the tier's proof system, and its declared supply
   is what the document says;
6. the topology derived from the revealed seed reproduces the grid assignment;
7. `era0.root` is a Merkle tree over the published leaves, and the holder map
   covers every turn exactly once;
8. its own store, if it has one, is empty or already holds this `chain_id`.

And then the thing that no checklist covers: **a node handed two genesis
documents has no way to prefer one except by who signed it.** Distribution is out
of band and always will be. Trust in a fin6 network begins as trust in a file,
and the most a design can do is make the file small enough to read, canonical
enough to compare, and specific enough that signing it means something.

## 9. Genesis is not a moment, it is a decaying assumption

The useful frame, and the one this document exists to add: each of the six is
diluted by something, and they dilute at wildly different rates.

| assumption | what dilutes it | how long |
|---|---|---|
| supply | nothing — but §2 makes it checkable instead | fixed at block 0 |
| founding standing | non-founders reaching attester | **13 minutes** |
| turn custody | era rollover, if holders change | **12 hours**, and never if the slice stays put |
| seating | grid split and merge | never, today — they are not implemented |
| parameters | nothing. They are the chain | never |
| time zero | the first difficulty retarget | one era |

Two of the six never decay, and one of those two — seating — decays only via a
mechanism that does not exist yet. That is the finding: the launch risk of this
design is not concentrated at t=0, it is concentrated in the two assumptions that
t=0 makes permanent.

## 10. What this adds to `chain/`

| module | change |
|---|---|
| `genesis.py` | *new* — the document, `chain_id` derivation, ratification, the joining checklist of §8 |
| `params.py` | `chain_id` becomes a digest; a `params_digest` over both parameter sets |
| `state.py` | `issue()` retires in favour of the genesis mint |
| `transaction.py` | a negative fee is legal for exactly one transaction at height 0 |
| `txsystem.py` | unchanged — the sum row already does this; only the policy around it moves |
| `register.py` | provisional standing for the founding cohort (§3) |
| `hardening/pool.py` | `Era` splits into a private `TurnHolder` and a public `EraSpec`; era 0 built from contributed leaves |
| `hardening/draw.py` | block 1 draws against the genesis digest |
| `locality.py` | topology seed from commit-reveal rather than a caller's string |
| `store/db.py` | store the document; refuse to open a store whose `chain_id` differs |
| `tiers.py` | `bootstrap_world` becomes a genesis loader, and the test fixture becomes a genesis generator |

## 11. Open items

| item | why it is open |
|---|---|
| The gate is thirteen minutes | Measured here for the first time. Either the threshold is denominated in the wrong unit, or the claim that it is a serious apprenticeship should be dropped. Both are changes to part two, not to this document. |
| Founding seating is permanent | Because split and merge are not implemented. Until they are, commit-reveal is not a nicety. |
| Reveal withholding | Commit-reveal turns grinding into withholding, which needs a timeout rule and a way to record who did not reveal. |
| Ratification threshold | The document declares its own threshold, which is circular; something has to say how many founders are enough, and that something is governance, not code. |
| Key custody at the holders | §4 stops one party holding every turn. It says nothing about how a holder keeps its own slice, which is where the high-water mark from part four applies. |
| Genesis for a network that already exists | Adding an operator, retiring one, or changing a parameter is a governance event with no design at all yet. Genesis is the easy end of that problem. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/b74b02fd-3480-46c9-8026-21016c3d0f1b
