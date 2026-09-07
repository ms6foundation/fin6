# Running fin6 locally — design sketch, part six

How to run a real fin6 network on one machine. Follows the five design parts,
all implemented in `chain/`, and is the first of them about *operating* the
thing rather than deciding what it does.

## 0. What exists is not a testnet

Everything in `chain/` runs in one process. `TierWorld` holds every node in a
dict, a ceremony passes Python objects between them by reference, and
`run_tiered_epoch(world, epoch=4)` is a function call with the epoch number
supplied by the caller. That is a *simulation*, and it has earned its keep: it
found the round schedule, the register deadlock, the quadratic append, the
proof-size ratio. But there are whole classes of failure it cannot see, because
it does not have the thing that causes them.

| the simulation has | a network has |
|---|---|
| a function call | a socket that can drop, reorder, duplicate and stall |
| one clock, supplied by the caller | seven clocks, none of them agreeing |
| shared object references | bytes, and a decoder that is a trust boundary |
| a process that either runs or does not | a process that dies between an fsync and a broadcast |
| perfect knowledge of who is seated | a peer that thinks it is in a grid it has been moved out of |

A local testnet exists to make those reachable. Nothing else about it is
interesting, so nothing else about it should be elaborate.

## 1. What the ceremony assumes, and what the wire will do to it

`Ceremony.run` is **round-synchronous**: for `2 × diameter` rounds, every edge of
the grid exchanges a snapshot of both endpoints' envelopes, in both directions,
simultaneously. On a network there is no simultaneous.

The good news is structural, and it is the single most important fact for this
whole part. The envelope is monotone — *"merging two envelopes is a union"* —
and `absorb` checks every statement against the validator registry and its
signature on the way in. So:

- a duplicated message changes nothing;
- a reordered message changes nothing;
- a delayed message costs time, not correctness;
- a lost message is recovered by any later exchange, over any path.

**Union-merge is what makes an asynchronous transport safe here.** What the
rounds actually provide is a *bound on how long convergence takes*, and on a
real network that bound has to become a deadline instead of a step count:

```
in process     for t in 1..2*diameter:  every edge exchanges, lockstep
on the wire    gossip to neighbours until quorum is reached
               or the epoch's ceremony deadline passes
```

`2 × diameter` stops being the schedule and becomes the expected number of
exchanges — the thing you compare against when a testnet run takes eleven.

## 2. The message that must not carry a block

The in-process ceremony passes envelopes by reference, which hides their size.
Measured on the seven-node one-tier run: **132 directed messages per epoch**. An
envelope contains the leader's proposal, and a proposal contains the block, and a
block with one transaction carrying all three proofs is 542 KB.

```
132 messages x 542 KB  =  71.5 MB per epoch, per grid
132 messages x   2 KB  =  264 KB per epoch, per grid
```

So the wire format splits what the object model conflates:

- **envelope gossip** carries proposal *headers*, block *hashes*, attestations
  and fault reports — signatures and digests, a couple of KB;
- **block fetch** is a separate request by hash, answered once per peer that
  needs it;
- **transaction gossip** is its own flood, before the ceremony, not during it.

This is not an optimisation. At 71 MB per epoch per grid a laptop testnet would
be measuring its own loopback rather than the protocol.

Two configuration choices follow, both measured:

| choice | effect |
|---|---|
| `proof_backends=("mpcith",)` on a testnet | a transaction is 63 KB instead of 542 KB — 9x — and still verifies |
| block fetch by hash | the 542 KB moves once per peer, not once per round |

## 3. The node process

```
fin6-node
  ├── identity      one Ed25519 key, from a file the genesis never contains
  ├── genesis       the document (part five); chain_id is its hash
  ├── store         chain.db, turns.hw, archive/era-N.seg   (part four)
  ├── mempool       in memory, on purpose — gossip refills it
  ├── transport     framed TCP to its grid neighbours and its tier above
  ├── clock         epoch = floor((now - effective_time) / epoch_millis)
  └── scheduler     wake at the epoch boundary, seat, gossip, decide, commit
```

Everything except the transport, the clock and the scheduler already exists.
That is the whole build, and it is why this part comes last.

The frame is the codec from part four, which is already canonical and already
round-trips every object the chain has:

```
frame  =  varint length | codec.encode({kind, chain_id, epoch, payload})
kinds  =  tx | envelope | getblock | block | head
```

`chain_id` in every frame is not ceremony: it is the hash of the genesis
document, so a node that has been pointed at the wrong network finds out on the
first frame rather than at the first divergent root.

## 4. The clock

The genesis document already declares `effective_time` and `epoch_millis`, so a
node computes its epoch rather than being told:

```
epoch     = floor((now - effective_time) / epoch_millis)
seat at    epoch_start
deadline   epoch_start + 0.6 * epoch_millis      ceremony must decide
commit by  epoch_start + 0.8 * epoch_millis      one durable write
```

A node that wakes inside an epoch it has already missed does not try to catch
up mid-ceremony; it waits for the next boundary and syncs from peers. The
tiered path already refuses an epoch that does not follow the height, which is
exactly the check that turns a late node into a clear error instead of a
mystery.

Clock skew is a first-class testnet subject, not an accident: the harness
should be able to run a node with a deliberate offset.

## 5. Parameters for a laptop

Production hardening will not start on a laptop, and the reason is worth the
measurement. Building an era's Merkle tree of one-time keys costs **0.89 ms per
leaf** in Python:

| tree height | leaves | build |
|---|---|---|
| 10 | 1,024 | **0.91 s** |
| 12 | 4,096 | 3.65 s |
| **17** | **131,072** | **117 s** |

Production is height 17. Seven nodes each spending two minutes building the same
tree before they can do anything is not a testnet, it is a coffee break — and it
recurs at every era boundary, which is the "precompute before the rollover" note
from part three, now with a number on it.

So a testnet preset, chosen so every mechanism stays observable:

```python
LOCAL = HardeningParams(name="local", turns=1_000, width=8,
                        era_seconds=625, difficulty_bits=16, tree_height=10)
# 125 blocks of 5.00 s; threshold 6 of 8; era tree in 0.91 s
```

| what it buys | measured |
|---|---|
| era tree build | 0.91 s per node |
| a block's stamps | 0.03 s at 12 bits, 0.29 s at 16 |
| an era rollover | every 10 minutes, so it actually happens during a session |
| the rewrite ceiling | 1 of 7 holders = 17 blocks ≈ 1 min; 2 of 7 = 35 blocks ≈ 3 min |

That last row is the point. On the production preset a reorg at the fault bound
is a 3.4-hour experiment; here it is a three-minute one. **The local preset is
what makes the hardening layer's central claim testable at all.**

Chain parameters likewise: `attend_threshold` small enough that promotion and
grid founding happen while someone is watching (2–5 rather than 40), and one
proof backend rather than three.

## 6. Layout and commands

```
testnet/
  genesis.json                 the document; its hash is the chain id
  net.toml                     ports, peers, per-node behaviour, clock offsets
  keys/fin6-n01.key            0600, never in the genesis
  n01/
    chain.db  turns.hw  archive/era-0.seg  node.log
  n02/ …
```

```
fin6 genesis new --nodes 7 --preset local --out testnet/
fin6 net up      testnet/            # start every node
fin6 net status  testnet/            # heights, roots, tiers, mempools
fin6 net kill    testnet/ n03        # and `pause`, `partition`, `skew`
fin6 tx send     testnet/ --from treasury --to bob --amount 100
fin6 net down    testnet/
```

`fin6 genesis new` is `chain/genesis.py` with a roster and a preset;
`fin6 net up` is a supervisor holding seven child processes. Neither needs to be
clever, and the supervisor should be the only clever thing in the tree, because
it is the part that exists to break things.

## 7. Faults are configuration, not code

The simulation already has leader behaviours — honest, equivocating, silent —
passed as a dict into `run_tiered_epoch`. On a testnet the same thing is a field
in `net.toml`, so a node process can be told to misbehave without a special
build:

| behaviour | what it exercises |
|---|---|
| `equivocate` | two proposals to different neighbours; the fault report and the view change |
| `silent` | a leader that never proposes; the timeout path |
| `lazy` | attests without validating; nothing catches it, which is the point (part three's open item) |
| `slow` | replies after the deadline; how much slack `2 x diameter` really has |
| `partition` | a firewall rule between two sets of ports; whether union-merge recovers |
| `skew` | a clock offset; how far apart epochs can drift before seats stop meeting |

And two the simulation cannot do at all: `kill -9` between the fsync and the
broadcast — which is precisely the window part four's high-water mark exists for
— and `kill -9` mid-epoch, which should cost the epoch and nothing else, because
everything below tier 2 is a journal.

## 8. The health check is one line

Every node computes the same roots or the network has already failed:

```
fin6 net status
  node        height  tip           utxo_root      registers_root  tiers  mempool
  fin6-n01    412     nb:9f3c…      4479…31        7a0c…d2         1      3
  fin6-n02    412     nb:9f3c…      4479…31        7a0c…d2         1      3
  …
  agreement:  7/7 at height 412        ok
```

Roots agreeing at a common height is the whole of consensus health, and roots
*disagreeing* is worth more than any log line: it names the epoch where two
nodes stopped computing the same thing. The status command should exit non-zero
on disagreement so a CI job can be a testnet run.

## 9. What to build, in order

| stage | what | why first |
|---|---|---|
| 1 | frames, transport, node loop, `net up` / `status` — no hardening, one tier, seven nodes | this is the whole of what the simulation cannot test |
| 2 | block fetch by hash, transaction gossip | without it stage 1 measures loopback |
| 3 | hardening with `LOCAL` params | makes the rewrite ceiling a three-minute experiment |
| 4 | chaos: kill, pause, partition, skew | the reason the testnet exists |
| 5 | growth: admit nodes, watch a grid get founded, tiers go 1 → 2 → 3 | the part that has never run outside one process |
| 6 | more than one host | changes nothing in the design and everything in the operations |

Stage 1 is a few hundred lines. Stages 2 and 4 are where the findings will be.

## 10. What this adds to `chain/`

| module | change |
|---|---|
| `net/frame.py` | *new* — length-prefixed codec frames, one decoder, treated as a trust boundary |
| `net/peer.py` | *new* — a connection, its send queue, and reconnection |
| `net/gossip.py` | *new* — envelope exchange with neighbours, block fetch by hash, transaction flood |
| `net/clock.py` | *new* — epoch from wall time, deadlines, deliberate skew |
| `node/main.py` | *new* — the process: identity, store, scheduler, signal handling |
| `net/supervisor.py` | *new* — `net up/down/status/kill/pause/partition` |
| `cli.py` | *new* — `fin6 genesis` / `node` / `net` / `tx` |
| `ceremony.py` | rounds become a deadline: gossip until quorum or time, rather than a fixed loop |
| `block.py` | a proposal that can travel as a header plus a block hash |
| `hardening/params.py` | a `LOCAL` preset |
| `params.py` | a testnet preset: one backend, a small attendance gate |

`state.py`, `tiered.py`, `register.py`, `store/` and `mq/` do not move. That is
the useful summary of this document: **the consensus does not change to be
networked; only the parts that were pretending to be a network do.**

## 11. Open items

| item | why it is open |
|---|---|
| The round loop is a contract | `2 x diameter` is currently the number of exchanges *and* the guarantee. Splitting them into "gossip until quorum, deadline at T" is a change to `ceremony.py` that the simulation cannot motivate and the testnet will. |
| No transport authentication | Content is signed, connections are not. A peer can flood, and nothing rate-limits it. Fine on loopback, not fine on stage 6. |
| No peer discovery | Peers come from the genesis roster and `net.toml`. A network that grows needs joiners to find seats, which is the operational half of the founding rule. |
| View change over a real network | In process it is a retry loop with a fresh seed. With timeouts and partial delivery it is a protocol, and it is not designed. |
| The lazy stamper, again | `lazy` is in the fault table because the testnet can *run* it, not because anything catches it. Still part three's open item. |
| Hardened history is not wired | The store has the tables; `NetworkHistory` still keeps branches in memory. A testnet that restarts a node forgets its accumulated weight. |
| What a green run means | "Seven nodes agreed for an hour" is not a test suite. The chaos stages need assertions — a partition heals within N epochs, a killed node rejoins at the right height — or the testnet is a demo. |

## Rendered version

Diagrammed: https://claude.ai/code/artifact/26dc9b01-98b2-4500-ad3a-5d727e3d0900
