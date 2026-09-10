# Admission — fin6 design sketch, part nine

*Stages 1, 2 and 3 are built — see §10 for what changed on contact.*

How a node decides to spend work on a stranger. Follows `testnet_design.md`
(part six), whose open items included "no transport authentication", and
`light_client_design.md` (part eight), which built the first version of this in
`chain/net/limits.py` and left the number it was calibrated against sitting on
its own.

Everything here is node-local: what one node can do alone, with the genesis
document it already has and no new consensus rule. Charging for the work is a
chain-level design and it is not this one.

## 0. The failure this is defending against

Not a crash. A node that runs out of memory or falls over is the *good* case,
because a validator that is plainly dead is one the ceremony routes around: the
grid tolerates two Byzantine faults out of seven and a dead seat is the
cheapest kind of fault there is.

The real failure is a node that is **alive, honest, and late**. The clock comes
from the genesis document, so an epoch is 19,749 ms and every seat's deadlines
are carved out of it:

```
epoch start        0 ms
decide by     11,849 ms   (0.60)   validate the proposal, attest
commit by     15,799 ms   (0.80)   quorum, or a view change
```

A seat that spends its decide window verifying submitted proofs does not attest.
Enough seats late and the leader's block misses quorum, the epoch produces no
block, and the network takes a view change it did not need. The attacker never
touched consensus; it bought the CPU that consensus needed.

And the coupling is already in the code. `NodeProcess._handle` dispatches `tx`
before the epoch guard, so a submission from anybody reaches `Node.submit` on
the same single-threaded `_drain` loop that `_serve_until` runs to meet the
decide deadline. A stranger's 25 ms of proof verification runs on the thread
that has to attest.

**So the design has one governing rule: work for the chain is not preemptible,
and work for a stranger always is.** Everything below is machinery for telling
those two apart, and for making the second kind shed cleanly when there is not
enough of the first.

## 1. What part eight built

The structure is right and this sketch keeps all of it.

| piece | what it does |
|---|---|
| `Node.admissible` | every refusal that does not need the proof — wrong chain, negative fee, shape outside `MAX_INPUTS`/`MAX_OUTPUTS`, note not in the UTXO set, nullifier already published, conflict with a mempool reservation |
| `net/frame.py` | one decoder, length-prefixed, declared size refused before it is read, chain id checked on the first frame, and any malformed frame is a disconnect |
| `net/limits.py` | a token bucket per source: capacity for a burst, a rate for the long run, a cost per request kind |
| two keyspaces | a peer is metered under the name it claims, a client under the address it came from, so a validator's promotion does not hand its budget to everything else behind that address |
| `Limiter._sweep` | idle sources forgotten, oldest evicted at `max_sources` |

Three assumptions came with it, and none of them hold.

1. **That a claimed identity is an identity.** `hello` carries a `node_id` and
   nothing checks it. The module's own docstring says so — "it said it was a
   peer is not authentication" — and then meters on it anyway.
2. **That a token is a fixed amount of work.** `COSTS` prices a message by its
   kind. A kind is not a size and it is not a cost.
3. **That the meter runs before the work.** It does not. `Reader.feed` decodes
   the frame, and only then does `_read_loop` call `_afford` on the result.

## 2. The cost ladder, measured

Measured today on the development machine, `LOCAL` params, one input and two
outputs:

| rung | what it establishes | cost |
|---|---|---|
| set lookup | `admissible`: this transaction could be included at all | 2.1 µs |
| authentication | `verify_transaction` steps 1–4: the body binds, the note rows reproduce the declared commitments, values conserve, each nullifier is derived from the note being spent, each spending key matches the note's owner slot, and every spend signature verifies | **0.12 ms** |
| the proof | step 5: the MQ zero-knowledge proof | **25.4 ms** |

Per backend, same transaction:

| backend | verify | proof |
|---|---|---|
| `mpcith` | 25.4 ms | 60 KB |
| `ssh5` | 15.1 ms | 203 KB |
| `ssh3` | 23.2 ms | 304 KB |

One Ed25519 signature is 74 µs. Frame decode is 45 ms per megabyte, so a frame
at the 8 MB ceiling costs 357 ms to decode.

The ladder's middle rung is the useful discovery, and it is already built.
`verify_transaction` puts authentication at steps 1–4 and the proof at step 5,
in that order, deliberately. **Two hundred and twelve times the cost sits
between them, and no caller can act in the gap** — `Node.submit` calls the
whole function as one unit, so the node cannot learn who is asking before it has
already paid for the answer.

Splitting that function is the single highest-leverage change in this sketch.

## 3. The meter is in the wrong units

`COSTS["tx"]` is 50 tokens. Take the configured budgets at face value and ask
what they authorise in CPU:

| source | authorised | submissions | CPU-seconds per wall second |
|---|---|---|---|
| one seated peer | 2,000 tok/s | 40 tx/s | **1.02** |
| six peers (a 7-node roster) | 12,000 tok/s | 240 tx/s | **6.10** |
| one client address | 20 tok/s | 0.4 tx/s | 0.010 |
| `max_sources` client buckets | 81,920 tok/s | 1,638 tx/s | **41.6** |

A single seated peer is authorised to consume the whole machine. The full
roster is authorised to consume six of them. Against the decide window, one
peer at its permitted rate spends 12.0 CPU-seconds inside the 11.85 s the node
has to attest — the budget alone, honoured exactly, is a liveness failure.

The frame path is worse, because there the cost is paid before the meter is
consulted at all. `env` is not in `COSTS`, so it falls to `DEFAULT_COST` of 5:

| source | frames/s | decode at 8 MB | CPU-seconds per wall second |
|---|---|---|---|
| one client address | 4 | 357 ms | **1.43** |
| one seated peer | 400 | 357 ms | **142.8** |

One anonymous address, staying inside the client budget the whole time, consumes
more than a core. The burst is worse still: 240 tokens buys 48 frames at once,
which is 17 CPU-seconds before the bucket has refilled once.

The conclusion is not "raise the costs". A bucket denominated in tokens cannot
know what a token costs, and any fixed table will be wrong the next time a
backend changes. The node needs a budget denominated in the thing that is
actually scarce: **CPU-milliseconds of slack in the current epoch.**

## 4. Authentication

### 4.1 A peer, and what `hello` should be

Today `who = payload.get("node_id")` and `seated = who in self.peers`. Two
consequences, and the second is worse than the first.

**Escalation.** Claim any roster name and the budget goes from 20 tokens a
second to 2,000 — a hundredfold, for one unsigned string.

**Squatting.** The bucket key is `("peer", who)`, and `who` is the claim. A
stranger claiming `v3` spends out of `v3`'s bucket. The real `v3` then finds
its gossip refused, goes quiet, and misses its attestations. The limiter
becomes the weapon: an attacker throttles a validator out of the ceremony by
impersonating it at the meter, without ever forging anything the consensus layer
would check.

The fix needs no new key material. The genesis document already carries
`{node_id: public_hex}` for the whole roster, every node has it, and the
chain id *is* its hash — so a node can authenticate a peer against the same
document that defines the network:

```
dialer  → hello    {node_id, nonce_d}
listener→ challenge {node_id, nonce_l}
dialer  → proof    {sig over ("f6-hello", chain_id, dialer, listener,
                              nonce_d, nonce_l)}
listener→ proof    {sig over the same tuple with the roles swapped}
```

Both nonces, both directions, both names, and the chain id: replaying a
handshake to a different node, in the other direction, or on another network all
fail. Two signatures, 148 µs, once per connection.

Three rules around it:

- Until the handshake completes the connection is a **stranger**, on a budget
  below a client's, and `hello` itself is metered — it is currently the one kind
  that reaches `continue` before `_afford` is ever called, which makes the
  handshake free to replay.
- A peer is metered under its **authenticated** name. Nothing else can reach
  that bucket, so squatting stops being possible rather than becoming expensive.
- A failed handshake is a disconnect, and disconnects from an address are
  remembered — see §5, gate 0.

Worth recording what is already right: `Envelope.add_attestation` and
`Seat._take_header` both check the roster and the epoch by dictionary lookup
*before* verifying a signature, so a stranger's forged consensus statement is
refused for microseconds. The consensus layer authenticates its content
correctly. It is the transport underneath that does not.

### 4.2 A transaction, and what already authenticates it

There is no sender to authenticate. A submission is not signed by whoever
submits it, and it should not be — a wallet may relay through anyone.

But step 4 of `verify_transaction` proves something better, for 0.12 ms: that
whoever built this transaction holds spend authority over specific notes, each
of which `admissible` has just confirmed is **unspent and in the UTXO set**.
That is an identity backed by a scarce resource. Addresses are free; notes are
not.

So the transaction meter keys on the authenticated owner. The relevant fact
about a submission is not where it came from but which unspent note it is
willing to put behind it.

### 4.3 The attack this closes

Steps 1–4 never touch the proof bytes. That is the whole vulnerability:

1. Take any valid transaction — one of your own, or one off the wire, since
   gossip carries whole transaction bodies with their proofs.
2. Mutate a byte of the proof.
3. Submit. Steps 1–4 pass in 0.12 ms. Step 5 fails after 25.4 ms.
4. `Node.submit` increments `refused` and `bad_proofs` and records *nothing*.
   There is no negative cache.
5. Mutate a different byte. Repeat forever.

The mempool's `txid` guard never engages, because the transaction is never
admitted. The verification cache never engages, because `_verified` is only
written on success. And no per-address budget touches this: one 60 KB frame,
costing the attacker a byte flip, buys 25.4 ms of the node's only core — so an
attacker can stay inside the client bucket the whole time and still cost the
node more than it has.

Two changes close it, and they have to go together.

**A negative cache keyed on the fingerprint.** `tx_fingerprint` already exists
and already keys on txid, proof bytes and `v` — exactly right here, and the
reason it must not be keyed on txid alone: the same body can legitimately be
re-proved, and a txid-keyed negative cache would reject the honest retry along
with the mutations. Bounded, and cleared when the mempool is.

**Failure charged to the owner.** A cache only helps against repeats; the
attacker's whole method is to never repeat. So the cost has to land on the
scarce thing the transaction named. A note whose owner produces a bad proof
buys that owner a throttle for the rest of the epoch — and because the owner
slot is cryptographically bound to a note that is provably unspent, the price of
sustaining the attack is one real note per throttled identity. That is a price
the UTXO set sets, not the address space.

This is the substantive difference between this sketch and part eight: part
eight metered *sources*, and the source is free. Metering the authenticated
owner is the first thing in this system that costs an attacker something it
cannot mint.

## 5. The design: four gates

Each gate refuses what the next one would have to pay for.

| gate | keyed on | refuses | budget |
|---|---|---|---|
| 0 connection | address | too many sockets, idle sockets, recent offenders | slots |
| 1 frame | connection | oversized, undecodable, wrong chain | bytes |
| 2 statement | authenticated peer / owner / address | more than this identity may ask | tokens |
| 3 work | the node | more than this epoch can afford | CPU-ms |

### Gate 0 — connection admission

`_accept_loop` spawns a thread per accepted connection and appends it to a list
that is never pruned. There is no cap on connections, none per address, and
`_threads` grows for the life of the process. The limiter meters messages; it
has never seen a connection.

- A bounded accept: a fixed worker pool, not a thread per socket. A refused
  connection is closed immediately, which costs a syscall instead of a stack.
- A per-address connection cap, so one address cannot hold a thousand sockets
  each with its own 8 MB read buffer.
- An **idle deadline**. `SOCKET_TIMEOUT` is 1.0 s and the read loop treats a
  timeout as `continue`, forever: a connection that sends a length prefix
  announcing 8 MB and then nothing holds a worker and a buffer indefinitely.
  A partial frame needs its own deadline, separate from the socket's.
- A **penalty box**. A `FrameError` closes the connection and the attacker
  reconnects for free. An address that has just been disconnected for a bad
  frame waits, with the wait growing.

### Gate 1 — frames priced in bytes

Move the meter in front of the decode. The length prefix is known before the
body is read, so the bytes can be charged before they are parsed, and a source
that cannot afford them has its connection closed rather than its message
refused. Then two rules:

- Cost is `base(kind) + bytes × rate`. A kind is not a size.
- `MAX_FRAME` is 8 MB because a block body needs it. Nothing a *client* sends
  needs it, and neither does a `hello`, a `tx`, or an `env`. A per-kind ceiling
  — a few hundred KB for a submission, a few KB for a handshake — removes the
  357 ms decode from every path that has no use for it.

### Gate 2 — statements priced per identity

Three keyspaces, not two:

| identity | established by | metered as |
|---|---|---|
| peer | the §4.1 handshake against the genesis roster | generous; a validator that cannot gossip cannot vote |
| owner | steps 1–4 of `verify_transaction` | per authenticated owner, with failures charged heavily (§4.3) |
| address | nothing | tightest; the default, and the one that must never be able to reach a core |

Two repairs inside the limiter itself while it is being touched:

- `_sweep` runs on every *new* source, scanning every bucket and sorting them
  when crowded — under the one lock that also serialises every peer's gossip.
  One frame from one new address is O(n log n) for the node. Sweep on a timer,
  not on arrival.
- `_last_refusal` is a single field shared by every reader thread, so a refused
  client can be told another client's reason. Return the reason, don't store it.
- The `refused` reply is itself free to ask for and costs the node a send. Cap
  the refusals sent per source per second; silence is a valid answer.

### Gate 3 — the work budget

The gate that actually stops this, and the one that does not exist yet.

One scheduler for every expensive operation — today that means proof
verification and nothing else. It holds a bounded queue and a budget
denominated in CPU-milliseconds of *this epoch's slack*: the time between now
and the decide deadline, minus a reserve for validating the proposal that is
going to arrive.

```
priority 0   validating the leader's proposal        never shed
priority 1   gossip from an authenticated peer       shed last
priority 2   submissions from an authenticated owner shed on pressure
priority 3   anything from an address                shed first
```

Shedding drops the tail of the queue and answers `refused` with a retry hint —
a reply shape the wallet and the CLI already understand. Three properties fall
out of it:

- The decide deadline is met by construction, because the budget is derived
  from it rather than hoped for.
- Priority 0 work never queues behind priority 3 work, which is the coupling in
  `_handle` today.
- The budget is measured, not configured: it re-derives itself from what
  verification actually cost last epoch, so a backend change does not silently
  invalidate a table of token prices.

### And two bounds that are simply missing

**The mempool.** `Node.mempool` is an unbounded dict of transactions carrying
60 KB of proof each, gossip-amplified across the roster, and a node holds them
because they are *valid* — the expensive kind. Cap it, and evict the lowest fee
first. `tx.fee` is public in the body, so this needs no fee market and no
consensus change; it is a local eviction order, and when the pool is full
admission requires beating the floor.

**`Seat.pending`.** Headers that verify are stored under an attacker-chosen
digest and every one of them is then fetched by hash. Only the seated leader
can produce a header that verifies, so this is equivocation and it is
punishable — but it is unbounded until it is punished, and it should be capped.

## 6. What this does not do

- **It does not solve Sybil.** Addresses are free, so gate 2's address
  keyspace is a floor under the cost of flooding, not a fence around it. What
  changes is that the two keyspaces that matter — the roster and the UTXO set —
  are now *scarce and authenticated*, so the cheap keyspace is the one with the
  tightest budget rather than the one with the largest reach.
- **It does not charge for the work.** A fee still cannot be collected before
  the proof is checked, which is the wrong way round, and metering by identity
  is the local answer to a problem whose real answer is a fee market. Part ten.
- **It does not stop a seated validator flooding.** An authenticated peer that
  misbehaves is metered and can be de-prioritised, but making that *cost* the
  validator something requires a deposit and a slashing rule, which is a
  consensus change.
- **It does not stop bandwidth exhaustion.** Everything here happens after the
  packets arrive. A link filled upstream of the node is not a node-local
  problem.
- **It does not help a node that has fallen behind.** Catch-up is still the
  largest missing piece from part six, and a node shedding load is a node more
  likely to need it.

## 7. What this adds to `chain/`

| module | change |
|---|---|
| `transaction.py` | **built.** `authenticate(tx)` is steps 1–4 and returns an `Authenticated` carrying `(ts, v, beta)`; `verify_proof(tx, auth, backend)` is step 5 and reuses it. `verify_transaction` is now their composition, unchanged in behaviour and order of refusal |
| `node.py` | **built.** `Node.authenticate` / `Node.verify_and_admit` are the two rungs, `submit` is both back to back; `proof_fingerprint` keys the negative cache on proof *content*; `strikes_against` / `suspect` are the budget's demotion signal. Mempool bound and fee eviction are stage 6 |
| `net/limits.py` | byte-denominated costs, three keyspaces, sweep on a timer, per-kind frame ceilings, the refusal cap |
| `net/handshake.py` | **built**, though not as a challenge-response — see §10. A self-authenticating signed hello, verified against the roster in the genesis document |
| `net/peer.py` | **partly built.** The hello is signed on dial, authenticated on accept, and metered; a peer is keyed on the name it proved. Bounded accept, connection caps, deadlines and the penalty box are stage 4 |
| `net/frame.py` | per-kind size ceilings; charge the announced length before parsing the body |
| `net/budget.py` | **built.** `Meter` (EWMA of measured cost), `EpochBudget` (window, reserve, per-class floors), `WorkQueue` (bounded, priority-ordered, holds across epochs) |
| `net/node.py` | **built.** `_offer_tx` authenticates inline and queues the proof; `_gossip` and `_serve_until` drain the queue out of the epoch's slack; `run_epoch` opens the budget; `status` reports both |
| `net/seat.py` | cap `pending` |
| `net/clock.py` | *unchanged* — the deadlines the budget is derived from are already there |

`state.py`, `ceremony.py`, `tiered.py`, `register.py` and `mq/` do not move.
No consensus rule changes; a node that adopts all of this and a node that
adopts none of it agree on exactly the same blocks.

## 8. What to build, in order

| stage | what | state |
|---|---|---|
| 1 | split `verify_transaction`; fingerprint negative cache | **built** |
| 2 | the work budget and the scheduler; `_handle` off the inline path | **built** |
| 3 | the `hello` handshake; peers metered under authenticated names | **built** |
| 4 | connection admission: caps, pool, deadlines, penalty box | not started — the layer the limiter has never seen |
| 5 | byte-denominated costs and per-kind frame ceilings | not started — removes the 357 ms decode from paths that never needed it |
| 6 | mempool bound and fee eviction; `pending` cap | not started — the memory half, which valid transactions cause |
| 7 | owner-keyed metering with failures charged to the note | not started — the other half of §4.3, and the first cost an attacker cannot mint |

Stages 1 and 2 were a few hundred lines and remove the liveness attack. Stage 7
is the one worth arguing about, because throttling an owner for a bad proof
punishes a buggy wallet exactly as hard as an attacker.

## 10. What changed on contact

Four things the sketch had wrong, three of which only a running node showed.

**A strike threshold is a censorship primitive.** The plan was that a body with
three failed proofs against it stops being checked. Built, it took one test to
see what that hands an attacker: watch a transaction go past in gossip, splice
three bad proofs onto its body, and the real transaction is refused by every
node it reaches, having done nothing wrong. The defence had become the attack
with better manners. `PROOF_STRIKES` now only ever *demotes* a body in the
budget — an honest proof for a struck body is still verified, just behind
everything that has not been abused — and `test_splicing_bad_proofs_onto_a_body_cannot_censor_it`
is there to keep it that way.

**Shedding loses transactions, because nothing retries them.** §5's gate 3 said
work the budget will not pay for is dropped with a retry hint. It is not:
`client.submit` sends once and then polls `txstatus`, so a shed submission is
gone, and on the 2.5 s test epoch every single one was — a legitimate payment
had to arrive inside the first 350 ms of an epoch or vanish silently. The
budget reopens every epoch, so work refused now is affordable a second or two
later: the queue holds it, bounded, for up to `MAX_EPOCHS_QUEUED` epochs. Only
the queue being *full* drops anything, and staleness expires the rest.

**The floors had to come out of the slack, not the window.** Taking each
class's floor as a share of the whole decide window looked equivalent and is
not: on a short epoch the reserve is already half the window, so a floor of
half the window left the lowest class exactly nothing, for ever. The floors are
shares of the window *after* the reserve, and the reserve itself is capped
(`RESERVE_CAP`) because 128 proofs is 3.2 s against a 2.5 s epoch's 1.5 s
window — an uncapped reserve exceeds what it is protecting and refuses
everything, which is not caution but a stall with a rationale.

**The canonical codec has no float, and `status` goes over the wire.** The
budget reported its unit cost as `25.4` and every node in the four-process
testnet went dark at once — `codec.encode` raised inside the `status_reply`, in
the reader thread, so the symptom was "no node answered" and not anything about
floats. Reported in whole microseconds now. Worth stating as a rule rather
than a fix: anything that can reach `frame.pack` is integers and strings, and
`store/codec.py` is right to refuse the rest.

And two things found while reading that this stage did not change:

| finding | why it is left alone |
|---|---|
| **`already_verified` is backend-agnostic** | `tx_fingerprint` sums `proof_bytes()` over *every* backend attached and does not record which one was checked, so a transaction verified under `mpcith` at tier L satisfies `already_verified` at a tier that runs `ssh5` — and that tier's proof is then skipped by this node. Not a soundness break: the statement `(ts, v, beta)` is the same one, already known to hold. But it is the per-tier *diversity* the three backends exist to provide, quietly not happening. A consensus-path change, so not part nine's business |
| **`tx_fingerprint` keys on proof size, not content** | Two same-sized proofs on one body collide. Harmless for the positive cache, for the reason above, and wrong for the negative one — which is why part nine added `proof_fingerprint` beside it rather than changing it |

Unrelated, and noticed because the suite was run so many times:
`test_three_pass_rejects_a_wrong_witness` fails about once in a hundred runs.
It proves with `rounds=12`, and the 3-pass soundness error is `(2/3)^12`, which
is 0.8% — so the test is doing exactly what the mathematics says and the
assertion is stated as though it were certain. Nothing to do with this stage;
it wants more rounds or a seeded prover.

## 9. Open items

| item | why it is open |
|---|---|
| **The threshold for throttling an owner** | A wallet that ships a broken prover looks precisely like an attacker. Some tolerance before the throttle bites, and the number is not derivable from anything here |
| **Whether shedding is observable** | A node that quietly drops submissions under load looks, from a wallet, exactly like a node that is down. `refused` with a retry hint helps; a client that then tries every other node has moved the flood rather than stopped it |
| **The reserve is a guess** | The budget reserves time for validating a proposal whose size is not known until it arrives. A block of 100 transactions is 2.5 s of verification and the reserve has to assume the worst case, which wastes most of it |
| **The penalty box is a keyspace too** | Remembering offending addresses is state an attacker can grow by offending from many addresses. Bounded, and then it is a cache with an eviction policy, which is a thing to get wrong |
| **Owner metering leaks** | Which owner slot a submission names is already public — this is the confidential-transactions model — but metering on it makes the node's *behaviour* depend on it, which is a side channel a network observer can query |
| **Nothing measures any of this** | Part six's question again: "the node did not fall over" is not a test. The suite needs a load harness that asserts the decide deadline was met while a flood was running, or this document is a hypothesis |
| **One machine, one core** | The budget assumes verification is the scarce resource and that it is serial. Both are true today and neither is a design decision anybody made |
