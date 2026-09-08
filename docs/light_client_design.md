# The query interface and the light client

*Part eight. Sketched, then built — see §13 for what changed on contact.*

Part seven built a wallet and ended on an admission: `Client.sync` believes what
a node tells it about its own money. That is not a small gap. A wallet that
cannot check its own balance is a bank statement, and the whole point of putting
proofs on a chain is that nobody has to take a statement on faith.

This part is about closing it, and about the three other things a client turns
out to need before that answer is worth anything.

## 0. What a client can check today

Exactly one thing: that a note it decrypts really is the note its commitment
names, because it recomputes the commitment. Everything else is hearsay.

| the client asks | the node answers | can the client check it? |
|---|---|---|
| `status` | height, tip hash, roots | no — it has no idea whether that tip is real |
| `getoutputs(from, to)` | commitments, ciphertexts, nullifiers | partly — commitments are checkable, *completeness* is not |
| `txstatus(txid)` | pending / in block *h* | no |

The middle row is the interesting one. A client can verify every output it is
given. It cannot verify the outputs it is **not** given, and a node that omits
one output makes a payment vanish. Omission, not forgery, is the attack that
matters against a light client, and no amount of checking what arrived defends
against it.

## 1. Three clients, not one

"Light client" is not one thing here, and conflating the three is how these
designs go wrong. What separates them is what they refuse to trust.

| | trusts | verifies | per-block cost |
|---|---|---|---|
| **Trusting** | one node, entirely | the commitment of each note it decrypts | 0 |
| **Following** | the validator register | the tip certificate, ancestry, and its own notes' inclusion | ~1.3 KB |
| **Adjudicating** | nothing but the genesis document | the above, plus cumulative hardening weight | ~86 KB |

The trusting client is what exists. The following client is what a wallet on a
phone should be. The adjudicating client is not a daily mode — §7 argues it is a
court of appeal that is only convened when two nodes disagree, and pricing it as
an everyday cost is the mistake that makes light clients look impossible.

## 2. The question catalogue

Four questions exist today; seven more are needed. `CLIENT_KINDS` already exists
as the gate between a client and a ceremony message, so this is an extension of a
boundary rather than a new one.

| question | answer | who needs it |
|---|---|---|
| `status` | height, tip, roots | everyone *(exists)* |
| `getoutputs(from, to, cursor)` | outputs and nullifiers in a range | scanning *(exists — but see §12 on the missing cursor)* |
| `txstatus(txid)` | pending / in block *h* / unknown | anyone who submitted *(exists)* |
| `submit(tx)` | nothing | spending *(exists)* |
| `headers(from, to)` | the header spine | following |
| `ancestry(from_hash, to_hash)` | a proof that one header descends from another | following, after being offline |
| `inclusion(cm, at_height)` | a proof that this note is live under `utxo_root` | **the answer to part seven's open item** |
| `register(grid_id, at_height)` | the seat set, and its proof under `registers_root` | following, when the validator set moves |
| `weight(from, to)` | hardened weights, and stamps on demand | adjudicating |
| `params()` | the genesis document | bootstrapping |
| `tags(from, to)` | detection tags only, no ciphertexts | scanning on a phone (§9) |

Two properties should hold for all of them and hold for none of them today.
Every answer should be *self-certifying* — checkable against a root the client
already believes — and every answer should be *bounded*, because an unbounded
answer is a denial-of-service primitive pointed at the node rather than a query.

## 3. Unspent is a positive statement

The obvious way to ask "is my note still mine to spend" is to ask whether its
nullifier is absent from the nullifier set, and non-membership in an append-only
set is genuinely hard — it needs a sorted or indexed structure the chain does not
have. Part seven recorded it as the open item on those grounds.

That framing was wrong, and the accumulator already says so:

```python
def spend(self, value):
    pos = self.index[value]
    self.dead.add(pos)
    # The slot is kept so every other entry keeps its index; only the leaf
    # changes, so the root moves and history stays addressable.
    self._tree.update_leaf(pos + 1, _leaf(self.label, f"{TOMBSTONE}:{value}"))
```

`SealAccumulator` does not delete. It **tombstones in place**: the note's slot
survives and the leaf at that slot changes from `utxo:cm` to
`utxo:fin6:spent:cm`. So the question a wallet actually wants to ask is

> is the leaf at position *p* equal to `utxo:cm`, under the `utxo_root` in the
> header I trust?

which is an ordinary **inclusion** proof about one leaf, not a non-membership
proof about a set. If the note has been spent, the leaf there is the tombstone
and no proof of the live form exists. There is nothing to design: the property
fell out of a decision made for a different reason — keeping indices stable
across a spend so that history stays addressable — several parts ago.

Two things it gives for free. The client learns *only* about its own note, since
it names a position rather than scanning. And the answer is a proof, so the node
that serves it cannot lie, only refuse.

## 4. The fan-out is wrong

So how big is that proof? This is where the honest answer is uncomfortable.

`_SealTree` folds `sbs = 1000` children into each parent. A proof that one leaf
sits under the root therefore has to hand the verifier every sibling in the
chunk, at every level, so it can recompute the fold:

| leaves in the UTXO set | levels | siblings | proof | verify |
|---|---|---|---|---|
| 50,000 | 3 | 1,048 | **80 KiB** | 7.8 ms |
| 10,000,000 | 4 | 2,007 | **153 KiB** | 7.9 ms |

*(measured: 78 bytes per leaf on the wire, 3.9 ms per 1,000-leaf fold)*

153 KiB to prove one note is unspent is not a light client. A binary Merkle tree
over the same leaves gives 24 × 32 = **768 bytes** and verifies in 7 µs — two
hundred times smaller, and a thousand times faster.

The fix is not to change `sbs`. Part seven already found that `sbs` has two
constituencies pulling in opposite directions; this is a third, and a parameter
asked to satisfy three constituencies satisfies none. The fix is a **second tree**:

> a thin binary Merkle tree over the same UTXO leaves, maintained alongside the
> seal tree, its root committed as one more field in `NetworkBlockHeader`.

It costs 32 bytes in the header, one `log₂ n` update per note (measured at 0.04 s
to build 50,000 leaves from scratch, so the incremental cost is noise beside the
26 ms a transaction already spends being verified), and it buys 768-byte proofs.
The seal tree keeps doing what it is good at — a canonical root two nodes can
agree on, cheap to update in bulk. The witness tree does what it is good at —
short paths for people who were not there.

This is the same shape as the archive's two sections: one structure per
question, rather than one structure asked to answer every question badly.

## 5. The shortcut that does not work

There is a tempting way to avoid the second tree, and it should be written down
so nobody spends a week rediscovering it.

The seal fold is built from *counts*: `_apply_rows(cnt, _seal_rows(v), ±1)`
accumulates each child into a count matrix, and the parent is a function of that
matrix alone. Counts are additive. So why not send the client the aggregated
counts of the 999 siblings — one fixed-size matrix, independent of fan-out — and
let it add its own leaf's rows and check the parent?

Because the client would then be checking a weaker statement than it thinks. A
count matrix handed over as a witness is unconstrained: it need not correspond to
any multiset of real leaf values. Given the target parent and freedom to choose
the aggregate, an attacker is solving for a matrix rather than searching for a
collision among hash strings, and those are not the same problem. The individual
siblings are sound *because* they are values the fold is binding over; their
aggregate is a relaxation, and whether the relaxed statement is still binding is
an open question nobody here has answered.

The rule that falls out is worth keeping: **a witness may be a compression of the
data, never a compression of the constraint.**

## 6. The spine, and the cost of being offline

A following client needs to know that the tip it was handed descends from the
chain it saw last time. Today that means the header chain: 232 bytes per header
(measured), 1,072 bytes for a seven-seat certificate, 1.33 ms to verify one.

At the production cadence of 19.75 s that is 4,375 headers a day. Walking them
all is 1.0 MB/day of headers, or 5.7 MB/day if the client checks a certificate on
each — 2.1 GB a year to stay caught up on a chain whose entire state fits in a
laptop. The chain is not the problem; the *walk* is.

The fix is another root, and the same one the ledger already uses: an
append-only accumulator over header hashes, `history_root`, committed in each
header. Then a client that was last online at height *h₀* is handed

- the tip header and its certificate — 1.3 KB
- one ancestry proof that *h₀* is under the tip's `history_root` — ~21 nodes

and never downloads the 4,374 headers in between. A daily sync becomes about
**3 KB**. A client offline for a year pays the same 3 KB, which is the property
that makes an intermittently-connected wallet viable at all.

`registers_root` already sits in the header, so the same trick answers "who were
the validators at height *h*" with a proof rather than an assertion — which is
what makes following the register a *verified* choice rather than a trusted one.
That is the grid register's design (attendance as rooted state, not opinion)
finally paying its second dividend.

## 7. When the register is what is in dispute

Following the register works right up to the moment the register is the thing
being lied about. Two nodes hand a client two tips, each with a valid-looking
certificate from a different seat set. Signatures cannot settle it; only work
can.

That is exactly what hardening is for, and the arithmetic is unusually clean: a
branch that reuses a turn spent on its own history is invalid outright, so

    max fork depth = attacker's unspent turns / width

is a **bound**, not a probability. A client can compute how deep a reorg could
possibly go and decide for itself when a payment is settled — the number part
three promised and no client has ever asked for.

The cost is real and should not be hidden. A production stamp is 2,700 bytes
(2,144-byte WOTS signature, 17-node authentication path) and the width is 32
turns per block, so a block's stamps are **84 KiB** and verify at 0.44 ms each —
14 ms per block. Following weight costs 65× what following certificates costs.

The conclusion is not that hardening is too expensive. It is that hardening is an
**appeal court**. A client follows the register by default at 1.3 KB a block, and
downloads stamps only for the disputed range when it is shown two tips — which is
rare, bounded, and exactly when 84 KiB a block is worth paying. Designing for the
adjudicating client as the everyday case is what makes people conclude that light
clients are impossible on chains where they are merely unnecessary.

## 8. What it actually costs

The measurements, assembled, at 19.75 s blocks and 200 transactions a block:

| | per block | per day |
|---|---|---|
| headers only | 232 B | 1.0 MB |
| headers + certificates | 1.3 KB | 5.7 MB |
| following, with `history_root` | — | **~3 KB per sync** |
| one inclusion proof, witness tree | 768 B | per note, on demand |
| one inclusion proof, seal tree today | 80–153 KiB | per note, on demand |
| adjudicating (stamps) | 86 KB | 370 MB |
| **scanning for incoming notes** | **126 KiB** | **538 MB** |

The last row is the surprise, and it inverts the whole problem. Consensus is
cheap. A following client's per-block consensus cost is 1.3 KB and its per-block
*privacy* cost is 126 KiB — ninety-seven times more. Every design instinct here
has been pointed at making agreement verifiable, and the thing that will actually
stop a wallet running on a phone is that receiving money privately means reading
everyone else's mail.

## 9. Privacy is the whole difficulty

Part seven dismissed detection tags: "not needed at this scale; worth knowing the
shape of." That was right for a wallet on a laptop and wrong for a client on a
phone, and §8 is why.

There are three points on the curve and no free lunch:

| | scan cost | what leaks |
|---|---|---|
| download every ciphertext | 538 MB/day | nothing |
| static detection tag, filtered client-side | 3.4 MB/day + 272 B per hit | outputs to one address are linkable *to each other*, by anyone, forever |
| detection key held by the node | tunable | the node learns a fuzzy superset of your outputs |

The middle row is the trap. A tag the client can test *without* doing the
Diffie–Hellman must be derived from something static, and anything static is a
public label linking every payment to the same address — which is most of what
the ciphertext was protecting. The bandwidth is a 160× win and the privacy loss
is close to total, and a design that reports only the first number is lying by
omission.

The third row — a detection key with a tunable false-positive rate, so the node
learns a fuzzy set the user can plausibly deny — is the honest answer, and it is a
design of its own that this part does not attempt. What this part can do is name
the trade properly, and note that the point query of §3 has the same shape:
asking `inclusion(cm)` tells the node exactly which note is yours. The
mitigations are the usual ones — ask a different node than the one you scanned
from, batch with decoys, ask by position range rather than commitment — and all
of them cost something.

CPU, notably, is not the constraint: trial decryption is 36 µs per foreign
output, so a day of scanning is 62 seconds of a phone's time. Bandwidth is.

## 10. What the node must keep to answer

An operator picks a retention profile for reasons of disk. That choice silently
decides which clients that node can serve, and nothing currently says so:

| question | `FULL` | `COMPACT` | `HEADERS` |
|---|---|---|---|
| `status`, `headers`, `ancestry`, `weight` | ✓ | ✓ | ✓ |
| `getoutputs`, `tags` | ✓ | ✓ | ✗ |
| `inclusion` | ✓ | ✓ | ✗ *(needs the leaves)* |
| `register` | ✓ | ✓ | ✓ |
| `txstatus` for old transactions | ✓ | ✓ | ✗ |
| re-verifying a historical proof | ✓ | ✗ *(one backend kept)* | ✗ |

The row that matters is `inclusion`: a `HEADERS` archive keeps roots and not
leaves, so it can tell a client the tip is real and cannot tell it whether its
money is. A network of `HEADERS`-only nodes agrees with itself perfectly and can
serve nobody. That is an operational fact worth putting in the operator
documentation rather than leaving to be discovered.

## 11. What this adds to `chain/`

| module | change |
|---|---|
| `seal.py` | *witness tree* — a binary Merkle tree beside the seal tree, `path(pos)` and `verify_path` |
| `tiered.py` | `NetworkBlockHeader` gains `witness_root` and `history_root` |
| `state.py` | maintain the witness tree with the UTXO accumulator; the tombstone form is already there |
| `net/frame.py` | seven more names in `CLIENT_KINDS` |
| `net/node.py` | serve them; move the output index out of RAM and into the store |
| `net/client.py` | `headers`, `ancestry`, `inclusion`, `register`, `weight`, `tags`, and a cursor on `getoutputs` |
| `light.py` | *new* — the following client: a header spine, a register view, and a verified balance |
| `hardening/history.py` | serve weights and stamps for a range; nothing else moves |
| `cli.py` | `fin6 light sync` / `fin6 light verify` |

Note what does not move: the proof stack, the ceremony, the tiers. A light client
is a reader, and the ledger does not need to know it exists — the same property
part seven relied on, for the same reason.

## 12. Open items

| item | why it is open |
|---|---|
| ~~Two more roots is a format change~~ | **Done**, both at once as argued. Measured at 68 bytes of header between them. |
| The register a certificate is checked against is one roll late | The roll of an epoch is applied before `register_root` is taken, so the register under `registers_root` is one step ahead of the seats that signed the block. Membership survives a roll and standing does not, so a client's quorum figure can be wrong by one across a founding. Found while building, not while sketching. |
| *(was)* Two more roots is a format change | `witness_root` and `history_root` change every header hash and every root above them. Same argument as the ciphertext in part seven: cheap before a real genesis, expensive after — and this is the second time that argument has come up, which suggests doing both at once. |
| ~~`getoutputs` has no cursor~~ | **Fixed.** A page now ends on a height boundary and names where to resume; `Client.sync` follows the cursor to the tip. |
| ~~The output index lives in RAM~~ | **Fixed**, and more cheaply than expected: the outputs a wallet scans *are* the UTXO rows, so `utxo` grew a `height` and a `sealed` column and the separate index disappeared rather than moving. |
| Aggregate-count witnesses | §5 argues they are unsound and does not prove it. Worth an hour from someone who wants to be sure, because if the relaxation *is* binding, the second tree is unnecessary. |
| Completeness of a scan | Inclusion proofs answer "is this note live"; nothing answers "have I been shown every output in this range". A commitment to the per-block output *count*, checked against the range served, is most of the fix, and it is not designed. |
| Fuzzy message detection | §9's third row is the only honest answer to the scanning problem and is a design of its own. |
| Weight is observed, not agreed | Every node assembles a hardened block from whatever stamps have reached it, so two honest nodes at the same tip report *different* cumulative weights. Fork choice is unaffected — it compares branches, and the difference is smaller than one block — but a client must key agreement on the tip, never on the number. Found by running it. |
| Point-query linkability | `inclusion(cm)` identifies a note to the node serving it. Decoys and position ranges help; nothing is specified. |
| What a client does with two tips | §7 says weight decides. Nothing implements the comparison, and "the client asked two nodes and they disagreed" has no code path at all. |

## 13. What was built

Everything in §11 except the two things §09 and §07 said were designs of their
own — detection tags and the adjudicating client. `light.py` follows the
register; weighing two tips is still not implemented and still the honest answer
when two nodes disagree.

Four things changed on contact with the code.

**The witness tree is fixed-height, not `log₂ n` deep.** The sketch said "a thin
binary Merkle tree" and did not think about the fact that this tree takes
*updates*: spending a note rewrites its leaf. A tree whose shape depends on how
many leaves it holds reshapes on every append, so an update would cost a
rebuild. A fixed height of 32 keeps the shape constant, makes an update 32
hashes, and costs nothing for the empty part because every all-empty subtree at
a level has the same digest. The proof pays 32 siblings instead of ⌈log₂ n⌉ —
except that the ones above the occupied prefix are all that same default, so a
one-bit-per-level bitmap takes it back down:

| UTXO leaves | siblings sent | proof | verify | update |
|---|---|---|---|---|
| 1,000 | 10 | 328 B | 19.4 µs | 22.7 µs |
| 50,000 | 16 | **520 B** | 19.6 µs | 23.3 µs |
| 1,000,000 | 20 | 648 B | 19.4 µs | 23.0 µs |

Better than the 768 bytes the sketch promised. The verification figure is worse:
19 µs, not 7 µs, because the sketch priced a bare `sha256` pair and forgot the
interpreter around it. Against the seal tree's 7.9 ms for the same statement it
is still four hundred times faster, which is the comparison that mattered.

**A root can be recomputed for any earlier prefix.** A header at height *H*
commits the spine of blocks 1…*H*−1, so by the time anyone asks, the tree has
moved on — and the sketch did not notice. Keeping a lagging copy would have
been the obvious fix; it is not needed. In a fixed-height tree the root and the
path for any earlier cut come out of the live tree in `height` steps: a subtree
wholly below the cut is the node already stored, one wholly above it is that
level's default, and exactly one per level straddles, which is the node the
prefix walk is computing anyway. `WitnessTree.root_at` and `path_at`.

**Ancestry is cheaper than promised.** A day's spine at the production cadence
is 4,375 blocks and proves in 424 bytes; a year's is 1.6 M and proves in 680.
With the tip header (187 B for the header alone, 68 of that the two new roots)
and a seven-seat certificate (1,072 B), a client that has been away for any
length of time is caught up in about **1.9 KB** — against the ~3 KB estimated,
and against 371 MB of walking.

**The output index did not need to move; it needed to stop existing.** §12
recorded that `NodeProcess._index` grows a Python list for ever and said the
index belongs in the store. It belongs in the store the ledger already keeps: an
output *is* a UTXO row, so `utxo` grew `height` and `sealed` columns and the
second copy went away. The node serves clients from a read-only connection on
the same database, which is what WAL is for.

### What a client checks now

`test_a_light_client_proves_a_balance_on_a_running_network` runs the claim
across four node processes: follow the tip, check the certificate against a
register recomputed from its own records, prove a note live under the trusted
`witness_root`, go away for several blocks and come back on one path. Then it
puts four lies to the same client and asserts each is refused — a missing
certificate, an altered header, a register that does not recompute, and a
missing ancestry proof — plus a fifth on the note itself: a path that opens
perfectly well to somebody *else's* leaf. That last one is the check worth
naming, because a spent note's tombstone path also opens perfectly well, and a
client that verified the path without checking what it opened to would call a
spent note live.

The client reports **two numbers, never one**: proved and unproved. The
distinction is the only thing it has that a wallet does not, and collapsing it
into a single balance would give the answer back to the node.

## 14. The four that were left

§12 named eight open items. Four are now closed and one is half closed; what
follows is what each cost and, where it matters, what it does not buy.

### Metering, and a cheaper no

Two different answers to one sentence. The first is ordering: every reason a
transaction could be refused anyway — wrong chain, absent input, republished
nullifier, a shape outside what the chain admits — is now checked *before* the
proof rather than after it. Nothing new is checked; the checks were simply
behind the expensive one.

| | |
|---|---|
| refusing rubbish, cheaply | **2.1 µs** |
| refusing it by proof, as before | 25.5 ms |
| ratio | **12,000×** |

The second is a budget. Every source gets a token bucket, priced by what the
request makes the node do — a status is 1, an inclusion proof 2, a page of
outputs 10, a submission 50 — refilling at 20 tokens a second over a 240
capacity, so a wallet never meets the meter and a flood meets it in about four
transactions. A seated peer is metered too, generously, because a validator
that cannot gossip is a validator that cannot vote.

One defect found by running it, and worth recording because it would have been
invisible in a unit test: keyed on the source address alone, a validator's
promotion to peer rates handed its budget to **every** client dialling from the
same host — which on a testnet is all of them, and in production is anyone
behind the same address as a validator. Peers are now metered under the name
they claim, everybody else under the address they came from.

### Scan completeness

Two numbers in the header, `utxo_count` and `nf_count`, cumulative — four bytes
between them. Positions are issued in order and never reused, so the difference
between the header a client last scanned to and the header it trusts now is
exactly how many outputs the range produced. Counting them is the check; the
contiguity test beside it is what makes the count mean anything, because
otherwise a node could answer a request for *n* rows with *n* copies of one row
and the arithmetic would still work.

`LightClient.scan` refuses a short answer with the count and a padded one with
the positions, and it is the first thing here that catches **omission** — the
attack §00 named and nothing until now could see.

### Detection tags

The address grew a third key: spend, view, and now *detect*. A sender tags each
output with a truncated hash of a second exchange against it; a client hands a
node the detection secret and a precision, and the node returns the outputs
whose tags agree on that many bits. Measured against 4,000 outputs and a
watcher who owns none of them:

| precision | matched | in practice | in theory |
|---|---|---|---|
| 1 bit | 2,023 | 1 in 2.0 | 1 in 2 |
| 2 bits | 1,002 | 1 in 4.0 | 1 in 4 |
| 4 bits | 239 | 1 in 16.7 | 1 in 16 |
| 8 bits | 18 | 1 in 222 | 1 in 256 |
| 12 bits | 1 | 1 in 4,000 | 1 in 4,096 |

The knob behaves exactly as §09 predicted, at 30.8 µs per output for the node
doing the sorting. Three bytes on the wire per output, bound into the binding
scalar beside the ciphertext — rewriting a tag is not theft, but it is a way to
make a payment invisible to the person it was for, so the proof covers it.

And the caveat, which belongs in the same breath as the number: **the precision
is a knob the node turns.** It is handed the whole detection secret and asked
to compare only some of the bits, so this bounds the bandwidth
cryptographically and the disclosure only behaviourally. Binding it properly
needs one detection key per tag bit, so a client can hand over the first *p*
keys and the node is *unable* to compute bit *p*+1. That costs 32 bytes of
address per bit — at eight bits, a 570-character address against today's 166 —
and it stays open. What is built is the useful half, said out loud rather than
implied.

### The adjudicating client

Two changes, one of them forced.

The testnet now hardens. Each node holds the slice of the turn pool dealt to
it, stamps the drawn turns it owns, and gossips them; the stamps are assembled
and the block enters history once the threshold is met — usually an epoch or
two after it was agreed, which is the gap between consensus finality and
historical finality, made visible instead of hidden.

Building that broke the anchor. A turn used to sign
`H(block_hash, cumulative_weight, era_root)`, which reads well and cannot
survive a network: weight is not canonical until every stamp has arrived, so a
node that assembled a block with six stamps and one that assembled the same
block with eight disagreed about the anchor of the *next* block, and their
stamps then verified nowhere. `turn 70: puzzle not solved`, for twenty minutes,
until the cause was clear. The anchor now signs the branch **height**, which
consensus fixes before any turn is spent. Nothing is lost: the block hash still
commits to the parent, and a turn still cannot be moved to another block.

`Adjudicator` then verifies rather than tallies. It rebuilds each node's branch
in its own `NetworkHistory` and re-runs every check — that the committee is the
one the draw produces, that each stamp solves its puzzle and opens to the era
root, that no turn is spent twice on a branch, that the weight claimed is the
weight of the stamps present. A node's `cumulative` field is never read as
evidence, only compared with what the client computed.

| | |
|---|---|
| verifying a branch | 5.1 ms per block (local: 8 turns, tree height 10) |
| evidence | 19 KiB of stamps per block; 84 KiB at production width |
| settlement at a third of the pool | 729 blocks — **four hours**, and a bound, not a probability |

It reports; it does not adopt. Choosing is the caller's, and a client that
silently switched chains on a fork-choice rule would be doing the thing this
whole module exists to avoid.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/a8227791-ff29-4847-ae9f-1190c55b438f
