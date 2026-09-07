# Persisting the chain — fin6 design sketch, part four

How the chain survives a restart. Follows `private_chain_design.md`,
`tiered_ceremony_design.md` and `hardening_design.md`, all implemented in
`chain/`.

## 0. What survives a restart today

Nothing. Every object in `chain/` is a live Python value: `ChainState` holds two
`SealAccumulator`s in memory, `Node` holds a dict mempool, `TierWorld` holds the
grid registers, `NetworkHistory` holds every branch it has ever seen, and `Era`
rebuilds a 131,072-leaf tree in its constructor. The demos bootstrap a world, run
it, and exit.

There is also no wire format — the same gap seen from the other side. A store and
a network both need one canonical encoding of a block, and there is one right
answer serving both, so the codec below is not a storage detail.

Two questions, then: what is worth writing down, and what "written down" has to
mean for each kind of state. The second answer differs by three orders of
magnitude across the system, which is why it needs its own section rather than a
sentence.

## 1. Four kinds of state

| class | what is in it | what losing it costs | durability it needs |
|---|---|---|---|
| **A · ledger** | utxo values + dead bits, nullifiers, register records, network headers, hardened headers, weight, spent turns | the node cannot validate anything; recovery only by re-sync | atomic with the block, fsynced |
| **B · evidence** | transaction bodies, proofs, quorum certificates, attendance rolls, ceremony and super blocks | can still validate forward; cannot serve history or re-derive it | written lazily, deleted by policy |
| **C · working** | three mempools, verification cache, era tree, topology, trust list | an epoch of throughput | none |
| **D · secret and monotone** | node signing seed, era master seed slice, highest anchor ever signed | key compromise, or a turn spent twice | fsync **before** the action, not after |

Class D inverts the usual ordering. Everywhere else you do the thing and then
record it; there you record the intent and only then do the thing (§8).

## 2. The measured shape of the data

One 1-in/2-out transfer, DEMO parameters, carrying the full designed per-tier
policy:

| part | bytes | share |
|---|---|---|
| `v`, the MQ output vector (65 field elements) | 2,080 | 0.36% |
| cms, nullifiers, spend signature, fee | ~230 | 0.04% |
| `mpcith` proof | 64,760 | 11.1% |
| `ssh5` proof | 205,924 | 35.2% |
| `ssh3` proof | 311,437 | 53.3% |
| **shipped total** | **584,431** | |
| **class-A residue, binary** | **~200** | |

The residue is what the ledger keeps forever: one flipped dead bit, two created
commitments, one nullifier, and their index entries.

**A transaction ships about 2,900x more bytes than it permanently costs.**
Everything below follows from that ratio.

At the hardening layer's 19.75 s blocks — 70,000 turns, width 32, two eras a day
— there are 4,375 blocks a day:

| retained | 10 tx/s | 100 tx/s |
|---|---|---|
| everything (archive) | 505 GB/day | 5.0 TB/day |
| bodies without proofs | 2.0 GB/day | 20 GB/day |
| class A only | 173 MB/day | 1.7 GB/day |

So an archive node is a funded role, not a default, and an ordinary node keeps
proofs only as long as it might have to look at them again — which the hardening
layer bounds exactly (§5).

## 3. The commit boundary

**The network block is the only commit point.** Phases L and S produce real
signed objects, but nothing below tier 2 touches the ledger, so the store treats
a whole epoch as a journal and then applies once:

```
epoch journal (discardable whole)        ledger (atomic, ordered)
  phase L  ceremony blocks, rolls    ┐
  phase S  super blocks, drops       ├──> one transaction: deltas, registers,
  phase X  network block + cert      ┘    roots, tip, undo record
```

A crash anywhere in L/S/X leaves the ledger at the previous height and the
journal half-written; recovery is to drop the journal and re-run the epoch. That
is safe because nothing in the journal is unique — certificates can be
re-gathered from peers, and a node that lost its own ceremony block has signed
nothing about the ledger. Committing per tier instead would buy nothing, since
the lower tiers are not final, and would cost three fsyncs an epoch instead of
one.

Hardening commits separately and later: a block enters history when it carries
`t` stamps, which is a second write against the same tip. So there are exactly
two durable writers — apply-block and harden-block — and they are ordered by the
block hash they share.

## 4. Persist the set, not the tree

`SealAccumulator`'s logical state is exactly `(ordered values, dead bits)`;
everything else is derived. Measured on `_SealTree` at `sbs=1000`:

| operation | cost |
|---|---|
| build from leaves | 4.1 us/leaf, linear from 20k to 400k |
| `update_leaf` (a spend) | 1.6 ms, flat in N |
| `append_leaf` | 1.6 ms **plus a full rebuild every 1,000 appends** |

Four consequences, in order of importance.

**1. The store never encodes the tree.** Writing values and a bitmap and
rebuilding at startup costs 4.1 us/leaf: 41 s for a 10M-note history against
320 MB of values. Persisting internal tree state would couple the ledger format
to an mq implementation detail to save a minute once per restart.

**2. Startup is a rebuild, not a replay.** Replaying blocks re-verifies proofs;
rebuilding folds hashes. The two differ by about five orders of magnitude, and
that difference is what makes proof pruning (§2) tolerable.

**3. `append_leaf` had a defect the storage arithmetic made unignorable — now
fixed.** It rebuilt the entire tree whenever a new `sbs` group opened, because
extending a level meant growing the level above it and, at the top, promoting a
root. So the cost of an append was two terms: a flat fold of ~1.4 ms, which is
what incremental maintenance inherently costs, plus a rebuild term of
`N x 4.1 us / 1000`. The second term is invisible at demo sizes and eventually
swamps the first — they cross at about 340,000 notes. Marginal cost of an
append, measured at the production `sbs=1000` over 2,000 appends onto an
existing tree:

| existing notes | before | after |
|---|---|---|
| 20,000 | 1.45 ms | 1.35 ms |
| 100,000 | 1.90 ms | 1.46 ms |
| 400,000 | 3.29 ms | 1.58 ms |
| 10,000,000 (extrapolated) | ~42 ms | ~2 ms |

Before, the growth was linear in the set size and building a ten-million-note
history by append would have taken some 57 hours; a transaction touching four
leaves would have cost 168 ms, capping the chain near **6 tx/s** at that size.
After, the term is gone: `_propagate` opens a new group in place, and a level
that outgrows the root hashes its stored value and folds a new level over the
top, which is O(1) work at the moment of promotion. The same four-leaf
transaction costs ~8 ms, or **~125 tx/s** on one Python core at ten million
notes.

The fix is in `mq/ms6/core.py` and it is verified two ways: the roots of a
grown tree and a one-pass build agree exactly, at every fan-out from 2 to 7 and
across five levels of growth, and `mq/tests/test_sealtree.py` carries a tripwire
that fails if an append ever calls `build` again.

**4. The crossover is still exact.** Rebuilding costs `N x 4.1 us`;
propagating costs 1.6 ms per touched leaf. So **rebuild when a block touches more
than N/390 leaves, propagate otherwise** — 256 touches at 100k notes, 25,600 at
10M. Which says incremental is right at large N, which is precisely where
consequence 3 bites.

## 5. Undo, and why the pool bounds it

`ChainState` only moves forward; a reorg needs it to go back. The undo record is
the inverse of what was applied:

```
undo(h) = { unspend   : [cm, ...]        flip the dead bit back
            truncate  : n_created        drop the tail
            nullifiers: n_added          drop the tail
            fees, prev_utxo_root, prev_nf_root, prev_registers }
```

Truncation is legitimate only because the accumulator is append-only and undo is
strictly last-in-first-out, so the store must refuse to undo any block that is
not the tip. That is a stronger and far cheaper invariant than general rollback.

**How far back to keep undo is not a guess here.** The hardening layer bounds a
rewrite absolutely — `max fork depth = attacker's unspent turns / w` — so
retention has an arithmetic answer:

| tolerated adversary | ceiling | wall clock |
|---|---|---|
| 10% | 218 blocks | 1.2 h |
| 25% | 546 blocks | 3.0 h |
| a third | 729 blocks | 4.0 h |
| 50% | 1,093 blocks | 6.0 h |

Keep undo for the depth you are willing to be reorged by; beyond it a block is
irreversible by storage policy as well as by weight, which is an honest statement
of a limit rather than an accident. Bitcoin cannot compute this table. At 10 tx/s
a third-of-the-pool ceiling is 729 blocks x ~198 tx x ~200 B = **29 MB**, so the
answer in practice is to keep the whole ceiling and stop thinking about it.

## 6. Snapshots are self-certifying

A snapshot at height h is `(utxo values + dead bits, nullifier values, every
register, burned fees)`. Its correctness needs no trust in the sender: the
network header at h already commits `utxo_root`, `nf_root` and `registers_root`,
and the joiner recomputes all three by folding at 4.1 us/leaf — about a minute
for 10M notes.

That is what makes pruning safe. What a snapshot-synced node cannot do is
re-derive the agreement itself: it is trusting that the ceremony checked the
proofs and that the weight on top is real. **Snapshot sync trusts consensus;
genesis sync trusts nobody and needs an archive node.** Both are legitimate; the
design should not pretend the first is the second.

The values are an ordered list, so a snapshot streams as fixed-size ranges with a
digest each, fetchable from different peers and folded once at the end.

## 7. What a node's store looks like

**SQLite in WAL mode for indexed records, plus append-only segment files for
bodies and proofs.**

| engine | why | why not |
|---|---|---|
| **SQLite + segments** | one atomic multi-table commit *is* §3's boundary; single writer matches the node; pruning is `unlink`; stdlib, no build step | **chosen** |
| LMDB | faster point reads, single-writer MVCC | fixed map size, a C dependency, and the bulk lives in flat files anyway |
| RocksDB | built for exactly this scale | large operational surface, a build dependency for a project that has none |
| flat files only | no dependency at all | the class-A indexes are hundreds of millions of point lookups; that is a database, and writing one is not the interesting work here |

Schema sketch — class A and the tip:

```sql
meta(key, value)          -- chain_id, height, tip, era_id, format version
utxo(pos INTEGER PRIMARY KEY, cm BLOB UNIQUE, dead INTEGER)
nullifier(pos INTEGER PRIMARY KEY, nf BLOB UNIQUE)
register(grid_id, node_id, joined, standing, consecutive, total,
         last_seen, led, faults, PRIMARY KEY(grid_id, node_id))
netblock(height INTEGER PRIMARY KEY, hash, prev, epoch, utxo_root, nf_root,
         super_root, registers_root, seg_id, seg_off, seg_len)
hardened(block_hash PRIMARY KEY, height, prev, era_id, weight,
         cumulative, spent_root)
spent_turn(era_id, leaf_index, block_hash, PRIMARY KEY(era_id, leaf_index))
undo(height INTEGER PRIMARY KEY, blob)
```

Two details carry design weight. `utxo.dead` is a column rather than a deletion
because the seal tree keeps a spent slot so every later note keeps its index —
the storage model and the accumulator agree on this, which is the sign it is the
right shape. And `cm UNIQUE` **over dead rows too** is what implements
`ever_contained`, so output replay is caught by an index rather than a scan.

Bodies and proofs go into segment files, one per era (2,187 blocks), addressed by
`(seg_id, offset, length)`. Pruning an era is deleting one file and clearing
three columns.

## 8. Compressing an archive

Measured rather than assumed, because the intuition is wrong in both
directions: the bulk of the data cannot be compressed at all, and the part that
can does not need a compressor.

**Proofs do not compress, and trying costs bytes.** At 7.996-7.999 bits per byte
there is nothing there — uniform field elements and hash output:

| proof | raw | zlib-9 | bzip2 | lzma |
|---|---|---|---|---|
| mpcith | 63,192 | 63,218 | 63,792 | 63,256 |
| ssh5 | 199,844 | 199,915 | 201,161 | 199,916 |
| ssh3 | 326,877 | 326,983 | 328,816 | 326,952 |

Every entry to the right of `raw` is larger than `raw`. So the archive never
offers a proof to a compressor; the format separates opaque bytes from
structured ones and only tries on the second.

**Canonical encoding is what compresses the rest.** One block's headers, rolls
and certificates:

| | bytes | |
|---|---|---|
| Python objects as JSON | 19,001 | |
| JSON + zlib-9 | 5,404 | 3.5x |
| `codec.encode` | 5,011 | **3.8x** |
| `codec.encode` + deflate | 4,429 | **4.3x** |

Three mechanisms do that work, and all three are specific to what this chain
actually holds. *Interning*: a quorum certificate names one block hash once per
attestation — 28 times in the measured block — and the table stores it once.
*Hex packing*: every identifier here is a hex string, usually behind a short tag
(`tx:`, `nb:`), and the hex half is stored as the bytes it stands for.
*Vector packing*: a list of field elements is written as one length and n
fixed-width elements with no per-item tags, chosen per list against the tagged
encoding so a list of small integers is never inflated to 32 bytes an entry.
Deflate still finds another ~11% on top, so a structured section is deflated
only when the result is actually smaller, with a codec tag recording which
happened — the format therefore cannot make a record larger than not
compressing at all.

The encoding costs 0.86% against the per-protocol serialisers in `mq`, which is
the price of being decodable at all: those write bytes, this writes bytes that
come back as the object.

**Retention is the order of magnitude.** Every transaction carries three proofs
of the same statement because the tiers deliberately do not share an
implementation. That diversity protects the live consensus; it does nothing for
a reader in five years, who needs the statement to be true, not to be proved
three ways.

| profile | keeps | bytes/block | at 10 tx/s | can it re-derive history? |
|---|---|---|---|---|
| `full` | all three proofs | 583,445 | 505 GB/day | yes, in three independent systems |
| `compact` | one proof (`mpcith`) | 68,830 | 56 GB/day | yes |
| `headers` | no proofs | 5,865 | 1.4 GB/day | no — it can show what was agreed, not re-check it |

`compact` is **8.5x** smaller than `full` and every transaction in it still
verifies; `headers` is 99x smaller and honest about what it gave up. Dropping
proofs is a storage policy rather than a change to history, because no root
commits to them: `txid` binds the transaction body, and the proof bytes are not
in it.

**The segment.** One file per era, append-only, records of
`header | descriptors | payloads | sha256`. Descriptors precede payloads, so a
reader builds its index by seeking rather than by reading, and rebuilds it on
every open — a lost index can never be what loses an archive. The digest covers
descriptors and payloads together, which turns silent bit-rot into a refusal to
serve that record while its neighbours stay readable. Pruning an era is
`os.remove`, which is the whole reason for one file per era.


## 9. The one write that must precede its action

Everything above records what already happened. Turn spending cannot: signing a
second anchor with one WOTS key publishes the private key, so the record must be
durable *before* the signature exists.

```
1. fsync( high_water = anchor_height )     -- refuse to sign at or below it
2. sign
3. broadcast
```

A monotone high-water mark, not a set: 8 bytes, one fsync per stamp, and it fails
safe. A crash between 1 and 2 wastes a turn, which costs the holder one stamp; a
crash between 2 and 3 has already been recorded. The reverse order loses the key.

This also closes the **stateful signing** item from part three. The durable
spent-turn record is *the chain itself* — every spent turn appears in a hardened
block — so a holder restored from backup does not need its local file to be
right. It needs to sync to the tip and refuse to sign at or below the highest
height it finds itself in there. The local mark is a cache of a fact the network
publishes, which is the only version of stateful signing that survives an
operator restoring last night's backup.

The era master seed is the other class-D item: `Era` derives every key from it,
so a leak is the whole slice and a loss is the whole slice's remaining turns. It
does not belong in the same store as the ledger; the store holds the `EraSpec`,
which carries no secret, and the spent set.

The 131,072-leaf era tree is ~132M hashes of pure derived data — class C — but
the *next* era's tree must exist before the boundary, so it is precomputed and
cached as an ordinary file that may be deleted at any time.

## 10. What not to persist

- **The three mempools.** Rebuilt by gossip within an epoch, and a restored
  mempool is a way to re-admit transactions the chain has since invalidated.
- **The verification cache.** It keys on proof bytes and saves work only within a
  session.
- **Losing branches.** Keep the heaviest branch and anything inside the undo
  ceiling; a branch that can no longer win is garbage.

One exception, and it is the interesting one. **The trust list should be
persisted precisely because it does not matter.** It accrues by watching
ceremonies over many epochs, so it is expensive to rebuild; and it is
structurally barred from quorum, so corrupting it can hurt nobody but its owner.
It is the only state in the system that is costly to lose and harmless to get
wrong, so it gets the cheapest durability available: asynchronous, unfsynced,
best-effort.

## 11. What this adds to `chain/`

| module | change |
|---|---|
| `store/codec.py` | **written** — canonical binary encoding of every object; the same codec the wire needs |
| `store/db.py` | *new* — schema, migrations, the single-writer transaction |
| `store/archive.py` | **written** — append-only segments, retention profiles, opaque/structured sections, digests, prune by unlink |
| `store/snapshot.py` | *new* — export/import, range digests, root check against a header |
| `store/undo.py` | *new* — undo records, LIFO rollback, ceiling-driven retention |
| `store/high_water.py` | *new* — the fsync-first signing guard |
| `chain/seal.py` | `SealAccumulator.dump()` / `.load(values, dead)`; nothing else moves |
| `chain/state.py` | `ChainState.open(store)`; `apply_delta` returns its undo record |
| `chain/register.py` | `load`/`dump` — `MemberRecord.as_tuple` is already canonical |
| `chain/node.py` | takes a store; the mempool stays in memory |
| `chain/hardening/history.py` | branches and spent turns move into the store |
| `mq/ms6/core.py` | `_SealTree.append_leaf` must extend level 1 instead of rebuilding (§4.3) |

Nothing in `ceremony.py` changes. The ceremony moves signatures around and has no
durable state of its own, which is the same reason it survived the tiering and
the hardening untouched.

## 12. Open items

| item | why it is open |
|---|---|
| ~~The quadratic append~~ | **Closed.** `_SealTree` now grows by extension at every level. What remains is the flat ~1.4 ms per touched leaf, which is Python-interpreter-bound rather than algorithmic — the same wall `mq.md` reached on `matvec`. |
| The flat fold cost | ~1.4 ms per touched leaf caps a single node near 125 tx/s at ten million notes. That is an implementation ceiling, not a design one, and it is where a C or gmpy2 inner loop would pay. |
| Nullifiers never shrink | The one class-A term with no bound: correctness needs every nullifier ever, forever — 27 MB/day at 10 tx/s. Epoch-scoped nullifiers with note expiry would bound it and would change the note format. |
| Snapshot cadence | An era is 2,187 blocks and a snapshot is a full state copy. The cost of keeping them against the cost of not having them is unmeasured. |
| Archive incentives | Retention brings a fully verifying archive from 505 GB/day to 56 GB/day at 10 tx/s, which makes the role affordable but does not make it anyone's job. Still economics, still blank. |
| Fsync honesty | The high-water guard is only as good as the platform's fsync; on consumer SSDs with volatile write caches it is not a guarantee. A deployment that holds turns has to say what hardware it means. |
| Multi-process access | One writer is assumed. SQLite WAL gives an RPC reader MVCC, but the accumulator lives in the writer's memory and is not shared. |
| ~~Corruption detection~~ | **Closed for segments.** Every archive record carries a sha256 over its descriptors and payloads, and a damaged record is refused rather than served while its neighbours stay readable. The snapshot format still needs its per-range digests. |

Unchanged from part three: era genesis is a trusted setup.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/95df40f1-d87b-4c2b-b608-b8d036e66082
