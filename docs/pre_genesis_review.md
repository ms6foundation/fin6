# What has to be right before the chain exists

*A review of parts one through nine, ordered by what genesis makes permanent.*

Reviewed at `db7cf17`: ~16,300 lines outside the tests, 452 tests passing
(412 chain, 32 wallet, 8 client), ten design documents, four packages.

The request was for open items ranked two ways — by severity, and by whether
they are cheap now and expensive once the network is live. Working through it
turned up a finding that collapses those two axes into one, so that comes
first.

## 0. There is no later

The second axis assumes a network can adopt a change. This one cannot.

`FORMAT_VERSION` exists in two places — `store/codec.py` and `genesis.py` —
and both are *rejection* checks: a node refuses a document or a record from a
different version. Nothing negotiates. The handshake added in part nine
authenticates a peer's name; it does not carry a protocol version. There is no
activation height, no feature flag, no dual-format window, and
`genesis_design.md` says the rest out loud:

> **Genesis for a network that already exists** — adding an operator, retiring
> one, or changing a parameter is a governance event with no design at all yet.

So the honest ordering is not *cheap now / expensive later*. It is **cheap now
/ impossible later**, for everything that touches a byte any node hashes. A
format change on a live fin6 network today means stopping the network and
starting a different one, which is not an upgrade, it is a migration with a new
`chain_id`.

That makes **an upgrade path the highest-leverage open item in the repository**,
because it is the one that converts every item in class B below from permanent
to merely difficult. It is also the cheapest thing on this page to start: a
protocol version in the handshake and an activation height in the header are
perhaps a day's work, and they have to exist *before* the history they will
govern.

## 1. How things are ranked

**Severity** is what happens if it is wrong:

| | |
|---|---|
| **Critical** | funds can be taken or created, or history can be rewritten |
| **High** | the network stalls, diverges permanently, or a privacy claim fails |
| **Medium** | degradation, operational pain, a claim that has to be withdrawn |
| **Low** | debt |

**Class** is when it can be fixed:

| | |
|---|---|
| **A · baked** | its value goes into the genesis document, or into history signed under it. No later fix exists at all — only a new chain. |
| **B · format** | changes bytes a node hashes. Fixable live *only after* §0 exists; permanent until then. |
| **C · protocol** | behaviour, not format. Doable on a running network with coordination. |
| **D · operational** | tunable whenever, by whoever runs the node. |

One item sits outside the scale, and no ordering fixes it: **none of this has
been reviewed by anyone outside the project**, and the constructions are novel.
Everything below assumes the primitives do what their documents claim.

## 2. Class A — decide before genesis, or live with it forever

### A1 · The shipped genesis config is built on the insecure preset · **Critical**

`config/genesis-7.json` — the only genesis document in the repository — carries
the `demo` parameters:

```
n_note 8, note_folds 4   →  4 random blinders
range_bits 12            →  no note may hold more than 4,095 units
default_backend ssh5
hardening: production    (70,000 turns, width 32, 2^17 tree)
```

The project's own README says of exactly this shape: *"the `DEMO` preset is
deliberately insecure: 8 note coordinates of which 4 are random puts the
note-commitment MQ instance inside Gröbner range."* The document pairs it with
**production** hardening, which is the combination most likely to be mistaken
for a launch file. `fin6 genesis new` defaults to `--preset local`, which is
also demo-sized.

`STRONG` is the answer and costs 0.33 s a transaction. The decision is a launch
decision, and the note commitment is what the entire ledger's binding rests on.

*Fix now:* choose the preset, regenerate the document. Minutes.
*Fix live:* impossible. Every commitment ever made is under those parameters.

### A2 · `verify()` checks parameter names, never their values · **Critical**

The document above returns `ok: True`, **zero problems and zero caveats**.
`GenesisDocument.verify()` is careful and thorough — canonical round-trip,
roster uniqueness, ratification signatures, the turn map covering the pool,
the supply summing to its declared total — and it checks that the parameter
*names* are the ones this build knows. It never asks whether the values are
safe.

This is the cheapest fix on the page and the one with the best ratio: a dozen
lines that refuse, or at minimum caveat, a document whose MQ instance is inside
Gröbner range or whose `range_bits` cannot express the amounts a financial
chain deals in. The existing caveat mechanism is exactly the right vehicle —
it already reports the three things the design names and the code has not
reached, so nobody mistakes silence for a check. Right now, silence is what a
weak parameter set gets.

*Fix now:* an afternoon. *Fix live:* the document is already signed.

### A3 · The quorum signature scheme is a placeholder · **Critical**

Ed25519 signs every attestation, and the rest of the stack is post-quantum by
construction. `private_chain_design.md` has listed this as open since part one,
and part nine did the half that could be done without choosing: a certificate
is now `signers` plus `signatures` against the roster rather than a list of
self-describing attestations — 84 bytes a seat against 137, and the seam an
aggregate scheme drops into.

Two reasons this is class A rather than class B. Retroactivity: a scheme swapped
in later does not protect the history already signed, and history is what
hardening exists to make expensive to unsay. And scale: **54.7 KB of
certificate for a 667-seat quorum**, every epoch, before any payload. An
aggregate scheme collapses that to 6.8 KB, or about 0.2 KB if `signers` becomes
a bitmap over a canonical seat order — which needs that order **committed in the
header**, and that is a format change (B2).

The blocker is honest and not technical: threshold BLS means a pairing library,
and this repository has one runtime dependency.

*Fix now:* a dependency decision plus the header field. *Fix live:* the new
scheme cannot vouch for the old signatures.

### A4 · Era 0 is a trusted setup, and the distribution is the security parameter · **Critical**

`max fork depth = attacker's unspent turns / width` is a bound rather than a
probability, which is the best property hardening has. It is also the reason the
turn map is not an operational detail: **an attacker's share of the pool is the
rewrite ceiling**, exactly. 70,000 turns across 200 machines is 200 points of
failure, and `hardening_design.md` still calls the distribution *"the most
important unanswered question."*

Era 0's holder map is in the genesis document and era *n+1* is authorised by
era *n*, so the chain of eras is anchored to a setup nobody can audit after the
fact. There is no mechanism that verifies a holder actually controls what it
claims, nor that two holders are not the same operator.

*Fix now:* a contributed-leaves ceremony for era 0, or at least an attested
holder map. *Fix live:* era 0 already authorised everything after it.

### A5 · Genesis issuance proves nothing, and its openings are public · **High**

Two separate problems that arrived from opposite directions.

The supply is *issued*, not minted: `verify()` checks the declared total against
values in the document, which only a party holding the openings can do. Nobody
else can check that the chain started with the money it says it did.

And since part six made genesis reproducible across processes, note randomness
is derived from the document digest — so **every genesis opening is derivable by
anyone holding the document.** That was the right fix for the bug it addressed
(seven nodes computing seven different genesis states) and it makes the initial
holdings transparent to everyone, permanently.

A genesis mint transaction — the design's own §2 answer — makes the supply
checkable by anyone and the openings private. It has never been built.

*Fix now:* build the mint. *Fix live:* the openings are already out.

### A6 · The address format is at its last cheap moment · **High**

`wallet_design.md` is precise about what is built and what is not. Diversified
addresses and per-output disclosure keys both ship and **neither touches the
chain**. Era-derived viewing keys do: they fix the part diversifiers only
mitigate — *a key handed to an auditor today still opens payments made to that
address tomorrow* — and they change the address encoding.

The same document also flags the caveat worth respecting: tweaking X25519
public keys needs care about scalar clamping, so the clean construction does the
point arithmetic in Ed25519 form and wants a reviewer.

*Fix now:* one format change, before any address is published. *Fix live:* every
address in circulation is the old shape.

### A7 · `hardening/wots.py` is a teaching implementation · **High**

The README says so. One-time signatures are what make a stamp unforgeable and a
double-stamp self-incriminating; a subtle bug in the implementation is a
retroactive forgery surface across all of history. RFC 8391 exists and is
reviewed.

Swapping implementations is compatible if the scheme and parameters match, so
strictly this is class B — but era 0's leaves are committed at genesis, so the
parameters are not negotiable afterwards.

*Fix now:* adopt a reviewed implementation. *Fix live:* possible only if the
parameters happen to match.

### A8 · The ratification threshold is circular · **High**

The document declares how many ratifications the document needs. Something has
to say how many founders are enough, and that something is governance, not code
— which is §0 again, arriving from a different direction.

## 3. Class B — format changes, permanent until §0 exists

| | item | severity | why |
|---|---|---|---|
| B1 | **Faults are provable and unusable** | High | `Seat.catch_lazy` produces signed evidence that an attester did not check — an attestation over a block that does not validate. `GridRegister.apply` takes a `faulted` set. The network path passes none, because agreeing about a fault means **carrying it in the block**. So the standing system, apprenticeships and all, is inert against the one fault the code can now prove. |
| B2 | **No canonical seat order in the header** | Medium-High | The prerequisite for a signer bitmap, and therefore for A3's best case: 0.2 KB a certificate instead of 6.8 KB. |
| B3 | **Cross-partition transactions have no home** | High | A spend touching two partitions can be included by no grid. It does not bite today only because `Wallet.send` spends exactly one note — and multi-note spends are a named open item, so shipping them makes this live. |
| B4 | **The register is one roll late** | Medium | A certificate is checked against a register whose roll has already been applied, so a client's quorum figure can be off by one across a founding. |
| B6 | **Nothing binds a connection after its hello** | High | The handshake authenticates a frame, not a stream. Closing it needs either a transport or an agreement key per validator — and a key in the roster is a genesis decision, which is why a transport-layer answer sits in class B rather than class D. |
| B5 | **The nullifier set may not need to exist** | Medium | Part nine's finding: the spend graph is public, so `tin.cm not in utxo` already refuses a replay before the nullifier check is reached. Keeping, scoping or dropping it is now a free choice — but `nf_root` is in every header, so making it is a format change. |

**B1 deserves the emphasis.** Everything in parts two and five — attendance,
standing, the forty-ceremony apprenticeship, forgiveness counters — is
machinery for punishing behaviour the network cannot currently record.

## 4. Class C — protocol work, doable on a live network

| | item | severity | why |
|---|---|---|---|
| C1 | **View change over a real network** | High | In-process it is a retry loop with a fresh seed. With timeouts and partial delivery it is a protocol, and it is not designed. This is the liveness path for a dead leader. |
| C2 | **The supreme grid is a global stall point** | High | If it aborts, nothing finalises anywhere that epoch. |
| C3 | **Reorg past the undo ceiling diverges permanently** | High | Undo records are kept to `retention_depth` — 729 blocks at a third of the pool. Beyond it a node that cannot roll back diverges from one that can, with no reconciliation path but a snapshot. |
| C4 | **Grids never merge** | Medium-High | Split works and founding cohorts keep their standing. A network that shrinks keeps grids it cannot fill, and founding seating is permanent because merge does not exist. |
| C5 | **Apprentice density stalls a grid** | Medium | Apprentices hold seats and cannot make quorum. Admission needs a rate limit tied to attester count. |
| C6 | **No peer discovery** | Medium | Peers come from the roster and `net.toml`. A network that grows needs joiners to find seats. |
| C7 | **Body window is 21 minutes** | Medium | Past it, catch-up falls back to `getsnapshot`, which costs the serving node a full state copy on demand and is one frame rather than the chunked ranges `store/snapshot.py` was built for. |

## 5. Class D — operational, any time

Rate-limit thresholds and the throttle tolerance for a wallet shipping a broken
prover · penalty-box eviction policy · whether shedding is observable to a
client · snapshot cadence · archive incentives · fsync honesty on consumer SSDs
· the 1.4 ms flat fold cost (an interpreter ceiling, ~125 tx/s at ten million
notes) · sample rates at the upper tiers · locality tags being self-declared.

And the one that keeps recurring across three documents: **nothing measures any
of this.** "Seven nodes agreed for an hour" and "the node did not fall over"
are not tests. The chaos stages need assertions — a partition heals within N
epochs, a killed node rejoins at the right height, the decide deadline is met
while a flood runs — or part six and part nine are hypotheses.

## 6. Before the network opens, not before it launches

Two items are safe while the roster is permissioned and fatal if it is not:

- **Apprenticeship is a rate limiter, not Sybil resistance.** Forty ceremonies
  costs time, not identities.
- **Locality tags are self-declared.** A node claiming to be everywhere-adjacent
  widens its own candidate set.

## 7. The order I would work in

1. **A protocol version and an activation height** — because everything below
   costs less once it exists, and it cannot be added retroactively.
2. **A1 and A2 together** — pick the preset, and make `verify()` refuse the ones
   that should never launch. Hours, not days.
3. **A3's dependency decision** — it gates the header field, and the header
   field is a format change.
4. **A4, A5, A6, A7** — the four other things genesis makes permanent.
5. **B1** — turn the fault machinery on, while the block format is still free.
6. **C1 and C3** — the two ways a live network stops being one.
7. Everything else, in the order operations demands it.

The three findings in §2 that came out of this pass rather than out of the
existing documents — the config, the blind spot in `verify()`, and the absence
of any version negotiation — are all in the first two steps, and none of them
takes more than a day.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/0774da90-65d8-4c51-9fa1-e7810216cdbf
