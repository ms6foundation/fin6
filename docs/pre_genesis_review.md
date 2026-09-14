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

> **Resolved.** The preset is now `LAUNCH`, and it is neither `DEMO` nor
> `STRONG`: measurement said `STRONG` was not what its own docstring claimed
> (44 blinders against the 62 `mq/mq.md` sizes for 2^128, and 8 fold rows
> against the 2 it recommends — and the fold count sets the security loss
> directly, since `m - h = n_folds + opened - 1` does not shrink as *n* grows).
> `LAUNCH` is 62 blinders, 2 folds, `range_bits=48` — 0.59 s to prove, 0.32 s
> to verify, 378 KB a transaction — and it ships **one** proof backend, for the
> reason in A9. `config/genesis-7.json` is regenerated from it.

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

> **Resolved.** `ChainParams.assess(tiers=…)` is `mq/mq.md`'s closing mandate
> — *"treat these as a floor for rejecting bad parameters, not a guarantee"* —
> written down: Gröbner range and soundness bits are problems, a short-but-not
> absurd hidden block and a high fold count are caveats, and four
> internal-consistency checks that nothing anywhere made (a `default_backend`
> no wallet proves in, a tier verifying with a backend nobody makes, a quorum
> below two thirds, a founding cohort that cannot tolerate a fault) are
> problems. `GenesisDocument.verify()` calls it.
>
> The awkward part was that the test suite and the runnable demo *need*
> undersized commitments to finish in a second, and an off switch on the check
> is an off switch a founder can reach for. So the document says what it is
> **for**: `purpose` is `"launch"` or `"test"`, it sits inside `body()`, and
> therefore inside the hash the chain id is and inside every ratification. A
> test document cannot be quietly promoted — changing the word changes the
> chain. A file with no `purpose` field reads as `"launch"`, which is the safe
> direction: it gets held to the floor rather than excused.

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

> **Resolved, in the half that genesis makes permanent.** Written up in
> `docs/quorum_signature_decision.md`. The decision is *not threshold BLS now*:
> it needs a pairing library against this repository's one runtime dependency,
> and BLS12-381 is not post-quantum either, so it buys aggregation rather than
> the property the rest of the stack was chosen for. What ships is the
> preparation, which is the part that is a format: `QuorumCert.scheme` names the
> scheme and is bound into the certificate root (an unknown scheme is refused,
> not attempted); `NetworkBlockHeader.seats_root` commits each grid's seated
> membership, sorted, so a bitmap has an order to index into that the producer
> cannot pick per reader; and `compact_form`/`expanded_form` already encode the
> seats as a bitmap, with an identical root in both spellings.
>
> Two corrections to the figures above, both from measuring. The certificate is
> **56.2 KB** at 667 seats, and the bitmap takes it to **47.1 KB** — the 0.2 KB
> was always the *aggregated* number, and the seat encoding alone does not get
> near it, because what is left is one signature a seat. And the committed order
> closed a gap that was nothing to do with size: `verify()` checked signatures
> against the roster, but quorum is a fraction of a *grid*, so a signature from
> any validator in the network counted toward any grid's quorum. `verify(…,
> seats=)` now refuses a signer that does not sit in the grid.
>
> Left on purpose: the compact form is not yet the default wire encoding, since
> the light client, the archive and the snapshot reader all verify certificates
> with no membership in hand. That one is cheap now *and* cheap later — the root
> is the same in both encodings — which is why it is not in this change.

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

> **Built: the ceremony, not the attested map.** `chain/hardening/contrib.py`
> and `chain/hardening/ceremony.py`. Each holder generates the keys for its own
> contiguous slice from its own secret, publishes the public leaves, and — in a
> second round, after the tree is assembled — signs a claim to exactly that
> slice **naming the resulting era root**, with the key the roster names it by.
> A holder that signed in round one would be vouching for its own slice in
> isolation, which is the thing that needs no vouching.
>
> `GenesisDocument.era0` carries the root, the public randomiser, and the signed
> claims, inside the bytes the chain id hashes. `verify()` checks that the
> slices cover the pool exactly once, that every holder is a founder, that every
> claim verifies under the roster key, that the era matches the hardening
> parameters and the signature scheme, and that the public seed is the one
> *derived* from the network and the first seed rather than one somebody chose.
> A launch document without a ceremony is refused outright.
>
> The concentration is now a number in the output rather than an assumption:
> the largest holder's share, the rewrite ceiling it implies in blocks, and the
> same in hours. A holder above a third of the pool is a **problem**, not a
> caveat — `max_fork_depth` is a bound, so that is not a risk appetite. The
> shipped seven-holder document: **14% each, 312 blocks, 1.7 h**.
>
> Nobody can sign outside their slice, and that is not a rule that is enforced
> — it is a key that does not exist. What none of it proves is that two holders
> are not the same operator: nothing cryptographic can, so the claim is signed
> and named rather than assumed, and `verify()` says so every time.
>
> The other half — that the digests are really public keys — needs the
> published leaves, and `ceremony.verify_transcript` is that check. The document
> commits to the digests, so the two halves cannot disagree without one failing.
> `python3 -m chain.hardening.ceremony` runs the whole thing for the shipped
> roster: 70,000 WOTS key generations, 19 s across four processes.

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

> **Built.** `chain/mint.py` and `wallet/genesis_mint.py`. A mint is a
> transaction shape with **no inputs** — the existing system, with the guard
> relaxed: the sum row reads `-sum(outputs) = v`, so a verifier holding the
> declared total learns that the outputs add up to it and learns nothing else,
> and the range rows say each is a real amount rather than a negative that
> cancels. What authorises money appearing from nowhere is not a signature over
> a note, because there is no note to sign yet; it is the document, and the
> founders ratify that.
>
> The commitments are in the document, so every node still computes the same
> genesis state — which is what deterministic issuance was for — while the
> openings are sealed to their holders like any other payment's. A node boots
> the shipped document, holds five commitments, can check the total against the
> published artifact, and can open none of them. The treasury opens its own
> with `wallet.genesis_mint.claim` and nobody else's.
>
> Measured at launch parameters: **1.8 s to prove, 0.85 s to verify, a 720 KB
> artifact** for five notes. The artifact is published rather than carried,
> committed by digest, exactly as era 0's leaf transcript is.
>
> The document and the mint commit to each other without a cycle: the document
> holds the artifact's digest, and the artifact binds to `mint_context()` —
> this document *without its mint block*. A launch document that issues is now
> refused, and a minted one that also lists values is refused, because a list
> of amounts beside the commitments is the disclosure the mint exists to avoid.
>
> One consequence worth stating: `chain/demo_genesis.py` can no longer spend
> the shipped document's money, because no process holding only the document
> can. It runs its epochs on a test document now, and says so.

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

> **The format change is made; the construction is not.**
> `docs/address_format_decision.md`. Working through it turned up why this is
> not a scheme with an extra parameter: X25519 clamps, so a tweaked scalar
> cannot be used with the library at all, and a Montgomery public key is the
> x-coordinate only, so the tweak cannot even be computed on it. Era-derived
> viewing is a **different key agreement wearing the same thirty-two bytes** —
> and the failure mode of a silent mismatch is money that arrives on chain and
> cannot be read, with nothing saying why.
>
> So an address now says which scheme its keys are in: version 3 carries a
> scheme byte inside the checksummed body, `x25519-static-view` is what ships,
> `ed25519-era-rotating-view` is reserved, and a build that meets a scheme it
> does not implement **refuses the address** instead of paying into it. When
> the construction lands it is a value plus a wallet, and the address format
> does not change again.
>
> The construction itself wants the reviewer `wallet_design.md` asks for.
> Hand-written Edwards arithmetic, unreviewed, on the path that decides whether
> a payment can be read, is not an improvement on the problem it solves.

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

> **Resolved as a seam, not a swap.** `docs/wots_decision.md`. Adopting RFC 8391
> means a dependency or a second hand-written construction, and this chain's
> step function is WOTS-T style rather than RFC 8391's, so a byte-compatible
> swap was never available. What ships instead makes the swap *checkable*: the
> scheme has a name (`wots.SCHEME`), the name is a `HardeningParams` field and
> therefore inside the chain id, `EraSpec` carries it into the era's identity,
> and `chain/hardening/vectors/wots.json` pins known answers a replacement must
> reproduce byte for byte. A build whose implementation answers to another name
> refuses to construct hardening parameters rather than producing leaves nobody
> else's turns match.
>
> Writing the vectors found a live bug: `sign` accepted a message that was not
> the 32-byte digest and produced a short signature that no verifier could
> accept, with the `ValueError` swallowed into a `False`. Every caller in the
> chain passes a digest, so it was latent — but it is precisely the class of
> defect A7 is about, found by the cheapest available means. Fixed.

### A8 · The ratification threshold is circular · **High**

The document declares how many ratifications the document needs. Something has
to say how many founders are enough, and that something is governance, not code
— which is §0 again, arriving from a different direction.

> **Bounded, and the residual named.** The *range* was never a governance
> question, and leaving it unbounded meant a seven-node document could be
> founded by one signature and still verify clean. `verify()` now refuses a
> threshold above the roster (unreachable), or below the chain's own quorum
> rule — a set of founders too small to finalise a block cannot be enough to
> agree what the chain is. And a document marked `purpose: launch` must be
> ratified by **every founder it names**: before a chain exists there is no
> history to protect and no cost to waiting, so a founder that will not sign is
> a founder that should not be in the roster, and redrawing the roster is free
> now and impossible later. `config/genesis-7.json` is 7-of-7.
>
> What no rule settles is who is in the roster at all — unanimity among seven
> is unanimity among whoever chose the seven. `verify()` says so as a caveat
> rather than leaving the silence to be read as a check.

### A9 · Three proof backends do not fit through the client frame · **High**

Found while measuring for A1. At launch parameters a transaction carrying all
three backends is **3,265 KB**. `CLIENT_MAX_FRAME` is **1 MB**. The ceiling was
sized against `DEMO`, where the same transaction is 568 KB, so it has never
been hit — and nothing in the repository relates the two numbers.

At one tier this is not a live problem, because one tier needs one backend and
`LAUNCH` ships one. It becomes one the moment somebody turns on the upper
tiers, which is precisely a genesis or succession decision rather than a
configuration change. `assess()` now raises it as a caveat whenever a document
carries backends no tier verifies, naming both numbers.

*Fix now:* free — it is a choice about the proof policy.
*Fix live:* the frame ceiling is a wire-format constant; raising it is a
protocol version, which after step 1 is at least possible.

## 3. Class B — format changes, permanent until §0 exists

| | item | severity | why |
|---|---|---|---|
| B1 | ~~**Faults are provable and unusable**~~ **Done** | High | `Seat.catch_lazy` produced signed evidence that an attester did not check — an attestation over a block that does not validate. `GridRegister.apply` takes a `faulted` set. The network path passed none, because agreeing about a fault means **carrying it in the block**. So the standing system, apprenticeships and all, was inert against the one fault the code could prove. See §3.1. |
| B2 | **No canonical seat order in the header** | Medium-High | The prerequisite for a signer bitmap, and therefore for A3's best case: 0.2 KB a certificate instead of 6.8 KB. |
| B3 | ~~**Cross-partition transactions have no home**~~ **Done** | High | A spend touching two partitions can be included by no grid. It did not bite because `Wallet.send` spent exactly one note — and multi-note spends were a named open item, so shipping them made this live. Shipped, with the three answers in §3.2. |
| B4 | ~~**The register is one roll late**~~ **Done** | Medium | A certificate was checked against a register whose roll had already been applied, so a client's quorum figure could be off by one across a founding. The figure now travels in the header — §3.3. |
| B6 | ~~**Nothing binds a connection after its hello**~~ **Done** | High | The handshake authenticated a frame, not a stream. It needed neither a transport nor an agreement key: a MAC needs a shared secret and a *signature does not* — §3.5. |
| B5 | ~~**The nullifier set may not need to exist**~~ **Decided: keep** | Medium | Part nine's finding: the spend graph is public, so `tin.cm not in utxo` already refuses a replay before the nullifier check is reached. Measured at 0.3% of a proof and kept as a second independent record, with the redundancy turned into a tripwire — `docs/nullifier_decision.md`, §3.4. |

**B1 deserves the emphasis.** Everything in parts two and five — attendance,
standing, the forty-ceremony apprenticeship, forgiveness counters — is
machinery for punishing behaviour the network cannot currently record.

### 3.5 · B6, resolved: the roster's own keys bind the stream

The premise was that closing this needed a transport (TLS, Noise) or a shared
secret to MAC each frame with, and that the roster holds Ed25519 *signing* keys
rather than keys for agreement — so neither was available without new key
material or a new dependency.

The first half is right and the conclusion was wrong. **A MAC needs a shared
secret; a signature does not.** The roster's keys sign frames perfectly well,
and the only real question was cost — which is a measurement rather than an
argument:

| | |
|---|---|
| sign | 25 µs |
| verify | 79 µs |
| sha256 of the largest frame anybody sends (664 KB) | 0.27 ms |

At the 132 directed messages a seven-node epoch actually carries, that is 3.3 ms
of signing and 10 ms of verifying per node per **19.75-second** epoch.

So a hello now opens a *session* — `h(chain_id, from, to, epoch, nonce)`, which
both ends derive from the hello itself, nothing exchanged — and every frame
after it carries a sequence number and a signature over that session. What it
closes: **injection** (no signature without the key), **takeover** (an attacker
holding the socket cannot produce the next signature), **replay** and
**reordering** (strictly increasing sequence), and **splicing from another
connection** (the session is in the signature). A frame that fails ends the
connection, because a stream somebody else is writing into is not a stream worth
reading.

Two deliberate limits. A *gap* in the sequence is accepted — the path dropping a
frame is a denial of service, not a forgery, and refusing everything after it
would turn one lost packet into a dead seat. And **confidentiality is
untouched**: frames are still plaintext, so the path still sees who talks to
whom and how big a submission is. The ledger's privacy is in its proofs, not its
transport — but metadata is not nothing, and a deployment that cares still wants
a tunnel. What it no longer needs one for is integrity, which was the
load-bearing half.

### 3.4 · B5, decided: keep it, and make it earn its keep

Written up in `docs/nullifier_decision.md`. The finding is right — with a
public spend graph the UTXO tombstone is what stops a double spend, and the
nullifier is a second record of something the first already knows — but the
measurement decides it: at `LAUNCH` parameters the nullifier is **one row of
305**, 0.43 ms of a 600 ms proof, about **0.3% of a 341 KB transaction**, one
marker and one leaf a spend. Dropping it would move the routing rule onto
commitments, change what a wallet watches, and take two fields out of every
header, for a third of one percent.

So it stays, and the redundancy stops being ballast: `utxo.spent_count ==
nullifiers.size`, at every height, for ever. A spend tombstones a leaf in one
structure and appends to the other, and nothing else touches either. Two
integers, checked on the path that moves them, and a disagreement raises
`LedgerInconsistent` and stops the node — because a ledger whose own two records
of a spend disagree cannot tell locally which one is true, and carrying on means
computing roots nobody else will reproduce.

That is what a second record is *for*: a bug in the UTXO accumulator is
invisible to the UTXO accumulator.

### 3.3 · B4, resolved: the quorum travels with the block

A quorum is a fraction of the attesters, and standing moves. The roll of epoch
e-1 is applied when block e lands, so by the time anyone checks block e's
certificate the register has standing the ceremony did not have; across a
founding the attester count differs and a derived figure is wrong — in either
direction, and the dangerous direction is *too low*, which accepts a
certificate that was short. The light client's docstring had carried this as a
known residual since part eight.

The fix is that the number stops being derived. `CeremonyBlockHeader.quorum` and
`NetworkBlockHeader.quorum` carry what the ceremony required, inside the block
hash. A full node checks the claim against the register it ran the ceremony
under and refuses a mismatch — so among full nodes it is verified rather than
announced — and the super tier, the snapshot check and the light client all read
it instead of asking a register that has moved. A leader that understates its
own quorum gets its block refused by every honest seat.

The residual worth naming, in the light client's own words: the register it
fetches is still the one after the roll, so what it can say about *standing* is
a step stale even though the quorum figure no longer is.

### 3.2 · B3, resolved: multi-note spends, and the grid they belong to

Closing this meant shipping the thing that makes it live. `TxSystem` has always
handled *k* inputs; `Wallet.send` refused to use more than one and said so, so
a wallet holding change could be unable to spend what it plainly had. With two
inputs, the two can live in two different grids.

A note is spendable in exactly one grid — that is what makes a cross-grid
double spend structurally impossible rather than merely detectable — so a
transaction spending notes from two grids would need two grids to agree about
it, which is the thing partitioning exists to avoid. Such a transaction is not
rejected so much as **homeless**, and a homeless transaction used to be
accepted by a node and then sit in mempools until it was forgotten.

Three answers, and the first is the real one:

1. **The wallet does not build one.** `Wallet.select` chooses inputs from a
   single partition, largest-first, and returns which. When no single grid
   holds enough it says so, prints the spread, and names the remedy — that is a
   different failure from being poor and it gets a different message.
2. **A node does not take one in.** `_offer_tx` refuses before authentication
   and counts it in `status` as `homeless`, so a wallet somewhere building
   unroutable transactions is visible rather than mysterious.
3. **Change comes home.** The partition is a hash of the note and `rho` is
   randomness the payer draws anyway, so `note_in_partition` aims it for a few
   hashes and no information — a note's partition is public from the moment it
   is spent. Without that, a wallet's notes scatter one payment at a time until
   a balance that is plainly sufficient can no longer make a payment.
   `Wallet.consolidate` is the escape hatch for a balance that has already
   scattered: it gathers one grid's notes into one note *in that grid*.

Two things surfaced while building it. `select`'s comment said smallest-first
"keeps the note count down", which is the opposite of what smallest-first does
— covering 55 from 10, 50 and 100 takes two notes ascending and one descending.
The rationale was right and the sort was backwards; it is largest-first now.
And a **founding can make a transaction in flight homeless**, since K is the
routing rule: inputs that shared a partition at K can split at K+1.
`reroute_mempools` already drops those rather than stranding them, and there is
now a test that says so out loud.

### 3.1 · B1, resolved: a fault that costs something

The obstacle was never the plumbing. It was that *"this block does not
validate"* is usually a statement about the **ledger** — an input already
spent, a tip that has moved — and a node applying block h+1 next month cannot
re-run that check. Equivocation escaped it because its evidence proves itself:
two signed proposals, one height, one leader, and anybody with the bytes can
see it.

`chain/faults.py` gives laziness the same property by splitting invalidity in
two. **Self-evident**: the block's own bytes contradict each other — a
`tx_root` that is not the root of the transactions under it, a delta that is
not the delta those transactions make, a transaction that does not
authenticate or is in the wrong partition, a digest that does not match what it
commits to. Checking any of these needs the block and the chain parameters and
nothing else, so a verifier a year later reaches the verdict the seat reached
at the time. **Contextual**: everything about the ledger, which is objective
then and not re-derivable afterwards.

An attester that signed a self-evidently flawed block either did not look or
looked and lied. That is a `lazy_attestation` report: it carries the block in
`subject`, `substantiated()` re-runs the check rather than believing the
reporter, `accused()` names exactly the seats whose attestations are attached,
and `faulted_from` feeds them to `GridRegister.apply`, which suspends them —
permanently, since suspension is not self-healing.

The other half is the one that took the care. A report about a block that is
*fine* is signed, well-formed, and convicts nobody, because the check is
re-run and passes. A block that failed only a contextual check produces names
in the log and **no report at all**: a claim a validator cannot re-check is a
claim a leader could invent about anyone it disliked, and a block carrying one
is refused outright.

Two costs, both named rather than hidden. A report carries the block it
convicts, so `MAX_EVIDENCE_BYTES` (512 KB) is where reporting stops and the
fix becomes a succinct fraud proof naming the one contradiction — a design,
not a field. And `substantiated()` needs the chain parameters; without them a
report is *unproven rather than false*, so a caller that cannot check says so
instead of voting.

Also fixed on the way: `Seat.catch_lazy` was defined twice in the same class,
so the first definition had never run.

## 4. Class C — protocol work, doable on a live network

| | item | severity | why |
|---|---|---|---|
| C1 | ~~**View change over a real network**~~ **Done** | High | In-process it is a retry loop with a fresh seed. With timeouts and partial delivery it is a protocol, and it was not designed. This is the liveness path for a dead leader. Designed and built as part eleven — `docs/view_change_design.md`, §4.2. |
| C2 | **The supreme grid is a global stall point** | High | If it aborts, nothing finalises anywhere that epoch. |
| C3 | ~~**Reorg past the undo ceiling diverges permanently**~~ **Done** | High | Undo records are kept to `retention_depth` — 729 blocks at a third of the pool. Beyond it a node that cannot roll back diverged from one that can, with no reconciliation path but a snapshot, and *silently*. See §4.1. |
| C4 | ~~**Grids never merge**~~ **Done** | Medium-High | Split worked and merge did not exist, so a network that shrank kept grids it could not fill — each owning a nullifier partition nothing else may include. `plan_merges` is the other half, and it renumbers the partitions — §4.6. |
| C5 | ~~**Apprentice density stalls a grid**~~ **Done** | Medium | Apprentices hold seats and cannot make quorum, and admission was unbounded — so the 40-ceremony gate bounded nothing a grid cares about. A grid now runs at most `admit_num/admit_den` of its attester count in apprenticeships at once — §4.5. |
| C6 | ~~**No peer discovery**~~ **Done** | Medium | Peers came from the roster and `net.json`, so a network that grows needed every machine's file edited. Signed address records, gossiped — §4.4. |
| C7 | ~~**Body window is 21 minutes**~~ **Done** | Medium | Past it, catch-up falls back to `getsnapshot`, which cost the serving node a full state copy on demand and was one frame rather than the chunked ranges `store/snapshot.py` was built for. Both halves fixed — §4.3. |

### 4.6 · C4, resolved: the topology can shrink

`Topology.needs_merge` had been in the file since part four and **nothing ever
called it**. Splitting worked, so the topology could only grow; a grid whose
seats went quiet kept its name, its register and — the part that matters — its
nullifier partition. A partition is not a shard of traffic, it is a set of
notes that *only that grid may include a spend of*. So an unfillable grid is a
slice of the ledger nobody can spend in, held open indefinitely.

`plan_merges` mirrors `plan_foundings` — derived from committed state, carried
in the block, re-derived by every seat, at most one an epoch — with four
guards. A merge needs a sibling **in the same region** (locality is the point
of the assignment; a region whose only grid empties keeps it); one whose
combined size stays under the split threshold (or the network churns K every
other epoch: fold, overflow, found, fold); more than one grid in total (a
single grid is the degenerate case the tiers collapse onto, not an error); and
an epoch with no founding, because both move K and doing them together re-homes
every transaction in flight twice for no gain. The target is the smallest
sibling, ties broken by the previous block's hash, so the node assembling the
block cannot choose where a grid's members land.

Three things that were not obvious before writing it:

**A grid does not shrink by losing rows.** Nothing removes a node from a
topology — there is no departure path, and members only ever arrive or move to
found a child. So viability cannot be measured by membership; `needs_merge` now
takes the count of members that still *hold a seat*, which the topology cannot
know and the register does. A grid of nine of whom seven are suspended is
exactly the case this rule exists for, and it is the case the old rule could
never see.

**`release` cannot be reused, and that is the whole safety argument.** A
founding moves a selected cohort, so `GridRegister.release` refuses
apprentices and the suspended — an apprentice would arrive unable to vote, and
a suspended member would arrive with its suspension laundered into a fresh
register. A merge moves *everyone*, so it must take exactly those. `absorb` is
the separate primitive: apprentices keep their served time, suspensions and
fault lists come across intact, and `founded_from` records that the standing
was not earned here. Merging a register that is an epoch out of step is
refused rather than reconciled — it would credit or cost somebody a ceremony.

**The partitions have to be compacted, and that costs a promise.**
`GridSpec.index` *is* the partition and `n_partitions` is the number of grids,
so removing a grid without renumbering leaves the top partition owned by
nobody and its notes unspendable forever. The survivors are therefore
renumbered in index order, which falsifies `found_grid`'s claim that "a grid's
identity never silently becomes a different partition" — across a merge it
does, for every grid above the one that went. Survivable, because K moving
re-homes every transaction either way, but a stronger statement than the
founding path makes and now written where the renumbering happens rather than
in a changelog.

One storage detail, found by asking what a node sees after a restart: the
register write is an upsert, so a merged-away grid survived in the store and
came back from the next `load_registers` — holding members who by then sat in
another register too. `commit(retired=…)` deletes its register, roll and
certificate rows in the same transaction as the block that merged it.

### 4.5 · C5, resolved: the gate is per node, the rate is per grid

The 40-ceremony gate was written down as the cost of capturing a grid. It is
not, on its own, a cost of anything: **an apprenticeship served in parallel is
served once.** An adversary admitted a hundred nodes on one day, waited out one
gate, and a hundred attesters appeared in the same ceremony. Nothing in
`TierWorld.admit` counted, so the grid's composition could change completely in
a single step and the "40 ceremonies of visible apprenticeship per node" the
locality docstring promised was forty ceremonies *total*, however many nodes
walked through together.

The missing half is a rate. A grid runs at most `admit_num/admit_den` of its
own attester count in apprenticeships at once — a quarter, by default, and
never fewer than one, because a region with a single grid whose cap rounded to
zero would be closed to newcomers permanently and a network nobody can join is
a club. `Topology.assign_newcomer` takes the predicate and *narrows* the
candidate list with it; the seed still picks among what is left, so a newcomer
still cannot choose its grid by waiting for the others to fill, and a region
with no room refuses rather than spilling the newcomer into another region —
locality is the point of the assignment and is not negotiable for convenience.

What this does and does not buy, stated plainly: the population that eventually
promotes an intake is the population that authorised it, and reaching parity
with eight honest attesters takes four gates instead of one. It bounds the
*rate*, not the total — growth is geometric, because a promoted node counts
toward the next cap — so a patient adversary still gets there. It gets there in
the open, over k apprenticeships, which is the difference between a takeover
somebody can see coming and one that lands in a single ceremony.

Two details worth naming. Suspended members are not counted as apprentices:
counting them would let an adversary close a grid to honest newcomers by
getting its own nodes suspended, which is a fault that *buys* the faulter
something. And the rate is an exact ratio rather than a float, like the quorum
fraction beside it — a float has no canonical encoding in the store codec or
the genesis document, and a consensus parameter every node must round
identically has no business being approximate. Adding it re-digested
`config/genesis-7.json`, so the founders re-ratified and the genesis mint,
which binds to `mint_context()`, was minted again.

### 4.4 · C6, resolved: one address is enough

What keeps this small is that **the identities are already settled**. The
genesis document names every seat and its key, so discovery is only ever about
*addresses*: a record signed by a key the roster does not name is not an unknown
peer, it is noise. There is no sybil question to answer, because nothing here
admits anybody — `Topology.assign_newcomer` and the register decide membership,
and an address record says *where*, never *who*.

So the whole of it is one signed statement — "I am `fin6-n03`, I am listening
here, as of epoch 41" — gossiped between peers, newest-per-seat wins, bounded by
the roster so the memory is the size of the network rather than the size of what
somebody sends. A record ages out after an hour of nobody refreshing it, and one
from the future is refused, so a bad clock cannot pin a stale address in place.
`net.json` becomes a *seed* list: a node may be handed one address and learn the
rest, which the live test does with four processes.

**And it surfaced a real bug.** The admission rule from the authentication pass
— a connection that has not proved a seat may not send peer traffic — tested
`who in self.peers`, which is the *dial list*. That was the same set as the
roster only because every node's file named every node. The moment they differ,
a validator dialling *in* is treated as a stranger and refused, which is a
partition that heals only if somebody edits a file. The handshake already proves
a roster seat before `_greet` returns a name, so the roster is what authorises
now and the file only says where to dial. Both directions are tested: a seat
this node does not dial is seated, and a stranger is still a stranger when the
dial list is empty.

### 4.3 · C7, resolved: a state that arrives in pieces

Two different faults behind one line. The transfer was **one frame**, so a
state larger than 6 MB could not be sent at all — the code said so, in a log
line that told an operator chunked transfer was not built. And the serving node
**exported a full copy of its state per request**, on the thread that also has
to attest, so three peers behind the window meant three copies.

`store/snapshot.py` was chunked from the beginning, with a digest on every
chunk, precisely so ranges could be fetched separately. What was missing was
the manifest committing to them and a wire protocol using it. Both exist now:
the manifest lists every chunk with its size and digest, `getsnapshot` offers
the manifest, and `getchunk` serves one range at a time (`SERVE_CHUNK` = 10,000
values, about 680 KB, against a 6 MB ceiling). A receiver checks the header and
its certificate *first* — so a peer that invents a state cannot make it spend a
frame fetching one — then asks for a few ranges at a time, checks each against
the digest the manifest commits, and folds only when it has them all.

That last part is the difference worth having: a bad range is caught on
arrival, by name, rather than at the fold where all anybody knows is that the
roots do not match.

Serving is memoised per height. One export, one file, served to everybody who
asks until the height moves; the stale ones are deleted. The live test asserts
both halves — the victim's log says how many chunks it was offered, and each
server is left holding exactly one export.

### 4.2 · C1, resolved: a dead leader costs a view, not an epoch

Designed first, because the review's complaint was that it was not: part
eleven, `docs/view_change_design.md`. The short version of why a retry loop
does not port to a network — in view 0 a quorum attests to **B** and one seat
sees all of it, so **B is final there**; everybody else times out, moves to
view 1, and finalises **C**. Two blocks at one height and nobody misbehaved.

So a seat that attests is **locked** on that block, the view change collects
the locks, and the next leader is bound by them. `chain/viewchange.py` carries
the signed statement and the quorum certificate; the certificate travels with
the proposal, bound into its signature, so the leader and every seat evaluate
the same evidence rather than each its own collection. A lock can be released,
and §2.4 of the design is the argument for why that is safe: a block that
*finalised* was locked by a quorum, any later quorum shares an honest seat with
that one, so no certificate that omits it can exist.

Timeouts are the clock, which every node already derives independently — no
timer negotiation and no view change about the view change. The budget is
arithmetic rather than a setting: a view has to be long enough for an honest
ceremony, so `Clock.views_for` gives a 2.5 s testnet one view (exactly today's
behaviour) and the shipped 19.75 s epoch three. That fell out of building it —
three equal views of a 2.5 s epoch are three views too short to finish in, and
the first live run stalled until the budget was derived instead of configured.

Proven on real sockets as well as in process: four nodes, the computed view-0
leader of epoch 1 silent, every seat timing out and moving to view 1, the
height still advancing and the roots still agreeing.

### 4.1 · C3, resolved: a divergence that announces itself

The fix is not a deeper rollback — the ceiling is arithmetic, not a setting.
`max fork depth = attacker's unspent turns / width`, so a branch that forks
deeper than the ceiling is not one an adversary inside the assumption could
have built. Meeting one means the assumption is wrong: a pool more concentrated
than era 0's ceremony claims, or turns compromised. The failure worth fixing is
that the node had no opinion about this at all — `_retip` took the heaviest
branch whatever it cost to follow, and a node that could not roll back that far
simply went on believing its own history.

`NetworkHistory` now measures what a retip would cost (`reorg_depth`, from the
common ancestor) and refuses to follow one past `reorg_limit`, raising
`ReorgBeyondCeiling` through the node's existing fail-stop path — the same
discipline as a protocol version a build cannot run. The message names the fork
height, the depth, the limit, and the only reconciliation there is: a snapshot
at or below the fork from a node on the branch the network agrees on. The
offending branch is kept, because a stopped node with nothing to look at is
worse than one holding the evidence.

Two details worth stating. The check is on being *followed*, not on arriving: a
losing branch may fork as deep as it likes, since nobody has to undo anything
for it. And the share is now one constant — `hardening.params.
ASSUMED_ATTACKER_SHARE` — used by both `store.undo.retention_depth` and fork
choice, because keeping undo records for 729 blocks while following forks to
800 is C3's divergence with extra steps.

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
   *(Done: `chain/protocol.py`, an activation schedule inside the genesis hash,
   and `HaltRequired` so a node that cannot follow the rules stops.)*
2. **A1 and A2 together** — pick the preset, and make `verify()` refuse the ones
   that should never launch. Hours, not days. *(Done: `LAUNCH`,
   `ChainParams.assess`, and `purpose` in the document. A9 came out of it.)*
3. **A3's dependency decision** — it gates the header field, and the header
   field is a format change. *(Done: `docs/quorum_signature_decision.md`, plus
   `seats_root`, the named scheme, and the bitmap encoding.)*
4. **A4, A5, A6, A7** — the four other things genesis makes permanent.
   *(All four done, with A8. Class A is closed.)*
5. **B1** — turn the fault machinery on, while the block format is still free.
6. **C1 and C3** — the two ways a live network stops being one.
7. Everything else, in the order operations demands it.

The three findings in §2 that came out of this pass rather than out of the
existing documents — the config, the blind spot in `verify()`, and the absence
of any version negotiation — are all in the first two steps, and none of them
takes more than a day.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/0774da90-65d8-4c51-9fa1-e7810216cdbf
