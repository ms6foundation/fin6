# The one-time signature: what ships, and how it gets replaced

*A7 in the pre-genesis review. Decision plus the seam.*

`chain/hardening/wots.py` says of itself, and the README repeats: *"A deployment
should use a reviewed implementation (RFC 8391's XMSS WOTS+) rather than this
one."* The review made it class A for a reason that is easy to miss — swapping
implementations is compatible *if the parameters match*, but era 0's leaves are
committed at genesis, so after that the parameters are not negotiable.

## 1. The decision: this implementation ships, named and pinned

Adopting RFC 8391 now would mean either taking a dependency — the same trust-base
question as the pairing library in `quorum_signature_decision.md`, with the same
answer — or writing a second implementation by hand, which is not what "reviewed"
means and would be the third hash-based construction in this repository to have
no external eyes on it.

What is actually wrong with shipping this one is not the construction. It is a
chain built on it in a way that cannot be *checked* against a replacement. That
is fixable now, cheaply, and it is what this change does.

### What is not the standard, and is deliberate

The chain step folds the public seed and the step index into the hash input
rather than applying per-step bitmasks drawn from the seed. That is the WOTS-T
style construction: the same security argument, less machinery. It is not
RFC 8391's function, so a byte-compatible swap to RFC 8391 is **not** available
— which is precisely why the scheme needs a name rather than an assumption.

## 2. The seam

**A name.** `wots.SCHEME` is `"fin6-wots-t-sha256-w16-n32"`, and it is a field
on `HardeningParams`, which means it travels in the genesis document and is
inside the chain id. A build whose implementation answers to a different name
refuses to construct hardening parameters at all, rather than quietly producing
leaves that no other node's turns match. `EraSpec.scheme` carries it into the
era's own identity, because a leaf is only a public key *relative to a scheme*.

**Known answers.** `chain/hardening/vectors/wots.json` pins three
(index, message) pairs to a public key, a signature digest and a signature
prefix, under a fixed master seed and public seed. `chain/tests/test_wots_vectors.py`
checks them. A replacement implementation is a drop-in if and only if it
reproduces that file — a claim about bytes, checkable in a minute, rather than a
claim about two specifications being the same.

**The parameters as data.** `wots.params()` returns the eight numbers a
replacement has to match (hash, n, w, len_1, len_2, len, signature bytes, and
the scheme name).

## 3. What writing the vectors found

The implementation accepted a message of the wrong length. `_digits` reads
`LEN_1 = 64` digits out of what it assumes is a 32-byte digest; hand it four
bytes and it returned 8 digits, `sign` produced an 8-chain signature, and
`verify` refused it with `ValueError` swallowed into a `False`. An object shaped
like a signature that no verifier will ever accept, and nothing anywhere said
why.

Every caller inside the chain passes a 32-byte puzzle hash, so this was latent —
but it is exactly the class of bug the review is worried about, found by the
cheapest possible means, which is a reason to take the rest of A7's advice
seriously rather than a reason to feel reassured. `sign`, `public_key` and
`public_key_from_signature` now refuse a message that is not the digest.

## 4. What a replacement has to do

1. Reproduce `chain/hardening/vectors/wots.json` byte for byte, or
2. change `wots.SCHEME`, which changes `HardeningParams`, which changes the
   genesis document, which changes the chain id — i.e. it is a **new chain**, or
   a succession (part ten), and not a software update.

There is no third option, and that is the property worth having: the mismatch
that would otherwise be discovered as a stamp that will not verify at height
40,000 is discovered at import time.

## 5. Status

Built: the scheme name in `wots`, `HardeningParams` and `EraSpec`; the vector
file; `chain/tests/test_wots_vectors.py`, 7 tests; the message-length fix.

Not done, on purpose: adopting RFC 8391. It is now a checkable swap rather than
a leap, and it stays available — with the caveat above, that adopting it is a
new chain rather than an upgrade, because the chain function differs.
