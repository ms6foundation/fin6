# The address format: one field now, so the viewing key can rotate later

*A6 in the pre-genesis review. Decision plus the field.*

`wallet_design.md` is precise about what ships. **Diversified addresses** scope a
viewing grant to one address; **per-output disclosure keys** hand over exactly
one note. Neither touches the chain, and both are built. What neither fixes is
the direction of time:

> a key you hand to an auditor today still opens payments made to that address
> *tomorrow*.

**Era-derived viewing keys** fix it — the viewing key is tweaked per era, so a
grant is bounded in time as well as in scope, and revocation is the era ending
rather than a promise. The review makes it class A because it changes the
address encoding, and an address format is permanent the moment the first
address is published.

## 1. Why it cannot be a software change

The standard construction is a non-hardened additive tweak: the address carries
a base viewing key `V`, a sender computes `V_e = V + t(V, e)·B` for era `e` from
the address alone, and the holder derives `v_e = v + t(V, e)`. Handing over
`v_e` discloses era `e` and nothing else.

Two things break if that is bolted onto what ships:

- **X25519 clamps.** A tweaked scalar is not a clamped scalar, so `v_e` cannot
  be used with the library's X25519 at all. The key agreement would have to move
  to Edwards form and be done with point arithmetic this repository does not
  have — the same trust-base question as the pairing library in
  `quorum_signature_decision.md`, arriving from a different direction.
- **The u-coordinate is lossy.** A Montgomery public key is the x-coordinate
  only, so the tweak cannot be computed on it. The base key would have to be
  published in Edwards form.

So it is not one scheme with an extra parameter. It is a **different key
agreement wearing the same thirty-two bytes** — which is the worst possible
shape for a silent mismatch: a sender that guesses wrong seals the opening to a
point the holder cannot derive, and the money arrives on chain and cannot be
spent, with nothing anywhere saying why.

## 2. The decision: the field now, the construction with a reviewer

`wallet_design.md`'s own caveat is that the clean construction "does the point
arithmetic in Ed25519 form and wants a reviewer". Writing that arithmetic by
hand, unreviewed, and putting it on the path that decides whether a payment can
be read is not an improvement over the problem it solves. It is not shipping
here.

What ships is the part that is permanent: **an address says which scheme its
keys are in.**

```
address v3:  version | scheme | spend(32) | view(32) | detect(32) | checksum(4)
             scheme 1 = x25519-static-view      (implemented)
             scheme 2 = ed25519-era-rotating-view (reserved, refused)
```

The byte is inside the checksummed body, so a downgrade is not a typo anybody
can miss. A build that meets a scheme it does not implement **refuses the
address** rather than paying into it. That is the entire value of the change,
and it is worth exactly one byte.

## 3. What happens when the construction lands

1. A wallet publishes addresses with `scheme = 2`, carrying the base viewing
   and detection keys in Edwards form.
2. Senders that implement scheme 2 tweak per era and seal to `V_e`; senders that
   do not **refuse the address** and say so, rather than sealing to a key the
   holder cannot derive.
3. `viewing_secret()` becomes `viewing_secret(era)`, and the honest paragraph in
   its docstring — "it opens every note ever sent to this diversifier, including
   notes nobody has sent yet" — becomes false, which is the point.
4. **The address format does not change again.** No new version, no reissued
   addresses, no flag day.

What a reviewer has to check, when there is one: the tweak derivation binds the
base key as well as the era (so two addresses cannot be tweaked onto each
other), the scalar arithmetic is mod ℓ with no clamping anywhere, the Edwards
decoding rejects non-canonical encodings and small-order points, and the
detection key rotates on the same schedule or deliberately does not.

## 4. Status

Built: address version 3 with the scheme byte, `SCHEMES`, `IMPLEMENTED`, and a
refusal for anything outside it. `wallet/tests/test_address_format.py`, 7 tests.

Not built, on purpose: the era tweak itself, and the Edwards key agreement it
needs. There are no addresses in circulation — the chain has not launched — so
this is the only moment when the field costs nothing.
