# The nullifier set: keep it, and make it earn its keep

*B5 in the pre-genesis review. Decision plus the check that justifies it.*

Part nine's finding, restated: **this chain's spend graph is public.** A
transaction names the note it spends by commitment, so a replay is refused by
`tin.cm not in self.utxo` before the nullifier check is reached — and a second
transaction spending the same note names the same commitment and dies the same
way. Under the confidential-transactions model the nullifier is not what stops
a double spend. The UTXO set's tombstone is.

Which makes the nullifier set a *second record of something the first record
already knows*, and the review is right that keeping, scoping or dropping it is
a free choice — free until genesis, because `nf_root` and `nf_count` are in
every header.

## 1. What it costs, measured

At `LAUNCH` parameters, one input and two outputs:

| | |
|---|---|
| rows in the MQ system | **1 of 305** — the nullifier form is one row a slot |
| the form itself | 2,211 terms, **0.43 ms** to evaluate, against 600 ms to prove |
| proof size | 341 KB, of which the nullifier row is ~0.3% |
| state | one 67-byte marker and one accumulator leaf a spend |
| header | one root and one count |

So the honest figure is: dropping it would save **about a third of one percent**
of a transaction, and one root in a header.

## 2. What it would cost to drop

Removing it is not a deletion. `partition_of_nullifier` is the routing rule, so
grids would key on commitments instead; `Wallet.reconcile` learns a note is gone
by watching nullifiers, so it would watch its own commitments; `nf_root` and
`nf_count` leave every header. All of that is doable — the spend graph being
public is exactly what makes each substitution available — and all of it is a
change to the shape of the chain for a third of one percent.

There is one thing it would foreclose: hiding the inputs. A chain where the
spent note is *not* named needs nullifiers, because the commitment is no longer
there to check. That is a different proof system and therefore a succession
(part ten) rather than an upgrade, so it is not much of an argument for keeping
the field — but it is worth being explicit that dropping it and later wanting
it back is a new chain.

## 3. The decision, and the reason

**Keep it, and treat the redundancy as a check rather than as ballast.**

Two records of the same fact are worth having when they are reached by
different routes. The UTXO set says *this slot is tombstoned*; the nullifier set
says *this marker was published*. A bug in the first — a spend that fails to
tombstone, a tree update that lands on the wrong leaf — is invisible to the
first, because the first is the thing that is wrong. It is not invisible to the
second.

So the two are now compared, every time either moves:

```
utxo.spent_count == nullifiers.size
```

at every height, for ever. A spend tombstones a leaf in one and appends to the
other; nothing else touches either. Two integers, on the path that moves them,
and if they ever disagree the node raises `LedgerInconsistent` and stops.

Stopping is the right response and not a dramatic one. A ledger whose own two
records of a spend disagree cannot be reasoned about locally — there is no way
to tell which record is the true one — and carrying on means computing roots
nobody else will reproduce, which is the definition of a silent fork. The fix is
a resync from a node that agrees with the network, which is the same answer C3
gives for a rewrite past the ceiling.

## 4. What this does not claim

The check catches **loss of track**, not dishonesty. A node that is lying about
its state can keep both records consistent trivially; what it cannot do is
convince anybody else, because the roots are in the header. And the check is not
a substitute for the UTXO refusal — it is a tripwire on the machinery that
refusal depends on.

## 5. Status

Built: `ChainState.cross_check`, called from `apply_delta` and `apply_block`;
`SealAccumulator.spent_count`; `LedgerInconsistent`.
`chain/tests/test_nullifiers.py` carries the tests.

Not done, on purpose: dropping the set, and scoping it to something narrower
than "every spend". The measurement above is why.
