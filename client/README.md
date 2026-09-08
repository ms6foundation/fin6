# `client/` — what talks to a node without being one

```bash
python3 -m client.demo              # prove a balance instead of being told it
python3 -m client.tests.run_all     # 8 tests, ~31 s
```

Three levels of doubt, and they are different clients rather than settings on
one. What separates them is what they refuse to trust.

| | trusts | verifies | per block |
|---|---|---|---|
| `Client` | one node, entirely | the commitment of each note it decrypts | 0 |
| `LightClient` | the validator register — but checks it | the tip certificate, ancestry, its own notes, and that its scan was complete | ~1.3 KB |
| `Adjudicator` | nothing but the genesis document | cumulative hardening weight, stamp by stamp | ~86 KB |

The third is not a daily mode. A client follows the register at 1.3 KB a block
and convenes the adjudicator only when it is shown two tips — which is rare,
bounded, and exactly when 86 KB a block is worth paying.

| module | |
|---|---|
| `rpc.py` | the ten questions a node will answer, and fire-and-forget submission |
| `light.py` | the following client: a header spine, a verified register, proved notes, a counted scan |
| `adjudicate.py` | two tips and the arithmetic that decides between them |
| `demo.py` | all of it against a live testnet |

## What it will not do

It reports two numbers, never one — proved and unproved. That distinction is
the only thing it has that a wallet does not, and collapsing it into a single
balance would hand the answer back to the node.

And the adjudicator reports; it does not adopt. Choosing a branch is the
caller's, because a client that silently switched chains on a fork-choice rule
would be doing the one thing this package exists to avoid.

## Open

- Completeness now has an answer (the header's counts); *linkability* does not
  — `inclusion(cm)` tells the node exactly which note is yours.
- Weight is observed rather than agreed: two honest nodes at the same tip
  report different cumulative weights, so agreement is keyed on the tip.
