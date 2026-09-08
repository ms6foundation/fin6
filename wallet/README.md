# `wallet/` — the user's side

```bash
python3 -m wallet.demo              # pay a stranger across seven node processes
python3 -m wallet.tests.run_all     # 19 tests, ~11 s
```

```python
from wallet import Wallet, WalletKeys

keys = WalletKeys.generate()
w = Wallet(keys, params, chain_id=chain_id)
w.scan(outputs)                       # find money by trial decryption
tx, change = w.send(address, 250)     # build, seal and prove a transfer
```

A wallet holds exactly one secret. The spend key, the viewing key, the
detection key and the address all derive from it, and every note it holds can
be recovered by scanning the chain — so losing the note file costs a rescan
rather than the money. That is the whole point of putting an encrypted opening
on chain, and it is why the note store here is a **cache** and not a ledger.

| module | |
|---|---|
| `keys.py` | one seed → three keys and a checksummed address. The derivations themselves live in `chain/crypto.py`; what is here is the object |
| `sealing.py` | the opening sealed to its recipient, and the detection tag that lets somebody else sort the chain without reading it |
| `store.py` | the note cache: `scan`, `reconcile`, `select`, `send`, and a file that can be thrown away |
| `demo.py` | the whole story on a live testnet |

## Where the line is

`wallet` depends on `chain` and nothing depends on `wallet`. Two consequences
worth stating, because both were arrived at rather than assumed:

**The ledger does not seal.** `build_transaction` takes sealed openings and
tags already made, not recipient addresses — sealing needs to know what an
address is and the ledger has no business knowing. What the ledger *does* do is
bind them into the binding scalar, so swapping two ciphertexts breaks the proof
instead of redirecting a payment.

**The derivations are not here.** A genesis holder's spend key is derived from
a phrase exactly the way a user's is, and the chain has to be able to do that
without importing this package. So `chain/crypto.py` owns the arithmetic and
`wallet/keys.py` owns the object built from it — one formula, two callers,
no cycle.

## Open

- Multi-note spends. `select` picks several and `send` refuses loudly rather
  than building a statement it cannot prove.
- Detection precision is a knob the *node* turns (`sealing.detection_tag` says
  so at length). Binding it needs one detection key per tag bit.
- A viewing key granted to an auditor is permanent and unscoped.
