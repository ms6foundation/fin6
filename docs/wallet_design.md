# The wallet and the client — fin6 design sketch, part seven

How a person who is not a validator holds money on this chain, spends it, and
finds out that they were paid. Follows parts one to six, all implemented in
`chain/`.

## 0. What a user can do today, exactly

**Submit: yes.** The frame protocol takes a `tx` frame from any connection, not
only from a seated peer. `fin6 tx send` connects to a node, says hello, and
sends one framed transaction; the node verifies the proof, admits it to its
mempool and floods it onward, and it lands in the next block whose grid owns its
nullifier partition. Two properties of that path are worth saying out loud: it
is unauthenticated, and each submission costs the node ~26 ms of verification,
so it is a denial-of-service surface with no meter on it.

**Receive: no.** A transaction carries input commitments, nullifiers, spend
signatures, output commitments, the public fee, `v`, the binding scalar and the
proofs — and nothing else. A commitment is a hash of the note's opening, so a
recipient cannot recognise its own output by looking at the chain. It can only
recognise a note it *already holds*.

The simulation hides this completely, because `transfer()` hands the output
`Note` object straight into the receiver's wallet inside the same process:

```python
tx = build_transaction([(note, wallet_from.signer)], outs, fee, params)
wallet_to.receive(outs[0])        # <- this line is the payment system
wallet_from.receive(outs[1])
```

On a network that line is an email. This document is mostly about deleting it.

## 1. A wallet is two secrets, and one of them should not be

To spend a note the wallet needs its whole opening — value, asset, owner, rho,
and the blinders — because that is what goes into the proof. The signing key
alone proves nothing and unlocks nothing.

So a fin6 wallet as it stands holds **two** secrets: a key, and a file of note
openings. Losing the key loses the ability to spend. Losing the note file loses
the money, *with the key intact and the notes still sitting unspent in the UTXO
set for the rest of time*. No amount of care with the seed phrase protects a
user from that, because the seed is not what the money is made of.

That is the argument for the change in §2, and it is a stronger one than
"receiving does not work". Putting an encrypted opening on chain turns the note
file into a **cache** and the chain into the backup, which is the only version
of this where "restore from seed" is a true statement.

## 2. The note ciphertext

Every output carries an opening encrypted to its recipient:

```
per output:
    epk         32 B   an ephemeral X25519 public key
    ciphertext 224 B   value, asset, rho, 4 blinders — 7 field elements
    tag         16 B   ChaCha20-Poly1305
              -----
              272 B
```

Against a 63 KB `mpcith` proof that is **0.4%**, which is the whole cost
argument. The recipient derives the shared secret from its viewing key and the
ephemeral public key, decrypts, recomputes the commitment from the opening, and
keeps the note only if the commitment matches the one in the transaction — so a
malformed or mis-addressed ciphertext is detected rather than trusted.

The sender encrypts the change output to itself by the same mechanism. It has
to: otherwise the sender is the one who cannot restore.

Note this is only *delivery*, not new privacy. The spend graph is already public
— input commitments travel in `v` — so the ciphertext hides the value and the
randomness of an output from everyone but its owner, which is exactly what the
commitment already hid. Nothing gets weaker.

## 3. An address is two keys

```
fin6 address = (spend public key, viewing public key, checksum)
```

The spend key is the Ed25519 key the chain already uses: it authorises a spend
and its field image is the `owner` coordinate inside the note. The viewing key
is new and is X25519, because the ciphertext needs a Diffie–Hellman, and Ed25519
signing keys should not be reused for key agreement.

Both derive from one seed, so a user still holds one secret. A wallet can hand
out its viewing *private* key to an auditor to grant read-only access to its
incoming notes — which for a permissioned financial chain is a feature worth
designing in deliberately rather than discovering later.

Encoded with a human-readable prefix and a checksum, because an address that can
be mistyped into a valid-looking different address is a way to lose money
quietly.

## 4. Scanning, and what a restore costs

A wallet finds its money by trial-decrypting every output it has not seen
before. One X25519 operation per output. The sketch estimated 60 µs; the built
code measures **36 µs** for an output that is not ours — which is the number
that matters, because almost none of them are — and 111 µs for one that is,
where the opening is also unpacked and its commitment recomputed:

| situation | outputs | time |
|---|---|---|
| keeping up, one block at 200 tx | 400 | ~15 ms |
| a day at 10 tx/s | 1.7 M | ~62 s |
| restoring from seed over a 10 M-output history | 10 M | ~6 min |

Keeping up is free and a restore is a coffee. If that ever stops being true the
usual answer is a short detection tag — two bytes derived from the shared secret
— that lets a wallet skip the decryption for outputs that are not its own, at
the cost of a little linkability between outputs to the same recipient. Not
needed at this scale; worth knowing the shape of.

A wallet only needs to scan **outputs**, which are in class B of the persistence
design — the prunable half. A `COMPACT` archive keeps them; a `HEADERS` archive
does not. So the retention profile an operator picks decides whether a user can
restore from seed against that node, and that connection should be stated where
operators can see it.

## 5. Knowing a note is spent, and what change looks like

Spend detection needs nothing new. The nullifier is a deterministic function of
the opening, so a wallet computes the nullifier of each note it holds and
watches the nullifier set; when one appears, that note is gone — whether the
wallet spent it or someone who had the opening did.

Change is already right: `transfer` always creates two outputs and pads with a
zero-value note when there is no change, so every transaction has the same
shape. Hiding whether there was change is worth the empty note, and the range
proof covers zero without complaint.

## 6. The query interface a client needs

A client can currently ask a node exactly one thing — `status` — and infer
everything else. The minimum to build a wallet on:

| request | answer | why |
|---|---|---|
| `headers(from, to)` | network block headers | the chain a light client follows |
| `block(hash)` | a whole block | scanning, and fetching a specific transaction |
| `outputs(from, to)` | just the output commitments and ciphertexts | scanning without the proofs — the difference between 542 KB and 2 KB a transaction |
| `submit(tx)` | accepted, or the reason | today a submission is fire-and-forget |
| `txstatus(txid)` | pending / in block h / rejected, and why | a wallet cannot currently tell a slow transaction from a dropped one |
| `member(cm)` | a membership proof against `utxo_root` | §7 |

`outputs` is the one that matters for cost. A wallet that must download whole
blocks to scan them pays the proof bytes it has no use for; a wallet that asks
for commitments and ciphertexts pays 272 bytes an output.

## 7. A light client follows certificates, not weight

fin6 does not have Bitcoin's "verify the headers and count the work" shortcut,
and it has something better shaped for it. A network block header is signed by a
quorum certificate; the seated validators for that grid are a deterministic
function of the register; and the register roots chain back to the genesis
document whose hash is the chain id. So a light client with the genesis document
can verify the header chain by **checking quorum certificates against the roster
it can derive**, which is a real chain of trust rather than an assumption.

Hardening then gives it the second, independent guarantee: accumulated weight
says the history will *stay* true (part three), and a wallet should show both —
"agreed" at inclusion, "final" once the block carries its stamps.

**The membership proof is the problem.** A client that does not hold the UTXO set
cannot check that a note it is about to spend is still unspent; it has to be
told. The seal tree can prove membership — `_ps6_build_copath` exists — but its
fan-out makes the proof enormous, because a "sibling" is 999 values rather than
one. `sbs` has only ever been tuned for update speed:

| `sbs` | levels over 10 M leaves | proof size | cost of one update |
|---|---|---|---|
| 1000 (today) | 3 | **93.7 KB** | 1.6 ms |
| 100 | 4 | 12.4 KB | ~2.1 ms |
| 32 | 5 | 4.8 KB | ~2.7 ms |
| 8 | 8 | 1.8 KB | ~4.2 ms |
| 2 (a binary Merkle tree) | 24 | **0.8 KB** | ~12.7 ms |

That is the trade in one table, and it has never been made deliberately:
**`sbs` is the light-client knob**, and today it is set as if light clients do
not exist. Somewhere around 8 to 32 looks like the honest middle — a proof that
fits in a packet, at two to three times the per-update cost.

## 8. What a client leaks

| what | to whom | mitigation |
|---|---|---|
| which node saw your transaction first | that node | submit to a randomly chosen node, or to several |
| that these transactions are the same wallet's | everyone | nothing: the spend graph is public by design, and part one says so |
| which commitments you care about | any node you ask `member(cm)` | ask for a range, or hold the set |
| roughly when you transact | everyone | epochs are 19.75 s; there is no finer timing to leak |

The honest summary for a user: **fin6 hides amounts and owners, not
relationships.** A wallet should not imply otherwise in its interface.

## 9. What "confirmed" means, in four steps

The one question every wallet has to answer, and this design has four answers to
it. Part three left "applications need a stated rule" as an open item; for a
wallet, this is that rule:

| state | when | what it means | show it as |
|---|---|---|---|
| submitted | a node accepted it | the proof verified and it is in one mempool | *pending* |
| included | in a ceremony block with a quorum certificate | one grid agreed | *pending* |
| agreed | in the network block | the supreme tier agreed; consensus-final | **paid** |
| hardened | the block carries `t` stamps, and more accrue | historically final, cost to unsay grows | **settled** |

The gap between *agreed* and *settled* is where the rewrite ceiling lives —
minutes to hours depending on the pool, and exactly computable (part three §5),
which is unusual enough that a wallet ought to show the number rather than a
spinner.

## 10. What this adds to `chain/`

| module | change |
|---|---|
| `notes.py` | encrypt / decrypt an opening; the detection tag if it is ever needed |
| `keys.py` | *new* — one seed, a spend key and a viewing key, and the address encoding |
| `transaction.py` | outputs carry `(cm, ciphertext)`; `build_transaction` encrypts to the recipient address |
| `wallet.py` | *new* — the note store, scanning, spend detection, balance, coin selection |
| `net/client.py` | *new* — `status`, `outputs`, `txstatus`, `submit`, and `sync` |
| `net/node.py` | serve those to clients, and rate-limit submissions |
| `store/archive.py` | ciphertexts ride with the bodies and are pruned with them |
| `cli.py` | `fin6 wallet new / address / balance / send / history` |
| `mq/ms6/core.py` | nothing — but `sbs` becomes a parameter with a second constituency (§7) |

`state.py`, `ceremony.py`, `tiers.py` and the proof stack do not move. The
ledger does not need to know that anyone is watching it.

## 11. Open items

| item | why it is open |
|---|---|
| The ciphertext is a format change | Outputs grow a field, so `txid` and every root over it change. Cheap to do now, expensive once a chain exists — which is an argument for doing it before the first real genesis rather than after. |
| `sbs` has two constituencies now | Update speed and proof size pull in opposite directions and the table in §7 has never been costed against real usage. |
| ~~Rate limiting~~ | **Fixed in part eight.** A cheap admission test in front (2.1 µs against 25.5 ms — 12,000×) and a token bucket per source. Charging a fee for the work is still a design nobody has written. |
| Recovery without a scan | **Improved in part eight**: detection tags let a node sort the chain at a precision the client chooses. The residual — binding that precision cryptographically rather than behaviourally — is part eight §14. |
| Viewing keys and disclosure | Handing an auditor a viewing key grants *permanent* read access with no way to revoke or scope it. A permissioned financial chain probably wants scoped, expiring disclosure, and that is a design of its own. |
| Multi-note spends | `transfer` spends exactly one note. `Wallet.select` already picks several and `Wallet.send` refuses loudly rather than building a statement it cannot prove; `TxSystem` supports k inputs and no code exercises it. |
| What a client does when nodes disagree | `net status` exits non-zero; a wallet has no equivalent rule. Following the heaviest hardened chain is the answer, and nothing implements it. |

## 12. What was built

Everything in §10 except `headers`, `block` and `member`, which a wallet turned
out not to need once `outputs` carried the ciphertexts. The client interface
that shipped is three questions — `status`, `getoutputs`, `txstatus` — plus
fire-and-forget submission, listed in `CLIENT_KINDS` so a client can never reach
a ceremony message by asking for one.

Measured, not estimated:

| | |
|---|---|
| sealed opening | 272 bytes per output — 32 ephemeral key, 16 tag, 224 opening |
| scanning | 36 µs per foreign output, 111 µs per own |
| address | 115 characters, `fin6` + base32(version ‖ spend ‖ view ‖ checksum) |
| single-character typos caught | 36 of 36 tested positions |

Two things the tests pin down that prose cannot. Swapping the two ciphertexts
inside a transaction does **not** redirect the payment — the openings are hashed
into the binding scalar, so a swapped or stripped `output_notes` fails
verification. And `test_a_stranger_is_paid_on_a_running_network` runs the whole
claim across four node processes and real sockets: a wallet holding nothing but
a freshly generated seed is paid 250, finds it by trial decryption, spends 100
onward, and reconciles to 148. It is the test that makes the wallet real, and it
takes ten seconds.

Open, still: nothing here verifies that a note is *unspent* without trusting the
node it asked. `Client.sync` believes what it is told about its own money. The
membership proof that would fix it is the accumulator's, and it is too large to
serve — which is the design's open item and not the wallet's to close.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/5ac696b7-e3f6-4385-8a39-539f57207b8a
