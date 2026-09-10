# Private, transaction-based chain on fin6/mq — design sketch

Three departures from a conventional chain:

- **Transaction-based, not account-based.** State is a set of unspent note commitments, not a table of balances.
- **Verification via fin6/mq.** Every transaction's validity is a single MQ zero-knowledge statement, checked with the existing `ms6`/`vs6` prover/verifier pair.
- **Ceremony, not mining.** Validators sit in a fixed grid and exchange state along two edges per node (`front`, `right`) for a fixed number of rounds each epoch.

## 1. Ledger model: notes over MQ commitments

The unit of state is a **note** — a commitment to `(value, asset_id, owner_key, salt)` built with `ms6.Commitment`, playing the role a UTXO plays in Bitcoin or a shielded note plays in Zcash, except the commitment's hardness comes from a multivariate-quadratic system (`MQSystem`) rather than an elliptic-curve or hash accumulator.

Every node keeps two running accumulators, each an `ms6` seal-tree — the same batched-commitment structure `examples/ledger_system.py` already builds per account, here rooted per chain-state instead:

| accumulator | contents | built with |
|---|---|---|
| `utxo_root` | every live (unspent) note commitment | `_SealTree`, opened per-note with `ps6`/`vs6` |
| `nf_root` | every nullifier ever revealed (every spent note) | same primitive, disjoint tree |

A note is spent by revealing its **nullifier** — a value derived deterministically from the note's own secret, one per note, unlinkable to the note's commitment without that secret. Spending debits no balance; it publishes a nullifier and the network refuses to ever accept that nullifier again. There is no account row to update, only a growing set of spent markers and a growing set of live commitments.

## 2. Transactions: one gamma-batched proof per spend

A transaction consumes k input notes and creates m output notes. Enough funds, no double-spend, no negative or overflowing amount, and correct spend authorization all collapse into **one** MQ statement, proved and verified with `prove_hidden` / `verify_hidden`.

This reuses the row types `examples/ledger_system.py` already implements for a global balance table (`sum_row`, `range_rows`, `bit_rows`), resharded so the values being summed are +value for each output and −value for each input rather than one row per account:

- **Value conservation** — Σ input values = Σ output values + fee, enforced by the sum row exactly as `LedgerSystem` enforces Σ balances = total.
- **Range proof** — every output value lies in `[0, 2^B)`, via the existing recomp + bit-constraint rows, unchanged.
- **Spend linkage** — each revealed nullifier is tied to the same secret as one of the input commitments via `LinkedSystem`/`commit_linked` (the mechanism already used to relate two MQ commitments by an algebraic relation), applied to nullifier↔commitment.
- **Membership / non-membership** — input commitments are proved present in `utxo_root` (a `ps6`/`vs6` opening); nullifiers are proved absent from `nf_root` (the double-spend check).

On-chain, a transaction is only: the input nullifiers, the output commitments, the public fee, and one proof. Values, owners, and salts never appear.

```
Tx = {
  inputs:  [nullifier_1 .. nullifier_k]
  outputs: [commitment_1 .. commitment_m]
  fee:     public field element
  proof:   one gamma-batched 5-pass SSH proof over a per-tx TxSystem
           (LedgerSystem-style: sum + recomp + bit + link rows)
}
```

## 3. Block structure

```
Block[h] = {
  prev_hash,
  utxo_root[h], nf_root[h],   # post-state accumulator roots
  tx_root,                    # seal-tree over this block's transactions
  ceremony_meta: { round, leader_id, grid_shape: (R, C), grid_seed },
  quorum_cert,                # batched attestations, see §4.2 step 4
}
```

A block is valid when every contained transaction's proof verifies, its nullifiers are disjoint from `nf_root[h-1]`, and `utxo_root`/`nf_root`/`tx_root` recompute correctly from the previous state plus this block's transactions — all local, deterministic checks any node can run alone. What the ceremony adds is agreement on *which* block h is, and finality.

## 4. The synchronization ceremony

No puzzle to solve — a fixed grid, run for a fixed number of rounds, every epoch.

### 4.1 Grid formation

- N active validators this epoch; row size C is a network parameter.
- Row 0 holds exactly one seat: the leader.
- Rows 1..R hold up to C nodes each, `R = ceil((N-1)/C)`; the last row may be short.
- Seats are assigned by a permutation seeded on `grid_seed = H(prev_block_hash, epoch)` — nobody knows their neighbors, or whether they lead, until the previous block is final.

### Sync edges (per node at row r ≥ 1, column c)

- `front(r,c)` = node at `(r-1, c)` if `r>1`, else the leader for `r=1` — every row fronts to the same column one row up, and all of row 1 fronts to the single leader seat.
- `right(r,c)` = node at `(r, (c+1) mod C_r)`, where `C_r` is the size of row r (handles a short last row). The rightmost seat's "right" wraps to column 0 of the same row — each row is a ring, fed vertically from the row above. This is exactly the requested rule: the last node on the right syncs to the front node *and* to the leftmost node.

Each node's in/out degree is fixed at 2 regardless of N: `front` + ring-left/right.

### 4.2 Ceremony rounds

A ceremony for block h runs a fixed `T = R + C` rounds — enough for data to descend all R rows and circulate a full ring in the widest row:

1. **Propose (round 0).** The leader assembles `Block[h]` from already-individually-valid transactions (§2–3) and sends it directly to every seat in row 1.
2. **Descend + circulate (rounds 1..T).** Each round, every node pulls from `front` (propagating the proposal down its column) and from its ring-left neighbor (propagating and cross-checking within the row), verifies whatever proof material is new to it, and folds both into a signed round digest.
3. **Equivocation check.** A row is a ring, so if any node forwards a value to its right that disagrees with what its own front-derived digest says, the mismatch surfaces within at most `C_r` rounds — the offending node's neighbors see a mismatch directly instead of a clean attestation.
4. **Quorum / finality.** After T rounds, a node with no unresolved mismatches and attestations chained from ≥ 2/3 of reachable seats accepts `Block[h]`; those attestations are batched into `quorum_cert` the same way `ms6` batches any set of committed values.
5. **Abort / view change.** No quorum after T rounds (silent or equivocating leader) aborts the ceremony; the next leader candidate — deterministic from `grid_seed` — retries at the same height with a freshly reshuffled grid.

Per-round cost is fixed at two edges per node regardless of N — O(N) messages per round, not O(N²). Liveness comes from the schedule (a ceremony runs every epoch, on the clock); safety comes from the ring's built-in equivocation detection plus a 2/3 quorum — a lightweight reliable-broadcast over a purpose-built topology, not a race.

## 5. Open items

| Item | Why it's open |
|---|---|
| Adversary bound on seats | View-change (4.2.5) needs an explicit upper bound on faulty seats per row — the usual BFT <1/3 assumption isn't yet pinned to this grid's row size. |
| Row capture | A row fully controlled by one adversary can stall everything below it. Skip-edges (front from r-2 as well as r-1) would add resilience — not designed here. |
| Grid resize across epochs | Reshuffling policy exists (new seed each epoch), but the exact R×C recompute when N changes needs a stated formula. |
| Proof cost at scale | `mq/mq.md`'s own benchmarks put 5-pass SSH proofs at ~0.1-1 s and 100-500 KB for realistic batch sizes; worth revisiting against the MPC-in-the-head work already underway in `ms6acc_mpcith.py` before sizing blocks. |
| Quorum signature scheme | `quorum_cert` assumes an aggregable attestation format (e.g. threshold BLS) — not chosen here, and part nine made it more pressing rather than less: a certificate is 225 bytes per attestation, it is now carried in the *following* block as well as stored with its own, and at 1,000 nodes a two-thirds quorum is 146 KB of it. A field to change before a real genesis; a migration of every stored certificate after one. |

## Rendered version

A diagrammed version of this sketch (grid topology, transaction flow) is published at:
https://claude.ai/code/artifact/a3ac8404-c92c-41f5-ad5a-08edfe88c8d5
