# fin6

A private, transaction-based financial ledger. Transactions are verified with
multivariate-quadratic commitments and zero-knowledge proofs; blocks are agreed
by scheduled grid ceremonies rather than proof of work; and agreed blocks are
hardened into history by a finite pool of single-use turns.

> **Research code — unaudited, and not safe for value.** This is a working
> implementation of a design, not a reviewed cryptosystem. See
> [Security](#security) before doing anything with it.

## What's here

| path | |
|---|---|
| `mq/` | the MQ-hardened batched commitment — `ms6` (prover) and `vs6` (independent verifier) |
| `examples/` | account-based ledger and sanctions-screening demos built on `mq/` |
| `chain/` | the private chain: ~11,600 lines, 281 tests |
| `docs/` | the eight design sketches the chain was built from |

## Quick start

Python 3.10+. One runtime dependency — `cryptography`, used only for validator
and spend signatures. Run everything from the repository root.

```bash
python3 -m chain.demo             # one grid: transfers, ceremony, Byzantine leaders
python3 -m chain.demo_tiers       # many grids: registers, partitions, three phases
python3 -m chain.demo_hardening   # consensus through to hardened history
python3 -m chain.demo_archive     # what an archive costs, and where it goes
python3 -m chain.demo_persistence # stop the chain, start it again
python3 -m chain.demo_genesis     # launch the seven-node network from its config
python3 -m chain.demo_wallet      # pay a stranger across seven node processes
python3 -m chain.demo_light       # prove a balance instead of being told it

# and a real network of seven processes, over TCP:
python3 -m chain.cli genesis new /tmp/fin6-testnet --nodes 7
python3 -m chain.cli net up       /tmp/fin6-testnet     # ctrl-c to stop
python3 -m chain.cli net status   /tmp/fin6-testnet     # exits non-zero on disagreement
python3 -m chain.cli tx send      /tmp/fin6-testnet --amount 100

# and a wallet, which holds one seed and finds its money by scanning:
python3 -m chain.cli wallet import-genesis /tmp/fin6-testnet --holder treasury
python3 -m chain.cli wallet new     /tmp/fin6-testnet --name bob
python3 -m chain.cli wallet send    /tmp/fin6-testnet --name treasury \
        --to "$(python3 -m chain.cli wallet address /tmp/fin6-testnet --name bob)" \
        --amount 250
python3 -m chain.cli wallet sync    /tmp/fin6-testnet --name bob
python3 -m chain.cli wallet balance /tmp/fin6-testnet --name bob

# and a client that checks rather than believes:
python3 -m chain.cli light sync   /tmp/fin6-testnet
python3 -m chain.cli light verify /tmp/fin6-testnet --name bob

python3 -m chain.tests.run_all    # 281 tests, ~70 s
```

```python
from chain import DEMO, bootstrap, transfer, run_epoch

nodes, wallets, genesis = bootstrap(["v0", "v1", "v2"], {"alice": [1000]}, DEMO)
tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, DEMO)
for n in nodes.values():
    n.submit(tx)
epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s")
```

## The design, in three layers

### 1. Ledger and ceremony

State is a set of **notes** — this chain's UTXO — each committed under a fixed
public MQ map rather than a hash. The commitment is algebraic because the
transaction proof has to reason about it: `chain/txsystem.py` embeds one copy of
the note map per note slot, so a single gamma-batched proof relates a note's
hidden value to the very commitment the ledger stores.

One spend, one proof, covering all at once: value conservation, one asset per
transaction, every output in range, each nullifier derived from the note being
spent, each spending key matching that note's owner slot, and the whole thing
welded to this transaction body.

Consensus is a grid. The leader sits alone in row 0; every seat synchronises to
`front` (same column, row above) and `right`, with the rightmost seat wrapping to
the leftmost — so each row is a ring fed vertically by the row ahead of it.
Degree 2 per seat, `O(N)` messages per round, and a leader that sends different
blocks into different columns has them meet inside a row.

### 2. Tiered consensus

Many grids run concurrently and fan in:

```
Phase L   local grids, in parallel        →  CeremonyBlock  →  local mempool
Phase S   their leaders form super grids  →  SuperBlock     →  super mempool
Phase X   super leaders → supreme grid    →  NetworkBlock   →  supreme mempool
```

The ceremony machinery is untouched across all three — each tier supplies a
*workload* saying what its leader builds and what its seats check.

Standing is earned in the **grid register**: a rooted, deterministic record every
seat recomputes, so the leader's claimed `register_root` is checkable. Newcomers
are apprentices, seated in the back rows where no counting seat depends on them
to relay, casting shadow attestations that move their counter but not the quorum.
Because the counter lives in the grid, relocating restarts it — capturing a
particular grid costs 40 ceremonies per node, in the open.

Each node also keeps a private trust list built from what it watched. It is
deliberately powerless: it steers peering and preferences, never quorum.

Cross-grid double spends are made impossible rather than merely detectable — a
grid may only include transactions whose nullifiers fall in its partition.

### 3. Hardening

Consensus finality is instant; **historical** finality accrues. A block leaves
the supreme mempool agreed but reversible, and enters history when turns from a
finite single-use pool have burned themselves on it.

Each turn is a Winternitz one-time key in a Merkle tree. Spending it means
solving a puzzle and signing the result — and signing twice with a one-time key
leaks it, so equivocation is self-punishing. Verification recovers the public key
*from* the signature and opens it against the era root, so membership and
signature check in one step.

The pool is finite, which couples two things Bitcoin keeps independent:

```
block_interval = era_seconds × width / turns = 43200 × 32 / 70000 = 19.75 s
```

Two eras a day, 2,187 blocks each. And because the committee is redrawn every
block, the threshold *compounds* — an attacker must clear 22-of-32 on a fresh
unbiased draw every time:

| attacker's share of the pool | P(one block) | P(six consecutive) |
|---|---|---|
| 10% | 2.4e-15 | ~0 |
| 50% | 2.5e-02 | 2.5e-10 |
| 67% | 5.0e-01 | 1.6e-02 |
| 80% | 9.6e-01 | 7.8e-01 |

So the practical bar is near 80% of the pool, not 51%. The finite-pool ceiling
(`max fork depth = owned turns / width`) is the second line — and every failed
attempt burns the turns it drew, permanently shrinking the next one.

## Status

**Implemented and tested** — the ledger, the single-grid ceremony with
equivocation detection and view change, the three-tier epoch through to the
supreme mempool, grid registers and standing, nullifier partitioning, and
hardening into history.

**Three proof backends ship**, one per tier, all living in `mq/` proper with
verifier halves in `vs6`. `ssh5` is `mq/ms6`'s gamma-batched 5-pass (80 rounds,
185 KB at h=48); `ssh3` is the 3-pass written for this repo in `mq/ms6/ssh3.py`
(137 rounds, 295 KB), since `mq/ms6/core.py` had dropped its 3-pass path leaving
only the round-count helper; `mq/ms6/mpcith.py` is the MPC-in-the-head proof
`mq/mq.md` specifies but never shipped (20 repetitions at N=16, 62 KB — the
smallest and the fastest). All three reject each other's proofs, which is what
makes the per-tier diversity real, and every proof is checked by the independent
`vs6` verifier as well as the prover's own.

**The chain is persistent.** `chain/store/` holds a canonical binary codec, a
SQLite store that commits once per network block, undo records and rollback,
self-certifying snapshots, the fsync-before-signing guard for turn spending, and
the archive segment. A node stops and restarts with the same roots, tip and
registers, and keeps going. Retention makes a fully verifying archive 8.5x
smaller — 505 GB/day down to 56 GB/day at 10 tx/s — by keeping one proof per
transaction rather than three. What is not wired: hardened history still lives
in memory, and there is no snapshot schedule.

**A network can be launched.** `config/genesis-7.json` is a ratified seven-node
genesis — the smallest roster that tolerates two Byzantine faults — whose hash
*is* the chain id, so every attestation, proposal and proof binds to that exact
setup. With one grid the hierarchy collapses to a single ceremony that still
emits an ordinary `NetworkBlock`, with `tiers` in the signed header saying how
much independent verification stands behind it.

**And it grows.** A grid that is over size founds a child, and the cohort that
moves keeps the standing it earned — otherwise a grid of pure apprentices could
never reach quorum, and so could never run the ceremony that would promote
anyone. The cohort is drawn deterministically from committed state and seeded by
the previous block, so no leader chooses it, and `founded_from` sits in the
register root so the waiver is auditable. Seven nodes at one tier become two
grids and two tiers without changing block format.

**It runs as a real network.** `chain/net/` is seven processes over TCP with
framed messages, a clock each node derives from the genesis document, envelope
gossip that carries block *hashes* rather than blocks, and block fetch by hash.
They reach agreement with identical roots, and running it immediately found
three things one process had hidden — the attendance roll cannot be built from
one node's view, a seat that decides must keep talking, and genesis issuance was
not reproducible across processes.

**Not built:** grid merge, so a network that shrinks keeps grids it cannot fill;
cross-partition transactions; reorg rollback beyond the undo ceiling; catching
up a node that has fallen behind; hardening on the testnet; more than one host. The ceremony is a synchronous
simulation with no clock.

## Security

- **Unaudited.** Novel constructions, no external review.
- **The `DEMO` preset is deliberately insecure**: 8 note coordinates of which 4
  are random puts the note-commitment MQ instance inside Gröbner range. `STRONG`
  (48 coordinates) is sized per `mq/mq.md` and costs 0.33 s per transaction.
- **The spend graph is public.** Amounts, output owners and note randomness are
  hidden; which note is being spent is not. This is the confidential-transactions
  model, not the Zcash one.
- **Bootstrap is a trusted setup.** Each grid's founding cohort starts as
  attesters, because a grid of pure apprentices can never reach quorum. So is
  era 0 of the hardening pool, and genesis issuance proves nothing about the
  value it puts into circulation.
- **`chain/hardening/wots.py` is a teaching implementation.** A deployment should
  use a reviewed one (RFC 8391).
- **Distribution is the security parameter.** 70,000 turns on 200 machines is 200
  points of failure. An attacker's share of the pool *is* the rewrite ceiling.

## Documents

- [`docs/private_chain_design.md`](docs/private_chain_design.md) — the ledger and the single-grid ceremony
- [`docs/tiered_ceremony_design.md`](docs/tiered_ceremony_design.md) — many grids, registers, trust, per-tier proofs
- [`docs/hardening_design.md`](docs/hardening_design.md) — moving blocks into network history
- [`docs/persistence_design.md`](docs/persistence_design.md) — what survives a restart, and what may be thrown away
- [`docs/genesis_design.md`](docs/genesis_design.md) — what a new network must be trusted about, and for how long *(the one-tier launch is built; the rest is a sketch)*
- [`docs/testnet_design.md`](docs/testnet_design.md) — running it for real: seven processes, a wire, a clock *(built, through stage 2)*
- [`docs/wallet_design.md`](docs/wallet_design.md) — how a user holds money, spends it, and finds out they were paid *(built)*
- [`docs/light_client_design.md`](docs/light_client_design.md) — the query interface, and what a client can check for itself *(built, except the adjudicating client)*
- [`chain/README.md`](chain/README.md) — implementation notes, measured costs, and what the code changed about the design

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
