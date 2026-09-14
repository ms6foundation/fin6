# Running a fin6 network — the operator's guide

*How to lay one out, start it, watch it, and read it when it stops.*

This is the operational half of the documentation; `docs/user_guide.md` is the
other. It assumes you have the repository and Python 3.10+, and that you run
everything from the repository root.

Two things to know before anything else.

**A testnet and a launch are different documents.** `fin6 genesis new` drafts a
document marked `purpose: "test"`, which *issues* its supply — the openings are
derivable from the document, which is what makes a testnet wallet possible and
is exactly why it is not a launch. `python3 -m chain.genesis` drafts for launch:
it is held to the parameter floor, it *mints* rather than issues, and the money
is opened by its holders and by nobody else. Everything below says which it
means.

**A node that cannot follow the chain stops.** Three exceptions end the
process on purpose — `HaltRequired`, `ReorgBeyondCeiling`, `LedgerInconsistent`
(§7). None of them is a crash. Each is the node saying it would have to guess
to continue, and an outage you can diagnose is cheaper than a fork you cannot
see.

## 1. A testnet in four commands

```bash
python3 -m fin6 genesis new /tmp/fin6-testnet --nodes 7
python3 -m fin6 net up      /tmp/fin6-testnet     # foreground; ctrl-c stops it
python3 -m fin6 net status  /tmp/fin6-testnet     # non-zero exit on disagreement
python3 -m fin6 tx send     /tmp/fin6-testnet --amount 100
```

`--nodes 7` is the default for a reason: n = 3f+1 at f = 2, so the register's
two-thirds rule lands on a quorum of five and the network tolerates two faults.
`--preset local` (also the default) is a one-backend, short-apprenticeship
configuration sized for one machine; `--epoch-millis` overrides the cadence
the hardening preset implies.

`net up` holds the child processes, so it runs in the foreground. Every other
command is a one-shot client that talks to a node over TCP.

## 2. What is on disk

```
<root>/
  genesis.json          the document: roster, keys, parameters, schedule
  net.json              addresses and per-node settings — local, never hashed
  light.json            a light client's trusted header, if you have run one
  wallets/<name>.seed   a wallet seed phrase, mode 600 — this is the money
  wallets/<name>.notes.json
  fin6-n01.out          that node's stdout, captured by the supervisor
  fin6-n01/
    chain.db            the ledger: SQLite, WAL, synchronous=FULL
    chain.db-wal        the write-ahead log …
    chain.db-shm        … and its shared-memory index
    node.log            one line per event, with a timestamp and the node id
    serve-<height>.snap a snapshot export, written when a peer asks for one
                        and memoised until the tip moves
```

**The store is three files, not one.** Copying `chain.db` out from under a
running node gives you a database missing everything in the write-ahead log.
Stop the node and copy all three, or take the backup from a node that is down.

`genesis.json` is the chain's identity — `chain_id = "fin6:" + H(document)` —
so changing *any* field in it produces a different chain rather than a changed
one. `net.json` is the opposite: it is per-machine configuration, it is not
hashed by anything, and two nodes may disagree about it without consequence.

Back up `chain.db` and the wallet seeds. Everything else is either derivable
(the ledger rebuilds from a snapshot or from peers) or disposable.

## 3. `net.json`, field by field

```json
{
  "effective_ms": null,
  "nodes": {
    "fin6-n01": {
      "listen": ["127.0.0.1", 7600],
      "behaviour": "honest",
      "skew_ms": 0
    }
  }
}
```

| key | what it does |
|---|---|
| `effective_ms` | when epoch 1 began, in milliseconds. `net up` fills it in so the first epoch is the next one. |
| `listen` | `[host, port]` this node binds. |
| `behaviour` | `honest`, `silent`, `equivocating` — *a fault harness*, not a production setting. A network cannot test what it cannot stage. |
| `skew_ms` | deliberately wrong clock, for the same reason. |
| `peers` | `{node_id: [host, port]}` — a **seed** list. A node handed one address learns the rest from the signed directory (review C6), so this does not have to name everybody. |
| `max_views` | how many views one epoch may spend on a dead leader. Capped by arithmetic: a view too short to finish an honest ceremony is worse than no view change, so `Clock.views_for` gives a 2.5 s epoch one view and the shipped 19.75 s epoch three. |
| `limits` | `{"capacity": …, "rate": …}` — this node's token bucket for clients. Leave it out unless you are pointing a flood at the node on purpose. |
| `body_window` | how many recent block bodies to keep for peers catching up. |

## 4. Founding a real network

Four artefacts, in this order. Each one binds to the ones before it, so the
order is not a preference.

```bash
# 1. era 0 — the first pool of one-time signing turns.
python3 -m chain.hardening.ceremony config/era0-7.json

# 2. the mint — commitments for the genesis supply, and sealed openings.
python3 -m wallet.genesis_mint config/mint-7.json config/mint-7.bin

# 3. the document, which commits to both and is then ratified by every founder.
python3 -m chain.genesis config/genesis-7.json
```

Step 2 drafts the document *without* its mint to learn what the mint binds to,
mints against that, and step 3 drafts again carrying the mint block — which is
how the two commit to each other without a cycle.

Then read what step 3 printed. `verify` returns problems and caveats, and the
caveats are the point: they are the parts the design names and the
implementation has not closed, reported rather than skipped so nobody mistakes
silence for a check. A document with **problems** should not be launched. A
document with caveats should be read by somebody before it is.

Distribute `genesis.json` to every operator. Each writes their own `net.json`.

## 5. Watching it

```
$ python3 -m fin6 net status /tmp/fin6-testnet
node         height  tip            utxo_root      registers       t  mem  peers
fin6-n01        412  nb:9f3c…       4479…31        7a0c…d2         1    3  6
…
agreement:  7/7 reporting nodes agree at height 412
protocol:   running 1, builds implement [1]
```

**Roots agreeing at a common height is the whole of consensus health**, and
roots *disagreeing* is worth more than any log line: it names the epoch where
two nodes stopped computing the same thing. `net status` exits non-zero on
disagreement, so a CI job can be a testnet run.

The fields worth knowing, from `status`:

| field | read it as |
|---|---|
| `height`, `tip` | where this node is. A node one or two behind is catching up; a node stuck is not. |
| `utxo_root`, `nf_root`, `registers_root` | what it computed. These are the ones that must match. |
| `mempool` | transactions waiting for a grid that owns their partition. |
| `homeless` | transactions no grid may include — inputs spanning two partitions. Non-zero means a wallet is building spends the chain cannot route (see the user guide §6). |
| `peers`, `directory` | connections held, and seats whose address this node knows. `directory.refused` counts address records that failed their signature. |
| `budget`, `work` | the epoch's spending: `shed` counts work refused to protect the decide deadline, `queued` what is waiting. Both are healthy in small numbers and a symptom in large ones. |
| `gate`, `limiter`, `unsealed` | admission: connections refused, tokens refused, frames rejected for their seal. |
| `catchup`, `snapshots` | how far behind this node thinks it is, and how many state snapshots it has asked for or adopted. |
| `hardened`, `weight` | the hardened history: the height turns have been burned for, and its cumulative weight. |
| `protocol` | upgrade readiness — see §6. |
| `halted` | empty, or the message the node stopped on. |

## 6. Upgrades

Rule changes ship as a **protocol version with an activation height**, and the
schedule lives in the genesis document — so a chain's whole upgrade plan is
inside the thing its identity is the hash of. The shipped document reserves two
slots, at heights 1,596,840 and 4,790,520 (about one and three years at the
19.75 s epoch).

A reserved slot is a **deadline, not an option**. Every node must implement the
version before its height or the network halts there, and that is the correct
behaviour: applying a block under rules a build does not implement is a silent
fork, and the operator sees a running node. If a slot arrives and nothing
needed it, ship that version as "no rule changes" — a deliberate no-op is
cheap.

`net status` answers *"are we ready?"* as a number of blocks rather than a
conversation:

```
protocol:   running 1, builds implement [1] · 2 at height 1,596,840 in 1,596,428 blocks  ALL READY
```

Watch two things, and `net status` prints both. The protocol line ends in
`ALL READY` or `NOT READY:` followed by the nodes whose build is behind the
next version. And a halted node gets its own line: `HALTED: fin6-n03 — see the
node log`.

## 7. When a node stops

Three fail-stops, and none is a bug.

**`HaltRequired` — "height H runs protocol N; this build implements M."** The
node has reached an activation height for rules it does not have. *Fix:*
upgrade that node and restart it. It will catch up.

**`ReorgBeyondCeiling`** — the chain has reorganised further back than the undo
records reach (729 blocks, about four hours at a third-of-pool adversary).
Beyond the ceiling a node that cannot roll back has diverged from one that can,
and there is no local way to tell which branch is the real one. *Fix:* the node
re-syncs state from a peer (a snapshot proved against a header and its
certificate). It does not decide for itself.

**`LedgerInconsistent`** — the two records of what has been spent disagree:
`utxo.spent_count != nullifiers.size`. The nullifier set is deliberately
redundant with the UTXO tombstones, and the redundancy is a tripwire. This one
should never fire; if it does, keep the store and the log — that is evidence,
not a nuisance.

A halted node is also visible from outside: `status` carries `halted`, and
`net status` lists halted nodes under the protocol line.

## 8. Catching up, and state sync

A node that falls behind asks peers for the blocks it is missing, by range.
Past the body window — the recent blocks peers still hold in memory — it falls
back to **state sync**: it fetches a manifest, checks the header and its
certificate *first*, then pulls the state in chunks of about 680 KB, verifying
each against the digest the manifest commits before folding any of it.

Two operator consequences. Serving is memoised per height, so many peers
catching up at once cost one export rather than one each. And adopting a
snapshot **restarts this node's hardening weight from that height** — it proves
the state, not the turns that were burned to get there.

## 9. Faults and evidence

A provable fault — a leader proposing two blocks at one height, a node claiming
two grids in one epoch — is evidence anyone can check, and it suspends the
member in the grid register. Suspension is not self-healing.

Two things an operator should not do. Do not treat a *stalled* grid as a
faulted one: a grid that missed quorum produced no evidence, and the register
records only what the certificates prove. And do not delete a node's store to
"clear" a fault — the fault is in the committed register root, and a fresh
store will resynchronise to the same state.

## 10. Backups and retention

| what | keep it because |
|---|---|
| `wallets/*.seed` | it is the money. Nothing else can reconstruct it. |
| `<node>/chain.db` | the ledger. Recoverable from peers, but a restore is faster than a sync and does not restart hardening weight. |
| `genesis.json`, `config/mint-7.bin` | the document is the chain's identity; the mint artifact is what holders open their genesis money from. Both are needed years later. |
| `node.log` | the only record of *why*. |

The store keeps undo records to the rewrite ceiling and prunes past it, which
is deliberate: past the ceiling a block cannot be rewritten, so the record that
would rewrite it is dead weight. Archive profiles (`full`, `compact`,
`headers`) decide how much history a node keeps; a `headers` archive cannot
serve a claim, and it says so rather than failing quietly.

## 11. Measuring the machine you are on

```bash
python3 -m chain.measure --quick     # ~15 s
python3 -m chain.measure             # ~3 min, writes docs/measurements.md
```

Absolute timings are a claim about one machine, which is why the committed
record carries the build, the Python version and the platform beside the
numbers. What travels between machines is shape, and `chain/tests/test_measure.py`
asserts the shapes. Run the full one on the hardware a node will actually use,
and keep the output.

One measurement this repository cannot make for you: **whether your disk tells
the truth about flushes.** The store runs `PRAGMA synchronous=FULL`, which is a
claim about the device rather than about SQLite, and consumer SSDs acknowledge
flushes they have not completed. Test it once on the hardware — write, cut
power, reopen, compare the tip against what was acknowledged — and record the
answer. A node whose disk lies is not a node with a slower store; it is one
that can acknowledge a block it does not have.

## 12. Things this does not do yet

Named rather than discovered:

- **One tier over the network.** The node process runs a single grid. The super
  and supreme tiers exist in the simulation (`run_tiered_epoch`) and have never
  run over sockets.
- **No admission over the network.** Growth — admitting nodes, founding and
  merging grids — runs in the simulation. On a live network the roster is the
  genesis document's.
- **`fin6 net kill` needs the supervisor** that started the nodes; from the CLI
  it tells you so and exits non-zero.
- **No partition or clock-skew assertions.** Both faults are stageable from
  `net.json`; nothing asserts what should follow. Kill and pause do assert.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/6c2eb94c-15db-4c22-b8c7-2ecb6dd19398
