# Deploying fin6

*A launch runbook: from nothing to a network running across machines that
different people control. `docs/admin_guide.md` is the reference for a network
that already exists — layout, `net.json`, watching it, reading a halt. This is
how one comes to exist: who does what, in what order, on which host, and what
has to be true before it is allowed to carry anything.*

Run everything from the repository root. Python 3.10+, one runtime dependency
(`cryptography`, used only for validator and spend signatures).

## 0. Read this before planning a launch

The README's warning is not boilerplate — *"research code, unaudited, not safe
for value"* — and four specific things in the tree stop a value-bearing launch
today. Each is small to state and none is small to fix.

| blocker | where | what it means |
|---|---|---|
| **Validator keys are derivable from node names** | `genesis.dev_keyring`: `Signer.from_seed(f"validator:{node_id}")`, and `NodeProcess` defaults to it — `node_main.py` passes no keyring | Anyone who reads the repository can sign as any seat. There is no key-custody path in the shipped entry point at all. |
| **Turn seeds are derivable too** | `genesis.dev_turn_seed` = `sha256("fin6-turn-seed:" + node_id)` | The hardening pool is spendable by anyone, so the rewrite ceiling is zero. |
| **The era-0 ceremony runs in one process** | `hardening/ceremony.py`: *"`run()` does all of it in one process … the seeds it is handed are the only thing that makes that a demonstration rather than a launch"* | The distribution of the 70,000 turns is *the* security parameter (`hardening_design.md §5`), and there is no tooling for holders to contribute from separate machines. |
| **The roster is closed for the life of the chain** | `net/node.py`: `validators = {n.node_id: n.public_hex for n in doc.nodes}` | An operator cannot be added or retired later. See `plan/network_update_design.md §2`. |

Everything else in this guide works today. What you can deploy now is a
**testnet, a pilot, or an internal network among parties who already trust each
other** — which is worth doing, is how the blockers get found, and is what the
rest of this document is for. What you cannot deploy is a network whose safety
rests on the operators being unable to cheat.

Two further things to plan around rather than fix: fees exist but buy only
mempool survival (`fee_design.md`), and nothing pays validators on chain
(`emission_design.md §1`). Operator compensation is an off-chain arrangement, by
design and for now.

## 1. Roles, and who holds what

Three roles, and they are not the same people.

| role | holds | never sends anywhere |
|---|---|---|
| **founder** | the validator signing key named in the genesis document | the private key |
| **turn holder** | the secret its slice of the era-0 pool is generated from | the turn seed |
| **money holder** | a wallet seed under `wallets/<name>.seed`, mode 600 | the seed phrase |

One organisation may hold all three; the document does not care, and
`contrib.py` is candid that nothing can prove two holders are not the same
operator. Write down who holds what *before* the ceremony, because the
concentration you end up with is the rewrite ceiling you end up with.

Secrets inventory, in one place, for the security review somebody will ask for:
a validator key per node, a turn seed per holder, a wallet seed per money
holder. The genesis document carries public keys only.

## 2. Hosts

**Size the machine by measuring it, not by guessing.** The node derives its
queue depth and its client pricing from a measured unit of work, so a slow host
does not merely run slowly — it shapes its own admission budget:

```bash
python3 -m chain.measure          # prove/verify per backend, append ceiling
```

Read the numbers against `docs/measurements.md`: at `LAUNCH`/mpcith a transfer
is 421 ms to prove, 300 ms to verify, 369 KB encoded. A host that cannot verify
a transfer well inside the epoch's decide deadline (0.60 of 19.749 s) will shed
work under load, correctly and visibly (`budget.shed` in `net status`).

| | |
|---|---|
| CPU | verification is single-threaded per transaction and it is the whole cost; prefer clock speed over cores |
| disk | SQLite in WAL mode with `synchronous=FULL` — an fsync per commit, so a slow disk is a slow chain. Local SSD, not network storage. |
| disk size | capacity is 22 transfers a block at `LAUNCH` (8 MB frame ÷ 369 KB). At full frames that is ~35 GB **a day**; size against expected load, not the ceiling, and watch it. |
| clock | **NTP is mandatory.** The ceremony is scheduled by wall clock. `skew_ms` in `net.json` exists to *stage* a wrong clock as a fault; a real one behaves the same way. |
| network | one TCP port per node, reachable from every other node. No inbound access from clients is required unless this node serves wallets. |

Firewall: allow the roster's addresses to the node's `listen` port. Client
traffic (wallets, `tx send`, light clients) arrives on the same port and is
metered separately by the token bucket, so exposing a node to clients is a
policy decision, not a second port.

## 3. The four artefacts

Each binds to the ones before it, so the order is not a preference. Steps 1–3
happen once, before anything runs, and the shipped `config/*.json` files are
worked examples for seven nodes.

```bash
# 1. era 0 — the pool of one-time signing turns
python3 -m chain.hardening.ceremony config/era0-7.json

# 2. the mint — commitments for the supply, and openings sealed to holders
python3 -m wallet.genesis_mint config/mint-7.json config/mint-7.bin

# 3. the document, which commits to both
python3 -m chain.genesis config/genesis-7.json

# 4. every founder ratifies it
```

Step 2 drafts the document *without* its mint to learn what the mint binds to,
mints against that, and step 3 drafts again carrying the mint — which is how the
two commit to each other without a cycle.

**Then read what step 3 printed.** `verify()` separates *problems* from
*caveats*: a document with problems must not be launched; a document with
caveats must be read by a person who understands each one, because the caveats
are the places the design names something the implementation has not closed.
Expect at least these, and decide about each in writing:

- era 0 is a trusted setup;
- the first view seed is a value in the file rather than a commit-reveal;
- whether any activation slots are reserved — *"no activation heights are
  reserved, so this chain has nowhere to put a rule change"* is a caveat that
  cannot be fixed after launch (`plan/network_update_design.md §5`).

A launch document is `purpose: "launch"`, is held to the parameter floor, and
**mints** rather than issues. `fin6 genesis new` writes `purpose: "test"` and
issues — the openings are derivable from the document, which is what makes a
testnet wallet possible and exactly why it is not a launch.

Distribute `genesis.json` to every operator. It is public: it carries no
secrets, and `chain_id = "fin6:" + H(document)`, so every operator should
compare the chain id they compute against the one everybody else computes,
before starting anything.

## 4. One host, one node

```
/srv/fin6/
  genesis.json          identical on every host, byte for byte
  net.json              this host's own — never hashed, may differ per host
  fin6-n03/             created on first start
    chain.db  chain.db-wal  chain.db-shm
    node.log
```

`net.json` needs this node's `listen` and enough `peers` to reach the network —
a **seed** list, not a roster: a node that reaches any seat learns the rest from
the signed address directory.

```json
{
  "effective_ms": 1767225600000,
  "nodes": {
    "fin6-n03": {
      "listen": ["10.0.3.7", 7600],
      "peers": {"fin6-n01": ["10.0.1.4", 7600],
                "fin6-n02": ["10.0.2.5", 7600]}
    }
  }
}
```

`effective_ms` — when epoch 1 began — **must be identical on every host**. It is
the one field in this local file that is not local: nodes with different values
are running different schedules. `fin6 net up` fills it in for a single-machine
testnet; for a real network, one person picks a time comfortably in the future
and everybody writes the same number.

Leave `behaviour` and `skew_ms` out of a production file. They are a fault
harness (§7), and a network cannot test what it cannot stage.

Run the node:

```bash
python3 -m chain.net.node_main /srv/fin6 fin6-n03
```

It handles SIGTERM and SIGINT by stopping cleanly, so a systemd unit is
unremarkable — `Restart=on-failure`, `RestartSec=5`, `StandardOutput=append` to
a file, and the working directory set to the repository root. **Do not set
`Restart=always`**: the three deliberate fail-stops (`HaltRequired`,
`ReorgBeyondCeiling`, `LedgerInconsistent`) are the node refusing to guess, and
restarting it in a loop turns a diagnosable outage into a silent one.

Until the key-custody blocker in §0 is closed, the node's key comes from
`dev_keyring`. When it is closed, the key belongs in a file mode 600 owned by
the node's user, or in whatever the host offers that is better, and it is the
one thing on the machine that a backup must never carry in the clear.

## 5. Bring-up

1. **Before the hour.** Every operator has the same `genesis.json`, agrees on
   the chain id, has written `net.json` with the same `effective_ms`, and has
   run `python3 -m fin6.tests` once on the host that will run the node.
2. **Start everybody before epoch 1.** A node started late catches up
   (`admin_guide.md §8`), but the first epochs of a network with no history are
   the least interesting thing to debug under time pressure.
3. **Watch the first ten minutes** from any host that can reach the others:

```bash
python3 -m fin6 net status /srv/fin6
```

The four lines that matter, in order:

- `agreement: N/N reporting nodes agree at height H` — roots agreeing at a
  common height *is* consensus health, and `net status` exits non-zero when they
  do not;
- `height` rising by one per epoch on every node;
- `peers` reaching the roster size, and `directory` filling in;
- `protocol: … ALL READY`, and no `HALTED:` line.

4. **Then move money once**, end to end, and read the balance back with a light
   client rather than by asking a node — `fin6 light verify` proves each note
   against a header instead of trusting the answer.

Go / no-go, as a table somebody signs:

| check | pass |
|---|---|
| chain id computed independently by every operator | identical |
| document problems | none |
| document caveats | each read, each decided, in writing |
| reserved activation slots | at least one, and the count deliberate |
| `net status` | agreement at a common height, no halted node |
| a transfer | sent, included, and verified by a light client |
| a restart | one node stopped and restarted; it caught up |
| backups | taken, and **restored once**, before launch |

## 6. Day two

**Backups.** The store is three files — `chain.db`, `-wal`, `-shm`. Copying
`chain.db` from under a running node gives a database missing everything in the
write-ahead log. Stop the node and copy all three, or back up from a node that
is down. Back up the wallet seeds separately and treat them as money, because
they are. Everything else is derivable: a node can rebuild from peers or from a
state snapshot.

**Restore is a drill, not a plan.** Do it once before launch, from the backup
you actually take, onto a host you actually have.

**Catching up** happens by itself: blocks by range while the body window covers
the gap, then a state snapshot — manifest, header and certificate checked
*first*, then chunks verified against the digest before any of it is folded in.

**Upgrades** are `admin_guide.md §6` and `plan/network_update_design.md`. The one
sentence worth repeating here: a reserved slot is a deadline, not an option, and
the only abort is shipping that version as a deliberate no-op, on every node,
before the height.

**Retention.** Undo records reach 729 blocks (about four hours). A node that
reorganises beyond that cannot roll back and stops rather than diverge; it
re-syncs from a peer and does not decide for itself which branch was real.

## 7. Drills to run before you need them

The fault harness exists because a network cannot test what it cannot stage.
Run these on a testnet with the same topology as the real one:

| drill | how |
|---|---|
| a node dies | `fin6 net kill`, or SIGKILL the process; watch the quorum hold and the node catch up on restart |
| a silent node | `"behaviour": "silent"` — the view change should carry the epoch |
| an equivocating node | `"behaviour": "equivocating"` — a fault report should reach the register and the member should be suspended |
| a wrong clock | `"skew_ms"` — the honest failure that looks most like a bug |
| an un-upgraded build | an activation height on a `local` preset with one node left behind: watch it halt. Then repeat with a third of the roster behind, and watch the network stall — that is the failure with no runbook (`plan/network_update_design.md §3`) |
| a full disk | it is the one that happens |

## 8. Stopping a network

There is no "shut it down" command, and that is deliberate. A chain that must
stop permanently is a **freeze and a succession** — a terminal block, a claim
window, and a successor document (`succession_design.md`), none of which is
implemented. Until it is, the honest procedure is: stop the nodes, keep the
stores and the backups, and understand that nothing prevents somebody restarting
the chain later with old software.

## 9. What this guide does not cover

- **Key custody and an HSM path.** §0. It is the first thing to build.
- **A distributed era-0 ceremony.** §0, and it is the one that decides how
  trustworthy the result is.
- **Monitoring beyond `net status`.** There is no metrics endpoint; the status
  reply is JSON and a five-line exporter is an afternoon, but nobody has written
  it.
- **Any regulated deployment.** There is no audit, no formal review of the
  proof system, and `LedgerInconsistent` exists precisely because the authors
  expect to be wrong somewhere.
