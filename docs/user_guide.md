# Holding money on fin6 — the user's guide

*Making a wallet, being paid, paying, and checking for yourself.*

This is the other half of the documentation; `docs/admin_guide.md` is for the
people running nodes. Everything here runs from the repository root against a
network someone has started for you — a local testnet, or a real one whose
`genesis.json` and `net.json` you have been given.

The one sentence that explains most of the rest: **values are hidden, and the
spend graph is not.** Amounts live in commitments and only the holder can open
them. Which note was spent to create which note is public. That is a
deliberate trade — confidential transactions, not shielded ones — and §7 says
what follows from it.

## 1. A wallet is one seed

```bash
python3 -m fin6 wallet new /tmp/fin6-testnet --name bob
```

```
wallet bob
  seed      /tmp/fin6-testnet/wallets/bob.seed  (mode 600 — this is the money)
  address   fin6q8v3…
```

The seed is the whole wallet. Everything else — addresses, viewing keys, the
notes file — is derived from it or can be rebuilt by scanning the chain, which
is why there is nothing else to back up and why the seed file is the one thing
you must not lose or leak.

On a testnet the seed phrase defaults to the wallet's name, and the command
tells you so: *"which is fine for a testnet and nowhere else."* For anything
real, pass `--phrase` with something you generated.

## 2. An address, and what is in one

```bash
python3 -m fin6 wallet address /tmp/fin6-testnet --name bob
```

An address starts with `fin6`, is base32, and carries a checksum — a typo is
refused rather than silently paid to nobody. Inside it are **three** keys, not
two:

| key | what it lets someone do |
|---|---|
| spend | be paid. It is the owner coordinate of every note sent to you. |
| view | read every note ever sent to this address, including ones nobody has sent yet. |
| detect | sort the chain's outputs into "possibly yours" and "certainly not" — and nothing more. |

The third one exists so the *work* of finding your money can be handed to
somebody else without handing them the ability to read it (§6).

An address also carries the key-agreement scheme its viewing and detection keys
are in. A build that does not implement that scheme refuses the address instead
of paying to it, because sealing an opening to keys the holder cannot read is
money that arrives and cannot be spent, with nothing on chain to say why.

A wallet can hold many addresses (`new_address`), and it watches all of them
when it scans.

## 3. Finding your money

Nobody tells you that you were paid. You look.

```bash
python3 -m fin6 wallet sync    /tmp/fin6-testnet --name bob
python3 -m fin6 wallet balance /tmp/fin6-testnet --name bob
```

```
synced bob against fin6-n01 to height 412
  found 2 new note(s), 1 spent
  balance 0 -> 250
```

A sync fetches the outputs published since you last looked and tries one
key-agreement per output — about 30 µs each, so keeping up with a block costs
milliseconds. A restore from seed alone is the same walk over the whole history:
slower, and the reason you need no backups.

`balance` lists the individual notes, because on this chain a balance is a set
of notes rather than a number:

```
250  in 3 note(s), scanned to height 412
   200  cm:4f2a91c0…  from height 388
    40  cm:0b17e5a2…  from height 402
    10  cm:9c4d0f31…  from height 402
```

Sync first, then read the balance. `balance` does not go to the network.

## 4. Paying someone

```bash
python3 -m fin6 wallet send /tmp/fin6-testnet --name bob \
        --to fin6q9x2… --amount 120 --fee 1
```

```
sent 120 (+1 fee) to fin6q9x2… via fin6-n01
  txid      tx:7c1e…
  proof     61,624 B in ['mpcith']
  sealed    2 openings, 388 B
  next      fin6 wallet sync /tmp/fin6-testnet --name bob
```

What that transaction contains: a proof that the inputs you spent were unspent
and that the amounts balance, without revealing any amount; a *sealed opening*
for each output, so the recipient can find and open theirs and so you can find
your own change; and a nullifier per input, which is what makes a second spend
of the same note impossible rather than merely detectable.

Fees are burned, not paid to anyone.

Submission is fire-and-forget by design — the node answers nothing. To find out
what happened, sync, or ask:

```python
from client.rpc import Client
Client(host, port, chain_id).txstatus("tx:7c1e…")
```

That is honest rather than convenient: a transaction has to survive gossip, a
grid's mempool and a ceremony before anything can be said about it.

## 5. Change comes home, and why that matters

The chain is partitioned: every note is spendable in exactly one grid, decided
by a hash of the note itself. **A transaction may only spend notes from one
partition** — one spending across two would need two grids to agree, which is
the thing partitioning exists to avoid. Such a transaction is not rejected so
much as homeless: no grid may include it, and it sits in mempools until it is
forgotten.

Your wallet handles this without being asked. It selects inputs from a single
partition, and it steers change back into the partition it came from, so your
balance does not scatter one payment at a time. You will only notice it in one
case: **you have enough money, spread across partitions, and no single
partition holds enough.** Then a payment fails to select.

The fix is to gather:

```python
from wallet.store import Wallet          # the CLI has no consolidate command yet
tx, _ = wallet.consolidate()             # spends one partition's notes to yourself
```

It is the same transaction as a payment, pointed at the payer. It costs a fee
and a proof, and it is also the answer to a wallet that has accumulated many
small notes: every input is proved, so at some point the cheapest thing to do is
spend them all to yourself.

## 6. Letting someone else look for you

Scanning means trying every output. If you would rather not, give a node your
**detection secret** and let it pre-sort:

```bash
python3 -m fin6 wallet sync /tmp/fin6-testnet --name bob --tags 8
```

```
synced bob against fin6-n01 to height 412, node-sorted at 8 bits
  fetched 61 of 15,800 outputs (259x less to read)
  found 1 new note(s)
  the node now knows a set your outputs are hiding in
```

Read that last line before using it. The node learns a *set* your outputs are
inside — at 8 bits, roughly one output in 256 — and learns nothing about
amounts and cannot open anything. Fewer bits is a bigger haystack and more to
download; more bits is less to download and a smaller haystack. It is a dial
between bandwidth and privacy, and the default is to not use it at all.

A narrower grant exists for a single output: `Wallet.disclose` derives a key
that opens exactly one note, because the key comes from that output's own
ephemeral key. Use that for an auditor or a counterparty who needs to see one
payment. A viewing key, by contrast, opens everything ever sent to an address,
including what has not been sent yet.

## 7. Checking rather than being told

A node can lie to you. The light client does not ask it to be honest:

```bash
python3 -m fin6 light sync   /tmp/fin6-testnet          # follow the spine, verified
python3 -m fin6 light verify /tmp/fin6-testnet --name bob
```

```
bob against fin6-n01, at height 412
  proved       200  cm:4f2a91c0…       ok
  proved        40  cm:0b17e5a2…       ok
  UNPROVED      10  cm:9c4d0f31…       the node has no live note at that commitment
  proved   240
  unproved 10  — this client will not count these
```

`light sync` checks the tip's certificate against the register the ceremony ran
under, and checks that the new tip descends from the header it trusted before —
so a node cannot quietly move you onto a different chain. `light verify` then
proves each note is *unspent at that header*, with an inclusion proof of about
650 bytes that verifies in 19 µs. A spent note cannot produce one: spending
rewrites its leaf to a tombstone, so membership is the proof.

It exits non-zero if anything is unproved. That is the point — and an unproved
note is not necessarily stolen: the commonest reason is that it was spent from
another device. What the client will not do is repeat a claim it cannot
support.

If the nodes disagree with each other:

```bash
python3 -m fin6 light adjudicate /tmp/fin6-testnet
```

It asks every node, checks the work rather than counting votes, and says what
the work says — including how many blocks a holder of a given share of the pool
could rewrite.

## 8. Getting your genesis money

Two different chains, two different answers.

**On a testnet** the document *issues* its supply, and the openings are
derivable from the document — which is what makes this possible and is exactly
why it is not a launch:

```bash
python3 -m fin6 wallet import-genesis /tmp/fin6-testnet --holder treasury
```

**On a launch chain** the document *mints*: it carries commitments, and the
openings are sealed to their holders in a published artifact. Only the holder
can open them, and there is no CLI command for it yet:

```python
from wallet.genesis_mint import claim
notes = claim(artifact, "treasury", params)   # your notes, in mint order
```

Everyone can see the commitments and check that the total is what the document
declares. Nobody but you can turn one into money.

## 9. What to expect, and what not to

- **A payment is final when a block carrying it is finalised**, and one epoch is
  the cadence in the genesis document — 19.75 s on the shipped configuration.
  Below that, nothing has happened yet.
- **Nothing retries for you.** A submission the node shed, or one that arrived
  while a grid was busy, is not resent by anything. Sync, check, send again.
- **Amounts are private; the graph is not.** Anyone can see that a note was
  spent to create two others. Nobody can see for how much.
- **Your address links your payments to each other.** Use `new_address` for
  payments you do not want connected; the wallet watches every address it has
  issued, so there is no cost to using more of them.
- **The fee is burned.** There is no fee market and no priority to buy.
- **Ed25519 is a placeholder.** The rest of the stack is post-quantum by
  construction; the spend signature is not, and the repository says so rather
  than implying otherwise.

## 10. Recovering a wallet

Have the seed phrase, and:

```bash
python3 -m fin6 wallet new  <root> --name bob --phrase "<the phrase>" --force
python3 -m fin6 wallet sync <root> --name bob
```

The sync walks the chain from the beginning and finds every note ever sealed to
any address that seed derives. The notes file is a cache, not the wallet.

What this does **not** recover: notes that carry no sealed opening. Genesis
notes on a testnet are the only ones — they are issued outside any transaction,
which is what `import-genesis` is for, and which is exactly why a launch mints
instead.

## Rendered version

Diagrammed: https://claude.ai/code/artifact/a633ae02-011a-40d7-b9b2-afff04b8fb05
