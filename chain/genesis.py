"""The genesis document: what a network has to be trusted about, written down.

`docs/genesis_design.md` argues that a chain should be named after its genesis
rather than after a string somebody typed.  This is that:

    chain_id = "fin6:" + H(canonical encoding of the document)

`chain_id` is already threaded through every signature in the system —
proposals, attestations, fault reports, and the binding scalar inside every
proof — so making it a commitment turns each of those into a statement about
one specific setup, at no cost.  Two networks, or a network and its own
rehearsal, become structurally unable to confuse each other.

What is in the document is the answer to "who is trusted with what at t=0":
the roster and their keys, the parameters, the partition count, the turn-holder
map for era 0, the supply, the first view seed, and the founders' signatures
over all of it.

What is *not* here yet, and is tracked in the design: the supply is issued
rather than minted, so a reader can count the genesis notes and not add them up
(§2); era 0's root is not built from contributed leaves (§4); and the first
view seed is a value in the file rather than the output of a commit-reveal
(§5).  Each is called out by `verify()` as a caveat rather than passed over.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass

from .crypto import Signer, h_bytes, h_hex, verify_sig
from .hardening.params import HardeningParams
from .params import ChainParams
from .store import codec

FORMAT_VERSION = 1
ID_PREFIX = "fin6:"


class GenesisError(Exception):
    pass


@dataclass(frozen=True)
class NodeEntry:
    """One founder.  The public key is authoritative; nothing secret is here."""
    node_id: str
    region: str
    public_hex: str

    def as_tuple(self):
        return (self.node_id, self.region, self.public_hex)


@dataclass(frozen=True)
class GenesisDocument:
    network: str                      # a human label, never the identity
    params_fields: dict               # ChainParams minus chain_id, which is derived
    hardening_fields: dict
    tiers: int                        # how many tiers this network starts with
    n_partitions: int
    first_seed: str
    effective_time: str
    # Milliseconds, not seconds: the document is hashed, and a float that
    # round-trips differently on two builds is a chain split. Nothing in a
    # canonical encoding should be a float, which is why the codec has no
    # encoding for one.
    epoch_millis: int
    nodes: tuple                      # NodeEntry
    turn_holders: tuple               # node ids, in pool-slice order
    supply: dict                      # holder -> [note values]
    declared_total: int
    ratification_threshold: int
    ratifications: tuple = ()         # (node_id, signature hex)
    version: int = FORMAT_VERSION

    # ── identity ─────────────────────────────────────────────────────────────

    def body(self) -> dict:
        """Everything the identity commits to — the signatures cannot sign
        themselves, so they are the one thing left out."""
        return {
            "version": self.version,
            "network": self.network,
            "params": dict(sorted(self.params_fields.items())),
            "hardening": dict(sorted(self.hardening_fields.items())),
            "tiers": self.tiers,
            "n_partitions": self.n_partitions,
            "first_seed": self.first_seed,
            "effective_time": self.effective_time,
            "epoch_millis": self.epoch_millis,
            "nodes": [n.as_tuple() for n in self.nodes],
            "turn_holders": list(self.turn_holders),
            "supply": {k: list(v) for k, v in sorted(self.supply.items())},
            "declared_total": self.declared_total,
            "ratification_threshold": self.ratification_threshold,
        }

    def digest(self) -> str:
        return h_hex("genesis", codec.encode(self.body()))

    @property
    def chain_id(self) -> str:
        return ID_PREFIX + self.digest()

    def ratification_message(self) -> bytes:
        return h_bytes("genesis-ratify", self.digest())

    # ── derived objects ──────────────────────────────────────────────────────

    def chain_params(self) -> ChainParams:
        return ChainParams(chain_id=self.chain_id, **self.params_fields)

    def hardening_params(self) -> HardeningParams:
        return HardeningParams(**self.hardening_fields)

    def regions(self) -> dict:
        return {n.node_id: n.region for n in self.nodes}

    def keys(self) -> dict:
        return {n.node_id: n.public_hex for n in self.nodes}

    def quorum(self) -> int:
        p = self.chain_params()
        return p.quorum_size(len(self.nodes))

    # ── ratification ─────────────────────────────────────────────────────────

    def ratify(self, signer: Signer, node_id: str) -> "GenesisDocument":
        """Add one founder's signature over the digest."""
        entry = {n.node_id: n for n in self.nodes}.get(node_id)
        if entry is None:
            raise GenesisError(f"{node_id} is not in the roster")
        if entry.public_hex != signer.public_hex:
            raise GenesisError(f"{node_id}'s key does not match the roster")
        merged = dict(self.ratifications)
        merged[node_id] = signer.sign(self.ratification_message())
        return dataclasses.replace(self,
                                   ratifications=tuple(sorted(merged.items())))

    def verify(self) -> tuple:
        """The checklist from §8 of the design, as far as the code goes.

        Returns (ok, problems, caveats).  Caveats are the parts the design
        names and the implementation has not reached — reported rather than
        skipped, so nobody mistakes silence for a check.
        """
        problems, caveats = [], []
        if self.version != FORMAT_VERSION:
            problems.append(f"document version {self.version}")

        # 1. canonical: re-encoding the body must reproduce the same bytes.
        if codec.encode(codec.decode(codec.encode(self.body()))) != \
                codec.encode(self.body()):
            problems.append("the document does not round-trip canonically")

        # 2. the parameters have to be the ones this build knows.
        known = {f.name for f in dataclasses.fields(ChainParams)} - {"chain_id"}
        unknown = set(self.params_fields) - known
        missing = known - set(self.params_fields)
        if unknown:
            problems.append(f"unknown parameters {sorted(unknown)}")
        if missing:
            problems.append(f"parameters this build needs are absent: "
                            f"{sorted(missing)}")

        # 3. the roster: unique ids, unique keys, well-formed.
        ids = [n.node_id for n in self.nodes]
        if len(set(ids)) != len(ids):
            problems.append("duplicate node id in the roster")
        if len({n.public_hex for n in self.nodes}) != len(ids):
            problems.append("two founders share a key")
        for n in self.nodes:
            if len(n.public_hex) != 64:
                problems.append(f"{n.node_id}: not a raw Ed25519 key")

        # 4. ratifications.
        keys = self.keys()
        msg = self.ratification_message()
        good = set()
        for node_id, sig in self.ratifications:
            if node_id not in keys:
                problems.append(f"ratification by a non-founder {node_id}")
            elif not verify_sig(keys[node_id], msg, sig):
                problems.append(f"{node_id}'s ratification does not verify")
            else:
                good.add(node_id)
        if len(good) < self.ratification_threshold:
            problems.append(f"{len(good)} valid ratifications, "
                            f"{self.ratification_threshold} required")

        # 5. the tier count has to match what the roster can actually run.
        if self.tiers != 1:
            caveats.append("only a one-tier launch is implemented; a document "
                           "asking for three tiers will still start at one if "
                           "the roster forms a single grid")
        if self.n_partitions != 1 and self.tiers == 1:
            problems.append("a one-tier network has one grid, so K must be 1")

        # 6. the turn-holder map must cover the pool exactly once.
        hard = None
        try:
            hard = self.hardening_params()
        except (TypeError, ValueError) as exc:
            problems.append(f"hardening parameters: {exc}")
        if hard is not None and self.turn_holders:
            unknown = set(self.turn_holders) - set(ids)
            if unknown:
                problems.append(f"turns held by non-founders {sorted(unknown)}")
            if len(self.turn_holders) != len(set(self.turn_holders)):
                problems.append("a founder appears twice in the turn map")
            if hard.turns % len(self.turn_holders):
                caveats.append(
                    f"{hard.turns:,} turns do not divide evenly among "
                    f"{len(self.turn_holders)} holders")

        # 7. the supply.
        total = sum(sum(v) for v in self.supply.values())
        if total != self.declared_total:
            problems.append(f"issuance sums to {total}, document declares "
                            f"{self.declared_total}")
        caveats.append("the supply is issued, not minted: this checks the "
                       "declared total against the values in the document, "
                       "which only a party holding the openings can do. A "
                       "genesis mint transaction would make it checkable by "
                       "anyone (design §2)")
        caveats.append("era 0 is described by its holder map, not built from "
                       "contributed leaves (design §4)")
        caveats.append("the first view seed is a value in the document, not "
                       "the output of a commit-reveal (design §5)")
        return not problems, problems, caveats

    # ── serialisation ────────────────────────────────────────────────────────

    def to_json(self) -> str:
        out = self.body()
        out["nodes"] = [{"id": n.node_id, "region": n.region,
                         "public_hex": n.public_hex} for n in self.nodes]
        out["ratifications"] = [{"node_id": nid, "signature": sig}
                                for nid, sig in self.ratifications]
        out["chain_id"] = self.chain_id          # informational; always re-derived
        return json.dumps(out, indent=2, sort_keys=False) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "GenesisDocument":
        raw = json.loads(text)
        doc = cls(
            version=raw["version"],
            network=raw["network"],
            params_fields={k: (tuple(map(_retuple, v)) if isinstance(v, list) else v)
                           for k, v in raw["params"].items()},
            hardening_fields=dict(raw["hardening"]),
            tiers=raw["tiers"],
            n_partitions=raw["n_partitions"],
            first_seed=raw["first_seed"],
            effective_time=raw["effective_time"],
            epoch_millis=raw["epoch_millis"],
            nodes=tuple(NodeEntry(n["id"], n["region"], n["public_hex"])
                        for n in raw["nodes"]),
            turn_holders=tuple(raw["turn_holders"]),
            supply={k: list(v) for k, v in raw["supply"].items()},
            declared_total=raw["declared_total"],
            ratification_threshold=raw["ratification_threshold"],
            ratifications=tuple((r["node_id"], r["signature"])
                                for r in raw.get("ratifications", ())),
        )
        stated = raw.get("chain_id")
        if stated is not None and stated != doc.chain_id:
            raise GenesisError(
                f"the file says {stated}, the document hashes to "
                f"{doc.chain_id} — it has been edited since it was signed")
        return doc

    def __repr__(self):
        return (f"GenesisDocument({self.network}, {len(self.nodes)} nodes, "
                f"tiers={self.tiers}, {self.chain_id[:20]}…)")


def _retuple(v):
    """JSON has no tuples; ChainParams uses them for the proof policy."""
    return tuple(v) if isinstance(v, list) else v


def load(path) -> GenesisDocument:
    with open(path) as fh:
        return GenesisDocument.from_json(fh.read())


def save(doc: GenesisDocument, path):
    with open(path, "w") as fh:
        fh.write(doc.to_json())
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# Booting a network from a document
# ═══════════════════════════════════════════════════════════════════════════════

def dev_keyring(node_id: str) -> Signer:
    """Reproducible keys for a development network.

    A real deployment hands each node its own key material out of band; the
    document only ever carries public keys.  This is the convention the shipped
    config was generated with, and `boot` checks every derived key against the
    roster rather than trusting it.
    """
    return Signer.from_seed(f"validator:{node_id}")


def boot(doc: GenesisDocument, *, keyring=dev_keyring, store=None,
         strict: bool = True):
    """Build the network the document describes.  Returns (world, wallets).

    Refuses a document that does not ratify, and refuses a store that belongs
    to a different chain — a node that would compute different roots should
    stop rather than fork quietly.
    """
    ok, problems, _ = doc.verify()
    if strict and not ok:
        raise GenesisError("; ".join(problems))

    params = doc.chain_params()
    signers = {}
    for entry in doc.nodes:
        signer = keyring(entry.node_id)
        if signer.public_hex != entry.public_hex:
            raise GenesisError(
                f"{entry.node_id}: the key this node holds is not the key the "
                f"document names")
        signers[entry.node_id] = signer

    from .tiers import bootstrap_world
    world, wallets = bootstrap_world(
        doc.regions(), doc.supply, params, seed=doc.first_seed,
        signers=signers, note_seed=doc.digest())

    if len(world.topology.grid_ids()) != doc.n_partitions:
        raise GenesisError(
            f"the roster forms {len(world.topology.grid_ids())} grids, the "
            f"document says {doc.n_partitions}")

    if store is not None:
        held = store.get_meta("chain_id")
        if held is not None and held != params.chain_id:
            raise GenesisError(
                f"this store holds {held}, the document is {params.chain_id}")
        if store.is_empty():
            store.initialise(world.nodes[sorted(world.nodes)[0]].state)
            store.save_registers(world.registers)
        world.persist(store, [sorted(world.nodes)[0]])
    return world, wallets


# ═══════════════════════════════════════════════════════════════════════════════
# Building one
# ═══════════════════════════════════════════════════════════════════════════════

def draft(network: str, node_ids, params: ChainParams,
          hardening: HardeningParams, supply: dict, *,
          region: str = "genesis", tiers: int = 1, first_seed: str = "",
          effective_time: str = "1970-01-01T00:00:00Z",
          epoch_millis: int | None = None,
          keyring=dev_keyring,
          ratification_threshold: int | None = None) -> GenesisDocument:
    """Assemble an unratified document.  `first_seed` defaults to the roster's
    own digest, which is not a commit-reveal and is marked as such."""
    nodes = tuple(NodeEntry(nid, region, keyring(nid).public_hex)
                  for nid in node_ids)
    fields = {f.name: getattr(params, f.name)
              for f in dataclasses.fields(ChainParams) if f.name != "chain_id"}
    hfields = {f.name: getattr(hardening, f.name)
               for f in dataclasses.fields(HardeningParams)}
    n = len(nodes)
    return GenesisDocument(
        network=network,
        params_fields=fields,
        hardening_fields=hfields,
        tiers=tiers,
        n_partitions=1 if tiers == 1 else 0,
        first_seed=first_seed or h_hex("first-seed", network,
                                       [x.node_id for x in nodes]),
        effective_time=effective_time,
        epoch_millis=(epoch_millis if epoch_millis is not None
                      else round(hardening.block_interval * 1000)),
        nodes=nodes,
        turn_holders=tuple(x.node_id for x in nodes),
        supply=dict(supply),
        declared_total=sum(sum(v) for v in supply.values()),
        ratification_threshold=(ratification_threshold
                                if ratification_threshold is not None
                                else params.quorum_size(n)),
    )


def ratify_all(doc: GenesisDocument, keyring=dev_keyring) -> GenesisDocument:
    for entry in doc.nodes:
        doc = doc.ratify(keyring(entry.node_id), entry.node_id)
    return doc


# ═══════════════════════════════════════════════════════════════════════════════
# The shipped seven-node document
# ═══════════════════════════════════════════════════════════════════════════════

GENESIS_7 = "config/genesis-7.json"

#: Seven is the smallest roster that tolerates two Byzantine faults: n = 3f+1
#: at f = 2, and the register's 2/3 rule lands on a quorum of 5 = 2f+1 without
#: adjustment.  Seated it is the leader alone in front, a row of five and a row
#: of one — diameter 3, so six rounds a ceremony.
GENESIS_7_IDS = tuple(f"fin6-n{i:02d}" for i in range(1, 8))


def draft_seven(network: str = "fin6-genesis-7") -> GenesisDocument:
    """The document this repository ships, assembled from scratch."""
    from .hardening.params import PRODUCTION
    from .params import DEMO
    params = dataclasses.replace(DEMO, attend_threshold=40, grid_size=7,
                                 row_size=5)
    supply = {"treasury": [1000, 900, 800, 700, 600]}
    return ratify_all(draft(network, GENESIS_7_IDS, params, PRODUCTION, supply))


if __name__ == "__main__":                                   # pragma: no cover
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else GENESIS_7
    doc = draft_seven()
    ok, problems, caveats = doc.verify()
    save(doc, target)
    print(f"wrote {target}")
    print(f"  chain_id  {doc.chain_id}")
    print(f"  roster    {len(doc.nodes)} nodes, quorum {doc.quorum()}, "
          f"tolerates {len(doc.nodes) - doc.quorum()} faults")
    print(f"  ratified  {len(doc.ratifications)}/{doc.ratification_threshold} "
          f"required")
    print(f"  verifies  {ok} {problems if problems else ''}")
    for caveat in caveats:
        print(f"  caveat    {caveat}")
