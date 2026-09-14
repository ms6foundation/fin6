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
import hashlib
import json
from dataclasses import dataclass

from .crypto import Signer, h_bytes, h_hex, verify_sig
from .hardening import contrib
from .hardening.params import HardeningParams
from . import protocol
from .params import ChainParams
from .store import codec

FORMAT_VERSION = 1

#: What a document is for.  See `GenesisDocument.purpose`.
LAUNCH_PURPOSE = "launch"
TEST_PURPOSE = "test"
PURPOSES = (LAUNCH_PURPOSE, TEST_PURPOSE)

#: The era-0 block's field names, in the order a document writes them.
ERA0_FIELDS = ("root", "pub_seed", "tree_height", "turns", "scheme",
               "contributions")


def canonical_era0(era0: dict) -> dict:
    """Total and order-fixing, so `body()` never depends on how a dict was
    built.  Says nothing about whether the contents are *right* — that is
    `verify`'s job, and keeping the two apart is what lets a document with a
    nonsense era 0 be reported on rather than raise out of its own digest."""
    if not era0:
        return {}
    out = {}
    for name in ERA0_FIELDS:
        if name not in era0:
            continue
        value = era0[name]
        if name == "contributions":
            value = sorted((list(c) for c in value),
                           key=lambda c: (c[1] if len(c) > 1 else 0))
        out[name] = value
    for name in sorted(set(era0) - set(ERA0_FIELDS)):   # keep the unknown
        out[name] = era0[name]                          # so verify can refuse it
    return out
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
    #: {protocol version: activation height}.  A chain's whole upgrade
    #: schedule, inside the thing its identity is the hash of — so scheduling
    #: a rule change in advance is a number, and adding one afterwards is a
    #: new document and, by construction, a new chain.  See chain/protocol.py.
    activations: dict = dataclasses.field(default_factory=dict)
    #: "launch" or "test".  The parameter floor in `ChainParams.assess` would
    #: refuse every document the test suite and the runnable demo build, since
    #: those deliberately use undersized commitments to finish in a second.
    #: Rather than give the check an off switch that a founder could reach for,
    #: the document says what it is *for*, inside the bytes its identity is the
    #: hash of and inside the signatures.  A test document cannot be quietly
    #: promoted: changing this word changes the chain id.
    purpose: str = LAUNCH_PURPOSE
    #: Era 0 of the hardening pool, as a ceremony rather than as a seed
    #: somebody had: the root, the public randomiser, and one signed claim per
    #: holder to a contiguous slice of the turns.  A holder's share of the pool
    #: is its rewrite ceiling exactly (`max_fork_depth`), so this map is the
    #: security parameter and not an operational detail — see
    #: chain/hardening/contrib.py and review A4.  Empty is allowed only for a
    #: test document.
    era0: dict = dataclasses.field(default_factory=dict)

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
            "activations": protocol.canonical(self.activations),
            "purpose": self.purpose,
            "era0": canonical_era0(self.era0),
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

    def schedule(self) -> dict:
        """{version: height}, validated."""
        return protocol.normalise(self.activations)

    def protocol_at(self, height: int) -> int:
        return protocol.expected_version(height, self.activations)

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

        # 2b. the parameters have to be *strong*, not merely well-named.  Until
        # now nothing read the values: a document could ask for four blinder
        # coordinates and a 12-bit range and verify clean.  `assess` is mq.md's
        # floor written down, and it is scoped to the tiers this document
        # launches, because a backend no tier verifies is pure carried weight.
        if self.purpose not in PURPOSES:
            problems.append(f"unknown purpose {self.purpose!r}")
        if not unknown and not missing:
            strength, strength_caveats = \
                self.chain_params().assess(tiers=self.tiers)
            caveats.extend(strength_caveats)
            if self.purpose == LAUNCH_PURPOSE:
                problems.extend(strength)
            else:
                caveats.append(
                    "this document is marked purpose=test and must not be "
                    "used to found a network")
                caveats.extend(f"test document, so not a problem here: {s}"
                               for s in strength)

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

        # 4a. and the threshold itself, which the document also declares.
        #
        # The review's A8: a document that says how many signatures it needs is
        # circular, and something outside the document has to say how many
        # founders are enough.  That something is governance and cannot be
        # code — but the *range* is not a governance question, and leaving it
        # unbounded meant a seven-node document could be founded by one
        # signature and still verify.
        #
        # Two bounds, and then the residual is named rather than hidden.  The
        # floor is the chain's own safety rule: a set of founders too small to
        # finalise a block has no business agreeing what the chain is.  At
        # launch the rule is stricter and the argument is simpler — before a
        # chain exists there is no history to protect and no cost to waiting,
        # so every founder the document names signs it.  A founder that will
        # not sign is a founder that should not be in the roster, and redrawing
        # the roster costs nothing at this point and is impossible later.
        n_founders = len(self.nodes)
        floor = self.chain_params().quorum_size(n_founders)
        if self.ratification_threshold > n_founders:
            problems.append(
                f"{self.ratification_threshold} ratifications required of "
                f"{n_founders} founders: unreachable")
        elif self.ratification_threshold < floor:
            problems.append(
                f"{self.ratification_threshold} ratifications required, but "
                f"{floor} founders are needed to finalise a block: a set too "
                f"small to agree a block cannot be enough to agree the chain")
        elif (self.purpose == LAUNCH_PURPOSE
                and self.ratification_threshold != n_founders):
            problems.append(
                f"a launch document is ratified by every founder it names; "
                f"this one names {n_founders} and requires "
                f"{self.ratification_threshold}")
        caveats.append(
            "what the threshold cannot settle is who is in the roster at all: "
            "unanimity among seven founders is unanimity among whoever chose "
            "the seven. That is governance, and it is outside this document "
            "by construction (review A8)")

        # 4b. the upgrade schedule.
        try:
            schedule = self.schedule()
        except protocol.ProtocolError as exc:
            problems.append(f"activation schedule: {exc}")
            schedule = {}
        if protocol.expected_version(1, schedule) > protocol.PROTOCOL_VERSION:
            problems.append(
                f"this document starts at protocol "
                f"{protocol.expected_version(1, schedule)} and this build "
                f"implements {protocol.PROTOCOL_VERSION}")
        ahead = sorted(v for v in schedule if v > protocol.PROTOCOL_VERSION)
        if ahead:
            caveats.append(
                f"protocol {ahead} activate later and this build implements "
                f"{protocol.PROTOCOL_VERSION}: a node running it will halt at "
                f"the first of those heights rather than fork")

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

        # 6b. era 0, if the document builds one.
        #
        # A4: the holder map is the rewrite ceiling, exactly, because
        # `max_fork_depth = attacker turns / width` is a bound and not a
        # probability.  A map nobody attested is a security parameter on
        # trust, and era n+1 is authorised by era n, so era 0 is the anchor
        # for all of it.
        problems.extend(self._era0_problems(hard, ids, caveats))

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
        caveats.append("the first view seed is a value in the document, not "
                       "the output of a commit-reveal (design §5)")
        return not problems, problems, caveats

    def _era0_problems(self, hard, ids, caveats) -> list:
        """Era 0's contributed-leaf ceremony, checked from the document alone.

        What is checkable here: that the slices cover the pool exactly once,
        that every holder is a founder, that each claim is signed by the key
        the roster names it by, that the era agrees with the hardening
        parameters, and what the concentration implies for the rewrite ceiling.

        What is not: that the leaves behind each digest are real public keys —
        that needs the published transcript, and `verify_transcript` is the
        function for it. The document commits to the digests, so the two halves
        cannot disagree without one of them failing.
        """
        problems = []
        if not self.era0:
            if self.purpose == LAUNCH_PURPOSE:
                problems.append(
                    "era 0 has no contributed-leaf ceremony: the pool would be "
                    "one seed somebody holds, and a holder's share of the pool "
                    "is its rewrite ceiling exactly (review A4)")
            else:
                caveats.append("era 0 is described by its holder map, not "
                               "built from contributed leaves (design §4)")
            return problems

        unknown = set(self.era0) - set(ERA0_FIELDS)
        if unknown:
            problems.append(f"era 0 carries unknown fields {sorted(unknown)}")
        missing = [f for f in ERA0_FIELDS if f not in self.era0]
        if missing:
            problems.append(f"era 0 is missing {missing}")
            return problems

        if hard is not None:
            if self.era0["turns"] != hard.turns:
                problems.append(
                    f"era 0 has {self.era0['turns']:,} turns, the hardening "
                    f"parameters say {hard.turns:,}")
            if self.era0["tree_height"] != hard.tree_height:
                problems.append(
                    f"era 0's tree is 2^{self.era0['tree_height']}, the "
                    f"parameters say 2^{hard.tree_height}")
            if self.era0["scheme"] != hard.wots_scheme:
                problems.append(
                    f"era 0's leaves are {self.era0['scheme']!r} keys, the "
                    f"chain signs turns with {hard.wots_scheme!r}")

        expected = contrib.pub_seed_for(self.network, self.first_seed).hex()
        if self.era0["pub_seed"] != expected:
            problems.append(
                "era 0's public seed is not the one derived from the network "
                "and the first seed: a randomiser somebody chose is a "
                "randomiser somebody could have ground")

        try:
            claims = [contrib.Contribution(*c) for c in
                      self.era0["contributions"]]
        except TypeError:
            problems.append("era 0's contributions are not (holder, first, "
                            "count, digest, signature)")
            return problems
        try:
            contrib.check_coverage(claims, self.era0["turns"])
        except contrib.ContributionError as exc:
            problems.append(f"era 0's slices: {exc}")

        keys = self.keys()
        for c in claims:
            if c.holder not in ids:
                problems.append(f"era 0: {c.holder} holds turns and is not a "
                                f"founder")
                continue
            msg = contrib.Contribution.message(
                self.network, c.holder, c.first, c.count, c.digest,
                self.era0["root"], self.era0["scheme"])
            if not verify_sig(keys[c.holder], msg, c.signature):
                problems.append(
                    f"era 0: {c.holder}'s claim to turns {c.first}–"
                    f"{c.first + c.count - 1} is not signed by its roster key")

        # Concentration.  This is the number the whole ceremony exists for, so
        # it is stated in blocks and hours rather than left as a fraction.
        if hard is not None and claims:
            share = contrib.shares(claims, self.era0["turns"])
            worst, biggest = max(share.items(), key=lambda kv: kv[1])
            depth = hard.max_fork_depth(biggest)
            hours = depth * hard.block_interval / 3600
            if biggest * 3 > 1:
                problems.append(
                    f"era 0: {worst} holds {biggest:.0%} of the pool, which "
                    f"is a rewrite ceiling of {depth:,} blocks "
                    f"({hours:.1f} h) for one party")
            caveats.append(
                f"era 0's largest holder is {worst} with {biggest:.0%} of the "
                f"pool: {depth:,} blocks ({hours:.1f} h) of rewrite ceiling. "
                f"Nothing here proves two holders are not the same operator — "
                f"that is an identity claim, and it is signed rather than "
                f"assumed (review A4)")
        return problems

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
            activations={int(v): int(h)
                         for v, h in (raw.get("activations") or {}).items()},
            purpose=raw.get("purpose", LAUNCH_PURPOSE),
            era0=canonical_era0(raw.get("era0") or {}),
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

def first_seed_for(network: str, node_ids) -> str:
    """The default first seed: the roster's own digest.

    Public and derived rather than chosen, which is why era 0's public
    randomiser can be derived from it — and still not a commit-reveal, which
    the document says out loud.
    """
    return h_hex("first-seed", network, list(node_ids))


def dev_turn_seed(node_id: str) -> bytes:
    """Era-0 key material for a development network.

    A demonstration of the ceremony's *shape*: a real holder generates this on
    its own machine and never sends it anywhere, and a document whose turn
    seeds are derivable from a label has a pool anyone can spend. The shipped
    document is a demonstration in exactly this sense already — its roster keys
    come from `dev_keyring`.
    """
    return hashlib.sha256(f"fin6-turn-seed:{node_id}".encode()).digest()


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
    world.activations = doc.schedule()

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
          purpose: str = LAUNCH_PURPOSE,
          era0: dict | None = None,
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
        first_seed=first_seed or first_seed_for(
            network, [x.node_id for x in nodes]),
        effective_time=effective_time,
        epoch_millis=(epoch_millis if epoch_millis is not None
                      else round(hardening.block_interval * 1000)),
        nodes=nodes,
        turn_holders=tuple(x.node_id for x in nodes),
        supply=dict(supply),
        declared_total=sum(sum(v) for v in supply.values()),
        ratification_threshold=(
            ratification_threshold if ratification_threshold is not None
            # Every founder, for a launch; the safety floor for a test
            # document, which is what the suite's fixtures want.
            else (n if purpose == LAUNCH_PURPOSE else params.quorum_size(n))),
        purpose=purpose,
        era0=canonical_era0(era0 or {}),
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


#: Era 0's commitments for the shipped document.  A separate file because the
#: ceremony that produces it is 70,000 key generations — 19 s across four
#: processes, and not something to re-run every time a test builds a document.
#: Regenerate with `python3 -m chain.hardening.ceremony`.
GENESIS_7_ERA0 = "config/era0-7.json"


def load_era0(path: str = GENESIS_7_ERA0) -> dict:
    with open(path) as fh:
        return canonical_era0(json.load(fh))


def draft_seven(network: str = "fin6-genesis-7",
                era0: dict | None = None) -> GenesisDocument:
    """The document this repository ships, assembled from scratch."""
    from .hardening.params import PRODUCTION
    from .params import LAUNCH
    params = LAUNCH
    supply = {"treasury": [1000, 900, 800, 700, 600]}
    return ratify_all(draft(network, GENESIS_7_IDS, params, PRODUCTION, supply,
                            era0=era0 if era0 is not None else load_era0()))


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
