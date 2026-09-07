"""The genesis document, and a network that starts at one tier.

The document's job is to make "who is trusted with what at t=0" checkable, so
most of these tests are about refusing things: an edited file, a missing
signature, a key that is not the one the roster names, a store from another
chain.
"""
import dataclasses
import os
import tempfile

from .. import genesis
from ..crypto import Signer
from ..hardening.params import PRODUCTION
from ..network import transfer
from ..params import DEMO
from ..store.codec import CodecError, encode
from ..store.db import ChainStore
from ..tiers import run_tiered_epoch

IDS = tuple(f"g{i}" for i in range(7))
PARAMS = dataclasses.replace(DEMO, attend_threshold=40, grid_size=7, row_size=5)
SUPPLY = {"treasury": [1000, 900, 800]}

_CACHE = {}


def draft(**kw):
    return genesis.draft("test-net", IDS, PARAMS, PRODUCTION, SUPPLY, **kw)


def ratified():
    if "doc" not in _CACHE:
        _CACHE["doc"] = genesis.ratify_all(draft())
    return _CACHE["doc"]


# ── identity ─────────────────────────────────────────────────────────────────

def test_the_chain_is_named_after_its_genesis():
    doc = ratified()
    assert doc.chain_id.startswith("fin6:")
    assert doc.chain_id == genesis.ID_PREFIX + doc.digest()
    assert doc.chain_params().chain_id == doc.chain_id


def test_changing_anything_changes_the_identity():
    """Every signature in the system is domain-separated by chain_id, so this
    is what stops two networks confusing each other."""
    doc = ratified()
    for change in (dict(network="other"),
                   dict(tiers=3),
                   dict(declared_total=doc.declared_total + 1),
                   dict(first_seed="different"),
                   dict(turn_holders=tuple(reversed(doc.turn_holders)))):
        assert dataclasses.replace(doc, **change).chain_id != doc.chain_id, change


def test_the_ratifications_are_not_part_of_the_identity():
    """They cannot be: they sign the digest, so the digest cannot cover them."""
    doc = draft()
    assert genesis.ratify_all(doc).chain_id == doc.chain_id


def test_the_document_carries_no_floats():
    """A float that round-trips differently on two builds is a chain split, so
    the codec refuses one and the cadence is stored in milliseconds."""
    doc = ratified()
    assert isinstance(doc.epoch_millis, int)
    encode(doc.body())                       # would raise if a float sneaked in
    try:
        encode({"cadence": 19.75})
    except CodecError:
        return
    raise AssertionError("the codec accepted a float")


# ── ratification ─────────────────────────────────────────────────────────────

def test_a_ratified_document_verifies():
    ok, problems, caveats = ratified().verify()
    assert ok, problems
    assert caveats, "the parts that are not implemented must be reported"


def test_too_few_signatures_is_refused():
    doc = draft()
    for nid in IDS[:3]:                      # threshold is 5 of 7
        doc = doc.ratify(genesis.dev_keyring(nid), nid)
    ok, problems, _ = doc.verify()
    assert not ok and any("ratifications" in p for p in problems)


def test_a_signature_from_the_wrong_key_is_refused():
    doc = draft()
    stranger = Signer.from_seed("not-a-founder")
    forged = stranger.sign(doc.ratification_message())
    doc = dataclasses.replace(doc, ratifications=((IDS[0], forged),))
    ok, problems, _ = doc.verify()
    assert not ok and any("does not verify" in p for p in problems)


def test_a_non_founder_cannot_ratify():
    doc = draft()
    try:
        doc.ratify(Signer.from_seed("outsider"), "outsider")
    except genesis.GenesisError as exc:
        assert "roster" in str(exc)
        return
    raise AssertionError("ratified by someone not in the roster")


def test_a_founder_cannot_sign_with_a_key_it_does_not_own():
    doc = draft()
    try:
        doc.ratify(Signer.from_seed("someone-else"), IDS[0])
    except genesis.GenesisError as exc:
        assert "key does not match" in str(exc)
        return
    raise AssertionError("accepted a signature under the wrong key")


def test_a_mismatched_supply_total_is_refused():
    doc = dataclasses.replace(ratified(), declared_total=1)
    ok, problems, _ = doc.verify()
    assert not ok and any("declares" in p for p in problems)


# ── the file ─────────────────────────────────────────────────────────────────

def test_the_file_round_trips():
    doc = ratified()
    assert genesis.GenesisDocument.from_json(doc.to_json()) == doc


def test_an_edited_file_is_refused_on_sight():
    doc = ratified()
    text = doc.to_json().replace('"tiers": 1', '"tiers": 3')
    try:
        genesis.GenesisDocument.from_json(text)
    except genesis.GenesisError as exc:
        assert "edited since it was signed" in str(exc)
        return
    raise AssertionError("loaded a document that had been edited")


def test_the_shipped_config_is_what_the_code_produces():
    """A tripwire: the checked-in file must be reproducible from the source,
    so nobody can quietly hand-edit the network everyone launches."""
    path = os.path.join(os.path.dirname(__file__), "..", "..",
                        genesis.GENESIS_7)
    if not os.path.exists(path):
        return
    on_disk = genesis.load(path)
    assert on_disk == genesis.draft_seven(), \
        "config/genesis-7.json is stale — regenerate with python3 -m chain.genesis"


def test_the_shipped_config_verifies_and_describes_seven_nodes():
    path = os.path.join(os.path.dirname(__file__), "..", "..",
                        genesis.GENESIS_7)
    if not os.path.exists(path):
        return
    doc = genesis.load(path)
    ok, problems, _ = doc.verify()
    assert ok, problems
    assert len(doc.nodes) == 7
    assert doc.quorum() == 5, "n = 3f+1 at f = 2 gives a quorum of 2f+1"
    assert len(doc.nodes) - doc.quorum() == 2
    assert doc.tiers == 1 and doc.n_partitions == 1
    assert sorted(doc.turn_holders) == sorted(n.node_id for n in doc.nodes)


# ── booting ──────────────────────────────────────────────────────────────────

def test_booting_gives_a_world_that_matches_the_document():
    doc = ratified()
    world, wallets = genesis.boot(doc)
    assert world.params.chain_id == doc.chain_id
    assert set(world.nodes) == set(IDS)
    assert len(world.topology.grid_ids()) == 1
    assert wallets["treasury"].balance() == doc.declared_total
    reg = world.registers[world.topology.grid_ids()[0]]
    assert len(reg.attesters()) == 7, "the founding cohort skips the gate"
    assert reg.quorum(2, 3) == 5


def test_a_node_whose_key_is_not_the_documented_one_refuses_to_boot():
    doc = ratified()
    def wrong(node_id):
        return Signer.from_seed(f"impostor:{node_id}")
    try:
        genesis.boot(doc, keyring=wrong)
    except genesis.GenesisError as exc:
        assert "not the key the document names" in str(exc)
        return
    raise AssertionError("booted with keys the document does not name")


def test_an_unratified_document_does_not_boot():
    try:
        genesis.boot(draft())
    except genesis.GenesisError:
        return
    raise AssertionError("booted an unratified genesis")


def test_a_store_from_another_chain_is_refused():
    doc = ratified()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "node.db")
        store = ChainStore(path)
        genesis.boot(doc, store=store)
        assert store.get_meta("chain_id") == doc.chain_id
        store.close()

        other = dataclasses.replace(doc, network="a-different-network")
        other = genesis.ratify_all(dataclasses.replace(other, ratifications=()))
        store = ChainStore(path)
        try:
            genesis.boot(other, store=store)
        except genesis.GenesisError as exc:
            assert "this store holds" in str(exc)
            return
        finally:
            store.close()
    raise AssertionError("opened another chain's store")


# ── running at one tier ──────────────────────────────────────────────────────

def test_seven_nodes_run_a_one_tier_epoch():
    doc = ratified()
    world, wallets = genesis.boot(doc)
    tx, _ = transfer(wallets["treasury"], wallets["treasury"], 100, 5,
                     world.params)
    world.submit(tx)
    result = run_tiered_epoch(world, epoch=1, base_seed=doc.first_seed)
    assert result.finalised, result.reason
    assert result.tiers == 1
    block = result.block
    assert block.header.tiers == 1
    assert block.header.chain_id == doc.chain_id
    assert sum(1 for _ in block.transactions()) == 1
    world.apply_network_block(block)
    assert world.height == 1


def test_the_chain_keeps_the_same_block_format_at_one_tier():
    """The whole point of collapsing rather than skipping: an archive, a
    snapshot and a verifier see one kind of history."""
    from ..store import archive, codec
    doc = ratified()
    world, wallets = genesis.boot(doc)
    tx, _ = transfer(wallets["treasury"], wallets["treasury"], 120, 5,
                     world.params)
    world.submit(tx)
    block = run_tiered_epoch(world, epoch=1, base_seed=doc.first_seed).block
    assert codec.decode(codec.encode(block)).hash() == block.hash()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "era0.seg")
        with archive.ArchiveWriter(path, retention=archive.COMPACT) as w:
            w.append(block)
        back = archive.ArchiveReader(path).get(block.height)
        assert back.hash() == block.hash()
        assert back.header.tiers == 1
