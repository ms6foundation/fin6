"""Where the first money comes from, and who can check how much.

A5 in the pre-genesis review, which is two problems arriving from opposite
directions.

*Nobody outside could check the supply.* The document listed the values and
`verify()` added them up — which only works for a party holding the openings.
Everyone else took the total on trust, on a chain whose whole argument is that
a reader can check things.

*And everybody inside could read it.* Genesis had to be reproducible across
processes, so note randomness was derived from the document digest. That fixed
seven nodes computing seven different genesis states and made every initial
holding permanently public.

A mint is a transaction shape with no inputs: the sum row reads
`-sum(outputs) = v`, so a verifier holding the declared total learns that the
outputs add up to it and learns nothing else. The openings are sealed to their
holders like any other payment's. Every node still computes the same genesis
state, because the state is the commitments — and those are in the document.

What authorises money appearing from nowhere is not a signature over a note;
there is no note to sign yet. It is the document, and the founders ratify that.
"""
import dataclasses

from .. import genesis
from ..crypto import Signer
from ..mint import GenesisMint, MintError, build_mint, verify_mint
from ..notes import Note
from ..params import DEMO

CTX = "fin6:" + "cd" * 32
PK = Signer.from_seed("treasury").public_hex


def _notes(values, params=DEMO, owner=PK):
    return [Note.create(v, owner, params) for v in values]


def _mint(values=(1000, 900, 600), params=DEMO, context=CTX, **kw):
    return build_mint(_notes(values, params), params, context, **kw)


# ── what a mint proves ───────────────────────────────────────────────────────

def test_a_mint_proves_its_total_and_nothing_else():
    m = _mint()
    assert m.total == 2500
    ok, why = verify_mint(m, DEMO, CTX)
    assert ok, why
    # The values are nowhere in it: the artifact is commitments, a total and a
    # proof.  (The openings are in `sealed`, which is encrypted to holders.)
    body = str(m.body())
    for value in (1000, 900, 600):
        assert f": {value}," not in body


def test_a_total_that_is_not_the_sum_is_refused():
    m = _mint()
    ok, why = verify_mint(dataclasses.replace(m, total=m.total + 1), DEMO, CTX)
    assert not ok
    # The claimed total is in the binding, so this is caught before the proof
    # is even reached — which is the cheap half doing its job.
    assert "binding scalar" in why or "do not add up" in why


def test_an_edited_commitment_is_refused():
    m = _mint()
    swapped = list(m.output_cms)
    swapped[0] = swapped[0][:-2] + ("00" if not swapped[0].endswith("00")
                                    else "11")
    ok, why = verify_mint(dataclasses.replace(m, output_cms=tuple(swapped)),
                          DEMO, CTX)
    assert not ok, why


def test_a_mint_for_another_document_is_refused():
    """The binding names the document this money belongs to, so a mint cannot
    be lifted into a different genesis."""
    ok, why = verify_mint(_mint(), DEMO, "fin6:" + "ef" * 32)
    assert not ok and "another document" in why


def test_a_mint_without_its_proof_is_refused():
    m = dataclasses.replace(_mint(), proofs={})
    ok, why = verify_mint(m, DEMO, CTX)
    assert not ok and f"no {DEMO.default_backend} proof" in why


def test_a_corrupt_proof_is_refused_and_does_not_raise():
    m = _mint()
    broken = dict(m.proofs)
    name = DEMO.default_backend
    broken[name] = {"scheme": name, "nonsense": True}
    ok, why = verify_mint(dataclasses.replace(m, proofs=broken), DEMO, CTX)
    assert not ok and ("malformed" in why or "failed" in why)


def test_an_output_outside_the_range_is_refused_at_build_time():
    good = _notes([5])[0]
    too_big = dataclasses.replace(good, value=DEMO.max_value)
    try:
        build_mint([too_big], DEMO, CTX)
    except MintError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("a value outside the range was minted")


def test_a_mint_needs_an_output():
    try:
        build_mint([], DEMO, CTX)
    except MintError as exc:
        assert "at least one output" in str(exc)
    else:
        raise AssertionError("an empty mint was built")


def test_the_artifact_round_trips_and_its_digest_covers_the_proof():
    m = _mint()
    back = GenesisMint.decode(m.encode())
    assert back.digest() == m.digest()
    assert verify_mint(back, DEMO, CTX)[0]
    other = _mint()                     # fresh randomness, same values
    assert other.digest() != m.digest(), \
        "the digest covers the proof, not just the total"


def test_the_sealed_openings_are_inside_the_binding():
    """A relay that swaps a ciphertext breaks the proof rather than quietly
    leaving a holder unable to find money that is provably theirs."""
    m = _mint(sealed=[b"a" * 40, b"b" * 40, b"c" * 40])
    assert verify_mint(m, DEMO, CTX)[0]
    swapped = dataclasses.replace(
        m, sealed=(m.sealed[1], m.sealed[0], m.sealed[2]))
    ok, why = verify_mint(swapped, DEMO, CTX)
    assert not ok and "binding" in why


# ── the document ─────────────────────────────────────────────────────────────

def test_the_shipped_document_mints():
    doc = genesis.load(genesis.GENESIS_7)
    assert doc.mint["total"] == doc.declared_total == 4_000
    assert len(doc.mint["outputs"]) == 5
    assert not any(v for v in doc.supply.values()), \
        "a minted document carries no values"
    ok, problems, _ = doc.verify()
    assert ok, problems


def test_the_shipped_artifact_is_the_one_the_document_commits_to():
    doc = genesis.load(genesis.GENESIS_7)
    artifact = genesis.load_mint_artifact()
    assert artifact.digest() == doc.mint["digest"]
    assert tuple(artifact.output_cms) == tuple(doc.mint["outputs"])
    ok, why = verify_mint(artifact, doc.chain_params(), doc.mint_context())
    assert ok, why


def test_the_mint_and_the_document_commit_to_each_other():
    """Not a cycle: the document commits to the artifact's digest, and the
    artifact binds to the document *without its mint block*."""
    doc = genesis.load(genesis.GENESIS_7)
    assert doc.mint_context() != doc.chain_id
    moved = dataclasses.replace(doc, network="somewhere-else")
    ok, why = verify_mint(genesis.load_mint_artifact(), doc.chain_params(),
                          moved.mint_context())
    assert not ok and "another document" in why


def test_a_minted_document_with_values_beside_it_is_refused():
    doc = genesis.load(genesis.GENESIS_7)
    loud = dataclasses.replace(doc, supply={"treasury": [1000, 3000]})
    problems = loud.verify()[1]
    assert any("carries no values" in p for p in problems), problems


def test_a_launch_document_that_issues_is_refused():
    """The other direction: a document that lists its supply in the clear is
    not a launch document, whatever it says about itself."""
    from ..hardening.params import PRODUCTION
    from ..params import LAUNCH
    from .test_era0 import _era0_for
    ids = genesis.GENESIS_7_IDS
    issued = genesis.ratify_all(genesis.draft(
        "t", ids, LAUNCH, PRODUCTION, {"treasury": [10]},
        era0=_era0_for(ids, "t")))
    problems = issued.verify()[1]
    assert any("issued rather than minted" in p for p in problems), problems


def test_a_minted_total_that_disagrees_with_the_document_is_refused():
    doc = genesis.load(genesis.GENESIS_7)
    lying = dataclasses.replace(doc, mint=dict(doc.mint, total=9_000))
    assert any("the mint totals" in p for p in lying.verify()[1])


def test_the_mint_is_inside_the_chain_id():
    doc = genesis.load(genesis.GENESIS_7)
    moved = dataclasses.replace(
        doc, mint=dict(doc.mint, digest="00" * 32))
    assert moved.chain_id != doc.chain_id


# ── booting ──────────────────────────────────────────────────────────────────

def test_a_node_boots_the_commitments_and_can_open_none_of_them():
    """The property the whole change is for. The node has the genesis UTXO
    set, can check the total against the artifact, and holds no opening."""
    doc = genesis.load(genesis.GENESIS_7)
    world, wallets = genesis.boot(doc)
    node = world.nodes[sorted(world.nodes)[0]]
    assert node.state.utxo.size == len(doc.mint["outputs"])
    assert wallets["treasury"].balance() == 0
    for cm in doc.mint["outputs"]:
        assert cm in node.state.utxo, cm


def test_every_node_computes_the_same_genesis_state():
    """What deterministic issuance was for, kept — without the openings being
    a function of the document."""
    doc = genesis.load(genesis.GENESIS_7)
    a, _ = genesis.boot(doc)
    b, _ = genesis.boot(doc)
    roots = {w.nodes[n].state.utxo.root for w in (a, b) for n in w.nodes}
    assert len(roots) == 1


# ── a fixture other modules use ──────────────────────────────────────────────

_MINTS = {}


def mint_block_for(skeleton, values, params) -> dict:
    """The document block for a mint of `values`, bound to `skeleton`.

    Exported because every launch document needs one now, and building it is
    the two-step dance the ceremony does: draft once without a mint to learn
    what the mint binds to, mint, then draft again carrying the block. No
    sealed openings — sealing needs an address, which lives in `wallet`, and
    a document verifies without them.
    """
    key = (skeleton.mint_context(), tuple(values), params.name)
    if key not in _MINTS:
        artifact = build_mint(_notes(values, params), params,
                              skeleton.mint_context())
        _MINTS[key] = {"total": artifact.total,
                       "outputs": list(artifact.output_cms),
                       "digest": artifact.digest()}
    return _MINTS[key]
