"""Claiming minted genesis money — the half the ledger cannot do.

The proof that the genesis commitments add up to the declared total lives with
the ledger, because the ledger verifies it. Sealing and opening live here,
because they need an *address*, and a validator has no business knowing what
one is.

The property these tests are about is the one review A5's second half asks for:
the initial holdings are not derivable from the document. A holder opens its own
notes out of the published artifact and nobody else's, and a node that boots the
document can check the total and open nothing.
"""
from chain.mint import verify_mint
from chain.params import DEMO

from ..genesis_mint import claim, holder_keys, mint_supply

CTX = "fin6:" + "ab" * 32
ENDOWMENTS = {"treasury": [1000, 900], "alice": [50], "bob": []}


def _mint(params=DEMO):
    return mint_supply(CTX, ENDOWMENTS, params)


def test_the_block_carries_commitments_and_a_total_and_no_values():
    block, artifact = _mint()
    assert block["total"] == 1950
    assert len(block["outputs"]) == 3
    assert block["digest"] == artifact.digest()
    assert "values" not in block and "supply" not in block


def test_the_mint_verifies_against_the_ledger_side():
    block, artifact = _mint()
    ok, why = verify_mint(artifact, DEMO, CTX)
    assert ok, why


def test_a_holder_opens_its_own_notes_and_only_its_own():
    _, artifact = _mint()
    assert sorted(n.value for n in claim(artifact, "treasury", DEMO)) \
        == [900, 1000]
    assert [n.value for n in claim(artifact, "alice", DEMO)] == [50]
    assert claim(artifact, "bob", DEMO) == [], "an endowment of nothing"
    assert claim(artifact, "mallory", DEMO) == [], \
        "a stranger opens nothing, and learns that much and no more"


def test_the_openings_are_not_a_function_of_the_document():
    """The bug this replaces: genesis randomness derived from the document
    digest made every opening derivable by anyone holding it. Two mints of the
    same endowments from the same context now share nothing."""
    a, b = _mint()[1], _mint()[1]
    assert a.total == b.total
    assert set(a.output_cms).isdisjoint(b.output_cms)


def test_a_claimed_note_reproduces_the_commitment_on_chain():
    """Self-proving, like every other opening: the holder is not taking the
    minter's word for an amount."""
    from chain.notes import note_id, note_vector

    _, artifact = _mint()
    for note in claim(artifact, "treasury", DEMO):
        assert note_id(note_vector(note, DEMO)) in artifact.output_cms


def test_a_genesis_holders_keys_come_from_its_name():
    """Which is what makes claiming possible at all, and what `fin6 wallet
    import-genesis` has always relied on."""
    assert holder_keys("treasury").address == holder_keys("treasury").address
    assert holder_keys("treasury").address != holder_keys("alice").address
