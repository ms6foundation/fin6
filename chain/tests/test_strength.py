"""Whether the numbers in a genesis document are strong enough to launch.

`verify()` checked that the parameter *names* were the ones this build knows.
It never read a value.  A document asking for four blinder coordinates and a
12-bit range — which is what the shipped `config/genesis-7.json` asked for —
verified clean, because nothing in the repository had an opinion about what a
good parameter was except a paragraph in `mq/mq.md`.

`ChainParams.assess` is that paragraph as code, and these tests are mostly
about the documents it is supposed to *refuse*.  The check has to be in
`verify()` rather than in a launch script: verify is what a founder runs
before signing, and a founder is the only party who can still fix this.
"""
import dataclasses

from .. import genesis as genesis_mod
from ..genesis import (draft, draft_seven, ratify_all, load, GENESIS_7,
                       LAUNCH_PURPOSE, TEST_PURPOSE)
from ..hardening.params import PRODUCTION  # noqa: F401  (documented below)
from .test_era0 import SMALL, _era0_for
from ..params import (DEMO, LAUNCH, STRONG, PRESETS, BLINDERS_128,
                      RECOMMENDED_FOLDS, NOTE_FIXED_COORDS)

IDS = tuple(f"n{i}" for i in range(7))
SUPPLY = {"treasury": [1000, 900, 800, 700, 600]}
EMPTY = {"treasury": []}


# A small hardening preset, and era 0's ceremony built once for the whole
# module. Nothing here is about hardening — these tests are about the chain
# parameters — but a launch document needs a real era 0 since review A4, and
# `PRODUCTION`'s is 70,000 key generations.
def _doc(params, **kw):
    """A document whose *parameters* are the subject. It still has to be a
    valid launch document in every other respect, so it carries a real era-0
    ceremony and a mint — both built once and cached, since neither is what
    these tests are about."""
    from .test_mint import mint_block_for

    kw.setdefault("era0", _era0_for(IDS, "t"))
    if kw.pop("issued", False):
        return ratify_all(draft("t", IDS, params, SMALL, SUPPLY, **kw))
    common = dict(kw)
    skeleton = draft("t", IDS, params, SMALL, EMPTY, declared_total=10,
                     **common)
    return ratify_all(draft("t", IDS, params, SMALL, EMPTY,
                            mint=mint_block_for(skeleton, (10,), params),
                            **common))


def _problems(params, **kw):
    return " | ".join(_doc(params, **kw).verify()[1])


# ── the presets ──────────────────────────────────────────────────────────────

def test_the_demo_preset_cannot_be_launched():
    """The preset named for an afternoon's testing should say so when someone
    tries to found a network on it."""
    said = _problems(DEMO)
    assert "Groebner" in said, said
    assert "range_bits" in said, said
    assert not DEMO.launchable()


def test_the_launch_preset_verifies_clean():
    ok, problems, _ = _doc(LAUNCH).verify()
    assert ok, problems
    assert LAUNCH.launchable()


def test_the_shipped_document_is_launchable():
    """The tripwire that would have caught this: the config in the repository
    is the one a founder reads, so it is the one that has to pass."""
    doc = load(GENESIS_7)
    ok, problems, _ = doc.verify()
    assert ok, problems
    assert doc.chain_params().launchable(tiers=doc.tiers)
    assert doc.chain_params().note_blinders == BLINDERS_128
    assert doc.chain_params().note_folds == RECOMMENDED_FOLDS


def test_draft_seven_is_the_shipped_document():
    assert draft_seven().digest() == load(GENESIS_7).digest()


def test_every_preset_assesses_without_raising():
    for name, p in PRESETS.items():
        problems, caveats = p.assess()
        assert isinstance(problems, list) and isinstance(caveats, list), name


# ── the floor, item by item ──────────────────────────────────────────────────

def test_a_hidden_block_inside_groebner_range_is_a_problem_not_a_caveat():
    weak = dataclasses.replace(LAUNCH, n_note=NOTE_FIXED_COORDS + 8)
    problems, _ = weak.assess()
    assert any("Groebner" in p for p in problems), problems


def test_a_short_but_not_absurd_hidden_block_is_a_caveat():
    """44 blinders is what STRONG carried while its docstring claimed it was
    sized per mq.md.  That is a judgement somebody should have to look at, not
    a refusal."""
    near = dataclasses.replace(LAUNCH, n_note=NOTE_FIXED_COORDS + 44)
    problems, caveats = near.assess()
    assert not problems, problems
    assert any("blinders is below" in c for c in caveats), caveats


def test_a_high_fold_count_is_a_caveat():
    folded = dataclasses.replace(LAUNCH, note_folds=8)
    problems, caveats = folded.assess()
    assert not problems
    assert any("fold rows" in c for c in caveats), caveats


def test_a_twelve_bit_note_is_not_an_amount_of_money():
    small = dataclasses.replace(LAUNCH, range_bits=12)
    problems, _ = small.assess()
    assert any("range_bits" in p for p in problems), problems


def test_soundness_below_eighty_bits_is_refused():
    for field in ("zk_rounds", "security_bits"):
        weak = dataclasses.replace(LAUNCH, **{field: 40})
        problems, _ = weak.assess()
        assert any(field in p for p in problems), (field, problems)


# ── internal consistency: fields that cannot all be right at once ────────────

def test_a_default_backend_nobody_proves_in_is_refused():
    bad = dataclasses.replace(LAUNCH, default_backend="ssh5")
    assert any("default_backend" in p for p in bad.assess()[0])


def test_a_tier_verifying_with_a_backend_no_wallet_proves_is_refused():
    bad = dataclasses.replace(LAUNCH,
                              proof_policy=((0, "ssh3"),
                                            (1, "mpcith"),
                                            (2, "mpcith")))
    assert any("no wallet proves" in p for p in bad.assess()[0])


def test_a_quorum_below_two_thirds_is_refused():
    bad = dataclasses.replace(LAUNCH, quorum_num=1, quorum_den=2)
    assert any("two thirds" in p for p in bad.assess()[0])


def test_carried_backends_are_counted_against_the_tiers_that_run():
    """STRONG carries all three.  At one tier two of them are weight nothing
    verifies; at three tiers they are the policy."""
    one = STRONG.assess(tiers=1)[1]
    three = STRONG.assess(tiers=3)[1]
    assert any("3.27 MB" in c for c in one), one
    assert not any("3.27 MB" in c for c in three), three


# ── and it has to be wired in, not merely written ────────────────────────────

def test_verify_reads_the_values_and_not_only_the_names():
    """The regression this whole module exists for: a document whose fields
    are all present and all wrong."""
    ok, problems, _ = _doc(DEMO).verify()
    assert not ok
    assert problems


def test_the_tier_count_reaches_assess_through_the_document():
    doc = _doc(STRONG, tiers=1)
    assert any("3.27 MB" in c for c in doc.verify()[2])


# ── what a document is for ───────────────────────────────────────────────────

def test_a_test_document_may_carry_test_parameters():
    """The suite and the runnable demo need undersized commitments to finish
    in a second.  They say so in the document rather than switching the check
    off, which is why `purpose` is inside the hash."""
    ok, problems, caveats = _doc(DEMO, purpose=TEST_PURPOSE).verify()
    assert ok, problems
    assert any("must not be used to found a network" in c for c in caveats)
    assert any("Groebner" in c for c in caveats), caveats


def test_the_word_is_part_of_the_identity():
    """A test document cannot be quietly promoted: the same parameters under a
    different purpose are a different chain."""
    a = _doc(DEMO, purpose=TEST_PURPOSE)
    b = dataclasses.replace(a, purpose=LAUNCH_PURPOSE, ratifications=())
    assert a.chain_id != b.chain_id
    assert "purpose" in a.body()


def test_promoting_a_test_document_by_hand_is_refused():
    """Twice over: the parameters are refused under the new purpose, and the
    ratifications no longer verify because they signed the old word."""
    weak = dataclasses.replace(_doc(DEMO, purpose=TEST_PURPOSE),
                               purpose=LAUNCH_PURPOSE)
    ok, problems, _ = weak.verify()
    assert not ok
    assert any("Groebner" in p for p in problems), problems
    assert any("ratification" in p for p in problems), problems


def test_an_unknown_purpose_is_refused():
    odd = dataclasses.replace(_doc(LAUNCH), purpose="production")
    assert any("unknown purpose" in p for p in odd.verify()[1])


def test_the_shipped_document_is_for_launch():
    assert load(GENESIS_7).purpose == LAUNCH_PURPOSE


def test_a_document_with_no_purpose_field_reads_as_launch():
    """An older file predates the field.  Reading it as a launch document is
    the safe direction: it gets held to the floor rather than excused."""
    import json
    raw = json.loads(_doc(LAUNCH).to_json())
    raw.pop("purpose")
    raw.pop("chain_id")
    assert genesis_mod.GenesisDocument.from_json(
        json.dumps(raw)).purpose == LAUNCH_PURPOSE


# ── who is enough to found it (A8) ───────────────────────────────────────────

def test_a_launch_document_is_ratified_by_every_founder_it_names():
    weak = _doc(LAUNCH, ratification_threshold=5)
    ok, problems, _ = weak.verify()
    assert not ok
    assert any("every founder it names" in p for p in problems), problems


def test_a_threshold_below_the_quorum_rule_is_refused():
    """A set of founders too small to finalise a block cannot be enough to
    agree what the chain is."""
    weak = ratify_all(draft("t", IDS, LAUNCH, SMALL, SUPPLY,
                            era0=_era0_for(IDS, "t"),
                            purpose=TEST_PURPOSE, ratification_threshold=2))
    assert any("finalise a block" in p for p in weak.verify()[1])


def test_an_unreachable_threshold_is_refused():
    odd = _doc(LAUNCH, ratification_threshold=9)
    assert any("unreachable" in p for p in odd.verify()[1])


def test_the_shipped_document_is_unanimous():
    doc = load(GENESIS_7)
    assert doc.ratification_threshold == len(doc.nodes) == 7
    assert len(doc.ratifications) == 7


def test_what_the_threshold_cannot_settle_is_said_out_loud():
    assert any("who is in the roster at all" in c
               for c in _doc(LAUNCH).verify()[2])
