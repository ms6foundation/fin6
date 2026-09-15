"""The rule about when rules change.

The pre-genesis review's first finding was that `FORMAT_VERSION` existed twice
and both were rejection checks, so there was no mechanism by which a running
network could adopt a format change — which made every format change
permanent rather than merely difficult.

The property these tests are really about is the last one: a node that cannot
follow the rules **stops**. Applying a block under rules it knows would be a
silent fork, and an operator watching a running node would never find out.
"""
import dataclasses

from .. import genesis
from .. import protocol
from .. import protocol as pr
from ..crypto import Signer
from ..hardening.params import PRESETS, PRODUCTION
from ..params import DEMO
from ..net import handshake
from ..protocol import HaltRequired, ProtocolError

CHAIN = "fin6:" + "ab" * 32


# ── the schedule ─────────────────────────────────────────────────────────────

def test_a_chain_with_no_schedule_runs_version_one_for_ever():
    for height in (1, 10, 10_000_000):
        assert pr.expected_version(height, {}) == 1
        assert pr.expected_version(height, None) == 1


def test_a_version_takes_effect_at_its_height_and_not_before():
    schedule = {2: 100, 3: 500}
    assert pr.expected_version(99, schedule) == 1
    assert pr.expected_version(100, schedule) == 2
    assert pr.expected_version(499, schedule) == 2
    assert pr.expected_version(500, schedule) == 3


def test_a_schedule_written_by_hand_means_the_same_thing():
    """A document is written by hand as often as by code, and a schedule that
    means one thing in Python and another in a file is a fork with a date."""
    assert pr.normalise({"2": "100"}) == pr.normalise({2: 100}) == {2: 100}


def test_an_impossible_schedule_is_refused():
    for bad, fragment in (
            ({1: 10}, "1 is what a chain starts under"),
            ({2: 0}, "before the chain exists"),
            ({2: 500, 3: 100}, "must increase"),
            ({2: "soon"}, "not a number"),
    ):
        try:
            pr.normalise(bad)
        except ProtocolError as exc:
            assert fragment in str(exc), (bad, str(exc))
            continue
        raise AssertionError(f"accepted {bad}")


# ── a block names its rule set ───────────────────────────────────────────────

def test_a_block_claiming_the_wrong_rules_is_refused_either_way():
    schedule = {2: 100}
    assert pr.check(100, 2, schedule)[0]
    ok, why = pr.check(100, 1, schedule)
    assert not ok and "claims 1" in why, why
    assert not pr.check(99, 2, schedule)[0], "nor may it run ahead"


def test_claiming_an_older_rule_set_matters_as_much_as_a_newer_one():
    """It is exactly what an un-upgraded producer would do."""
    ok, why = pr.check(1_000, 1, {2: 500})
    assert not ok and "runs protocol 2" in why


def test_a_malformed_claim_never_raises():
    for claimed in (None, "2", 2.0, [], {"v": 2}):
        ok, _ = pr.check(10, claimed, {})
        assert not ok, claimed


# ── and a node that cannot follow it stops ───────────────────────────────────

def test_a_build_that_is_behind_halts_rather_than_forks():
    ahead = pr.PROTOCOL_VERSION + 1
    try:
        pr.require(500, {ahead: 500})
    except HaltRequired as exc:
        halt = exc
    else:
        raise AssertionError("applied a block under rules it does not know")
    assert halt.needs == ahead and halt.have == pr.PROTOCOL_VERSION
    assert halt.height == 500
    # The message is the whole product: an operator has to be able to act on it.
    assert "Upgrade" in str(halt) and str(ahead) in str(halt)
    assert "fork" in str(halt)


def test_a_build_that_is_current_does_not_halt():
    assert pr.require(10, {}) == 1


def test_it_halts_before_the_height_not_after():
    """Below the activation height the old rules are still the right rules."""
    ahead = pr.PROTOCOL_VERSION + 1
    assert pr.require(499, {ahead: 500}) == pr.PROTOCOL_VERSION
    try:
        pr.require(500, {ahead: 500})
    except HaltRequired:
        return
    raise AssertionError("did not halt at the activation height")


# ── what an operator sees ────────────────────────────────────────────────────

def test_readiness_answers_in_blocks_rather_than_in_prose():
    ahead = pr.PROTOCOL_VERSION + 1
    r = pr.readiness(400, {ahead: 500})
    assert r["blocks_to_next"] == 100 and r["next"][0] == ahead
    assert not r["ready"], "this build cannot run what is scheduled"
    assert r["unimplemented"] == [(ahead, 500)]


def test_a_network_with_nothing_scheduled_is_ready():
    r = pr.readiness(400, {})
    assert r["ready"] and r["next"] is None and r["unimplemented"] == []


# ── the document carries it, and the identity commits to it ─────────────────

def _doc(**kw):
    from ..genesis import draft_seven
    doc = draft_seven()
    return dataclasses.replace(doc, **kw) if kw else doc


def test_the_schedule_is_inside_the_chain_id():
    """Which is the point: adding an activation afterwards produces a
    different document and therefore a different chain."""
    plain = _doc()
    scheduled = dataclasses.replace(plain, activations={2: 1000},
                                    ratifications=())
    assert plain.chain_id != scheduled.chain_id
    assert "activations" in plain.body()


def test_a_document_scheduling_what_this_build_cannot_run_says_so():
    doc = dataclasses.replace(_doc(), activations={pr.PROTOCOL_VERSION + 1: 900},
                              ratifications=())
    ok, problems, caveats = doc.verify()
    assert any("halt" in c for c in caveats), caveats
    assert not any("activation schedule" in p for p in problems), problems


def test_a_document_that_starts_beyond_this_build_is_a_problem_not_a_caveat():
    doc = dataclasses.replace(_doc(), activations={pr.PROTOCOL_VERSION + 1: 1},
                              ratifications=())
    ok, problems, _ = doc.verify()
    assert not ok
    assert any("implements" in p for p in problems), problems


def test_a_document_with_a_broken_schedule_does_not_verify():
    doc = dataclasses.replace(_doc(), activations={2: 500, 3: 100},
                              ratifications=())
    ok, problems, _ = doc.verify()
    assert not ok and any("activation schedule" in p for p in problems)


# ── the handshake reports it, and the report is signed ──────────────────────

def test_the_claimed_version_is_signed():
    """An unsigned version field is one an attacker rewrites to make a current
    peer look stale on somebody's upgrade dashboard the week before an
    activation height."""
    signer = Signer.from_seed("v1")
    keys = {"v1": signer.public_hex}
    v = handshake.Verifier(CHAIN, "v0", keys, lambda: 3)
    hello = handshake.build(signer, CHAIN, "v1", "v0", 3)
    rewritten = dict(hello, protocol=99, nonce="ff" * 16)
    ok, why, _ = v.check(rewritten)
    assert not ok and "did not sign" in why, why


def test_a_peer_that_predates_the_field_still_authenticates():
    """Read as version 1 rather than refused: the field is advisory, and a
    handshake that broke on an older peer would be a worse outage than a
    dashboard that is one row out of date."""
    signer = Signer.from_seed("v1")
    keys = {"v1": signer.public_hex}
    v = handshake.Verifier(CHAIN, "v0", keys, lambda: 3)
    nonce = "ab" * 16
    old = {"node_id": "v1", "to": "v0", "epoch": 3, "nonce": nonce,
           "signature": signer.sign(
               handshake.message(CHAIN, "v1", "v0", 3, nonce, 1))}
    ok, why, who = v.check(old)
    assert ok, why
    assert v.stats()["peers"] == {"v1": 1}


# ── reserving somewhere to put a rule change ─────────────────────────────────

def test_a_launch_document_reserves_activation_heights():
    """Review C2 §8, and the one part of it that expires at genesis.

    The schedule is inside the hash the chain id is, so a chain that reserves
    nothing can never adopt a rule change — it can only be replaced by a
    different chain.  Partitioned finality, the only design that takes the
    supreme grid off the critical path, is exactly such a change.
    """
    doc = genesis.draft_seven()
    assert doc.schedule() == protocol.reserved_slots(PRODUCTION)
    assert doc.verify()[0], doc.verify()[1]
    assert min(protocol.RESERVED_SLOT_ERAS.values()) >= 365 * 86400 // PRODUCTION.era_seconds, \
        "a slot inside a year is a release deadline, not a reservation"


def test_the_document_says_the_slot_is_a_deadline():
    """A node that reaches an activation for a version it does not implement
    halts.  That is right, and it is the sort of thing a document should say
    before anybody signs it rather than after a network stops."""
    doc = genesis.draft_seven()
    caveats = doc.verify()[2]
    said = [c for c in caveats if "activate later" in c]
    assert said, caveats
    assert "halt" in said[0] and "no rule changes" in said[0], said[0]
    for height in protocol.reserved_slots(PRODUCTION).values():
        assert f"{height:,}" in said[0], "it should name the heights"
    assert "era " in said[0], "and the unit the slot was actually chosen in"


def test_a_chain_that_reserves_nothing_is_told_so():
    doc = dataclasses.replace(genesis.draft_seven(), activations={},
                              ratifications=())
    assert any("nowhere to put a rule change" in c for c in doc.verify()[2])


def test_a_test_document_reserves_nothing():
    """A fixture that halts at a height is a fixture with a fuse in it."""
    doc = genesis.draft("t", genesis.GENESIS_7_IDS[:4], DEMO, PRODUCTION,
                        {"alice": [10]}, purpose="test")
    assert doc.schedule() == {}


def test_the_next_activation_is_findable_without_scanning():
    slots = protocol.reserved_slots(PRODUCTION)
    assert protocol.next_activation(0, slots) == (2, slots[2])
    assert protocol.next_activation(slots[3], slots) is None
    assert protocol.next_activation(0, {}) is None


# ── one definition of the period, and it is the era ──────────────────────────

def test_a_slot_lands_on_an_era_rollover():
    """Not cosmetic: a rollover is when the signing pool is reallocated, so
    starting new rules at one means the turns that harden them were handed out
    after the change was known."""
    for preset in PRESETS.values():
        per_era = preset.blocks_per_era
        for version, height in protocol.reserved_slots(preset).items():
            assert (height - 1) % per_era == 0, (preset.name, version, height)
            assert (height - 1) // per_era == protocol.RESERVED_SLOT_ERAS[version]


def test_the_heights_come_from_the_chain_and_not_from_a_constant():
    """The bug this replaced: heights computed from "a year" and written down,
    so every chain got production's numbers whatever its era was."""
    production = protocol.reserved_slots(PRODUCTION)
    local = protocol.reserved_slots(PRESETS["local"])
    assert production != local
    assert local[2] < production[2] / 10, \
        "a five-day era should not reserve a height a year away"


def test_there_is_no_second_definition_of_a_year():
    """A year in blocks has three answers — the era as the chain counts it, the
    rounded interval, and the exact one — because `blocks_per_era` floors
    2,187.5 and 19.749 is a rounding of 19.7485714…  So the repository holds
    none of them: a slot is N eras, converted once.
    """
    assert not hasattr(protocol, "BLOCKS_PER_YEAR")
    year_by_rounded_interval = int(365 * 86400 / 19.749)
    year_by_exact_interval = int(365 * 86400 / PRODUCTION.block_interval)
    year_by_era = 730 * PRODUCTION.blocks_per_era
    assert len({year_by_rounded_interval, year_by_exact_interval,
                year_by_era}) == 3, "this is the ambiguity being avoided"
    assert protocol.reserved_slots(PRODUCTION)[2] == year_by_era + 1


def test_an_era_of_nothing_cannot_schedule_anything():
    class Silly:
        blocks_per_era = 0
    try:
        protocol.reserved_slots(Silly())
    except ProtocolError:
        return
    raise AssertionError("scheduled a slot against an era of no blocks")
