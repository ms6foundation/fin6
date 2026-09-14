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

from .. import protocol as pr
from ..crypto import Signer
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
