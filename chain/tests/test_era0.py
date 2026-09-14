"""Era 0 as a ceremony: contributed leaves, signed claims, and a visible share.

A4 in the pre-genesis review. `max fork depth = attacker's unspent turns /
width` is a bound rather than a probability, which makes a holder's share of
the pool its rewrite ceiling *exactly* — so the turn map is the security
parameter, and until now it was a list of names in a document with nothing
behind it. One master seed generated every leaf, which is to say one party
could sign every turn; `Era`'s own docstring said the distribution was
"modelled explicitly rather than assumed", and modelled is the operative word.

What a contributed era changes: each holder generates its own slice from its
own secret, publishes the public leaves, and signs a claim to exactly that
slice with the key the roster names it by. Nobody can sign outside their slice,
because the leaf they would have to match is somebody else's public key.

What it does not change, and the tests say so: nothing here proves two holders
are not the same operator.
"""
import dataclasses
import hashlib

from .. import genesis
from ..crypto import Signer
from ..genesis import GENESIS_7, GENESIS_7_ERA0, load, load_era0
from ..hardening import ceremony, contrib, wots
from ..hardening.params import DEMO, HardeningParams, PRODUCTION

HOLDERS = [f"h{i}" for i in range(4)]
SMALL = HardeningParams(name="tiny", turns=64, era_seconds=600, width=8,
                        difficulty_bits=8, tree_height=6)


def _seed(holder):
    return hashlib.sha256(f"turn-seed:{holder}".encode()).digest()


def _signer(holder):
    return Signer.from_seed(f"validator:{holder}")


_CACHE = {}


def _era0_for(holders, network: str) -> dict:
    """Era 0 for a document, built once per (roster, network).

    Cached because the ceremony is real work — every leaf is a WOTS key — and
    several modules need a launch document to be launchable.
    """
    key = (tuple(holders), network)
    if key not in _CACHE:
        fields, _ = ceremony.run(
            network, genesis.first_seed_for(network, holders), list(holders),
            SMALL, seed_of=_seed, signer_of=_signer)
        _CACHE[key] = fields
    return _CACHE[key]


def _run(holders=HOLDERS, hardening=SMALL, network="t", first_seed="s"):
    return ceremony.run(network, first_seed, holders, hardening,
                        seed_of=_seed, signer_of=_signer)


# ── the pool is dealt, and the deal is checkable ─────────────────────────────

def test_every_turn_is_claimed_exactly_once():
    parts = contrib.deal(HOLDERS, 70)
    assert [c for _, _, c in parts] == [18, 18, 17, 17], parts
    contrib.check_coverage([contrib.Contribution(h, f, c, "") for h, f, c
                            in parts], 70)


def test_a_gap_and_an_overlap_are_both_refused():
    good = [contrib.Contribution(h, f, c, "") for h, f, c
            in contrib.deal(HOLDERS, 64)]
    for bad, expect in (
            ([dataclasses.replace(good[1], first=good[1].first + 1)],
             "claimed by nobody"),
            ([dataclasses.replace(good[1], first=good[1].first - 1)],
             "overlaps")):
        claims = good[:1] + bad + good[2:]
        try:
            contrib.check_coverage(claims, 64)
        except contrib.ContributionError as exc:
            assert expect in str(exc), str(exc)
        else:
            raise AssertionError(f"expected {expect}")


def test_a_short_deal_is_refused():
    try:
        contrib.deal(HOLDERS, 2)
    except contrib.ContributionError as exc:
        assert "cannot be dealt" in str(exc)
    else:
        raise AssertionError("two turns were dealt to four holders")


# ── a holder can spend its own turns and nobody else's ───────────────────────

def test_a_holder_signs_inside_its_slice_and_the_leaf_matches():
    fields, era = _run()
    message = bytes(32)
    for index in (0, 17, SMALL.turns - 1):
        sig = era.sign(index, message)
        assert wots.verify(sig, era.pub_seed, index, message,
                           era.leaf_pk(index))


def test_a_holder_cannot_sign_outside_its_slice():
    """The property the whole shape exists for: not a rule that is enforced,
    a key that does not exist."""
    pub = contrib.pub_seed_for("t", "s")
    mine = contrib.HolderSlice("h0", 0, 16, _seed("h0"), pub)
    try:
        mine.sign_turn(20, bytes(32))
    except contrib.ContributionError as exc:
        assert "holds turns 0–15" in str(exc)
    else:
        raise AssertionError("a holder signed a turn it does not hold")


def test_a_forged_leaf_does_not_match_the_published_one():
    """And if it tried anyway: signing turn 20 with h0's seed produces a
    signature against h0's key, which is not the leaf turn 20 committed."""
    fields, era = _run()
    pub = era.pub_seed
    forged = wots.sign(_seed("h0"), pub, 20, bytes(32))
    assert not wots.verify(forged, pub, 20, bytes(32), era.leaf_pk(20))


def test_an_era_built_from_leaves_carries_no_secret():
    """A verifier can hold the whole era and spend none of it."""
    fields, era = _run()
    public = contrib.ContributedEra(
        0, era.pub_seed, SMALL.tree_height, SMALL.turns,
        [era.leaf_pk(i) for i in range(SMALL.turns)])
    assert public.root == era.root
    try:
        public.sign(0, bytes(32))
    except contrib.ContributionError as exc:
        assert "belongs to another holder" in str(exc)
    else:
        raise AssertionError("a verifier signed a turn")


# ── the transcript ───────────────────────────────────────────────────────────

def test_the_published_leaves_rebuild_the_committed_root():
    fields, era = _run()
    leaves = [era.leaf_pk(i) for i in range(SMALL.turns)]
    ok, why = ceremony.verify_transcript(fields, leaves)
    assert ok, why


def test_one_altered_leaf_fails_the_transcript():
    fields, era = _run()
    leaves = [era.leaf_pk(i) for i in range(SMALL.turns)]
    leaves[9] = bytes(32)
    ok, why = ceremony.verify_transcript(fields, leaves)
    assert not ok and "do not match the digest" in why


def test_an_invented_digest_fails_the_transcript():
    """The half the document cannot check alone, and the reason it does not
    have to: the two commitments cannot disagree without one of them failing."""
    fields, era = _run()
    fields = dict(fields)
    first = list(fields["contributions"][0])
    first[3] = "00" * 32
    fields["contributions"] = [first] + [list(c) for c
                                         in fields["contributions"][1:]]
    ok, why = ceremony.verify_transcript(
        fields, [era.leaf_pk(i) for i in range(SMALL.turns)])
    assert not ok and "do not match the digest" in why


# ── the document ─────────────────────────────────────────────────────────────

def _doc(**kw):
    fields = _era0_for(genesis.GENESIS_7_IDS, "t")
    return genesis.ratify_all(genesis.draft(
        "t", genesis.GENESIS_7_IDS, __import__(
            "chain.params", fromlist=["LAUNCH"]).LAUNCH,
        SMALL, {"treasury": [10]}, era0=kw.pop("era0", fields), **kw))


def test_a_launch_document_without_a_ceremony_is_refused():
    doc = _doc(era0={})
    ok, problems, _ = doc.verify()
    assert not ok
    assert any("one seed somebody holds" in p for p in problems), problems


def test_a_ceremony_the_founders_signed_verifies():
    ok, problems, _ = _doc().verify()
    assert ok, problems


def test_a_claim_signed_by_the_wrong_key_is_refused():
    doc = _doc()
    era0 = dict(doc.era0)
    claims = [list(c) for c in era0["contributions"]]
    claims[0][4] = Signer.from_seed("validator:stranger").sign(
        contrib.Contribution.message(
            doc.network, claims[0][0], claims[0][1], claims[0][2],
            claims[0][3], era0["root"], era0["scheme"]))
    era0["contributions"] = claims
    ok, problems, _ = dataclasses.replace(doc, era0=era0).verify()
    assert not ok
    assert any("is not signed by its roster key" in p for p in problems)


def test_a_slice_moved_after_signing_is_refused():
    """The claim names the slice, so editing the map breaks the signature —
    which is the point of signing the map rather than announcing it."""
    doc = _doc()
    era0 = dict(doc.era0)
    claims = [list(c) for c in era0["contributions"]]
    claims[0][2] += 1
    era0["contributions"] = claims
    problems = dataclasses.replace(doc, era0=era0).verify()[1]
    assert any("not signed by its roster key" in p for p in problems), problems
    assert any("slices" in p for p in problems), problems


def test_an_era_that_does_not_match_the_hardening_parameters_is_refused():
    doc = _doc()
    era0 = dict(doc.era0, turns=SMALL.turns * 2)
    problems = dataclasses.replace(doc, era0=era0).verify()[1]
    assert any("the hardening parameters say" in p for p in problems), problems


def test_a_chosen_public_randomiser_is_refused():
    doc = _doc()
    era0 = dict(doc.era0, pub_seed="ab" * 32)
    problems = dataclasses.replace(doc, era0=era0).verify()[1]
    assert any("could have ground" in p for p in problems), problems


def test_the_era_is_inside_the_chain_id():
    doc = _doc()
    moved = dataclasses.replace(doc, era0=dict(doc.era0, root="cd" * 32))
    assert moved.chain_id != doc.chain_id


# ── concentration is the security parameter ──────────────────────────────────

def test_a_holder_with_more_than_a_third_of_the_pool_is_refused():
    """`max_fork_depth` is a bound, so this is not a risk appetite — it is the
    rewrite ceiling, stated in blocks."""
    fields, _ = _run(holders=["h0", "h1"])
    doc = _doc(era0=fields)
    problems = doc.verify()[1]
    assert any("rewrite ceiling" in p for p in problems), problems


def test_the_ceiling_is_reported_in_blocks_and_hours():
    caveats = _doc().verify()[2]
    assert any("rewrite ceiling" in c and "same operator" in c
               for c in caveats), caveats


# ── and the shipped document ─────────────────────────────────────────────────

def test_the_shipped_document_carries_a_ceremony():
    doc = load(GENESIS_7)
    ok, problems, _ = doc.verify()
    assert ok, problems
    assert doc.era0["turns"] == PRODUCTION.turns == 70_000
    assert len(doc.era0["contributions"]) == 7


def test_the_shipped_ceremony_file_is_the_one_in_the_document():
    assert load(GENESIS_7).era0 == load_era0(GENESIS_7_ERA0)


def test_no_holder_of_the_shipped_pool_can_rewrite_more_than_two_hours():
    doc = load(GENESIS_7)
    claims = [contrib.Contribution(*c) for c in doc.era0["contributions"]]
    worst = max(contrib.shares(claims, doc.era0["turns"]).values())
    hard = doc.hardening_params()
    depth = hard.max_fork_depth(worst)
    assert worst < 0.15, worst
    assert depth * hard.block_interval / 3600 < 2, depth
