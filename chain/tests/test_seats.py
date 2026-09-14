"""The seat order a certificate counts against, committed in the header.

A3 in the pre-genesis review: the quorum signature scheme is a placeholder, and
the two halves of fixing it have very different prices. Aggregating signatures
needs a pairing library and a dependency this repository does not have. Naming
*who signed* compactly needs only an order to count against — and an order is
worthless unless every reader derives the same one and nobody can choose it
after the fact, which means committing it in the header, which is a format
change and therefore a genesis-only move.

So: `chain/seats.py` is the order and the bitmap codec, `NetworkBlockHeader`
commits it, and `QuorumCert` gains the two things that make the eventual swap a
value rather than a format change — a named `scheme`, and a compact encoding
whose root is identical to the expanded one's.

The strengthening that came free: verifying a certificate against the *seats*
as well as the roster. Quorum is a fraction of a grid, and until now a
signature from any key the genesis document named counted toward any grid's
quorum.
"""
import dataclasses

from .. import seats
from ..block import ED25519, QuorumCert, SeatError
from ..crypto import Signer
from ..seats import canonical_order, from_bits, seats_digest, seats_root, to_bits
from ..tiered import NetworkBlockHeader
from .test_prevcert import CHAIN, SEED, _att, _cert, _roster, _signers

GRID = "genesis-0"


def _order(*names):
    return canonical_order(names)


# ── the order ────────────────────────────────────────────────────────────────

def test_the_order_is_a_function_of_the_set_and_nothing_else():
    """Sorted, so two nodes that agree on who is seated cannot disagree about
    the order — there is no tie-break to get wrong and no arrival time to
    remember."""
    assert _order("c", "a", "b") == ("a", "b", "c")
    assert _order("b", "c", "a") == _order("a", "b", "c")
    assert _order("a", "a", "b") == ("a", "b"), "a seat listed twice is one seat"


def test_an_order_cannot_be_lifted_from_one_grid_into_another():
    order = _order("a", "b", "c")
    assert seats_digest("genesis-0", order) != seats_digest("genesis-1", order)


def test_the_root_is_a_function_of_the_mapping_not_the_walk_order():
    a, b = _order("a", "b"), _order("c", "d")
    assert seats_root({"g0": a, "g1": b}) == seats_root({"g1": b, "g0": a})


def test_moving_one_seat_between_grids_moves_the_root():
    before = seats_root({"g0": _order("a", "b", "c"), "g1": _order("d")})
    after = seats_root({"g0": _order("a", "b"), "g1": _order("c", "d")})
    assert before != after


# ── the bitmap ───────────────────────────────────────────────────────────────

def test_a_bitmap_round_trips():
    order = _order(*[f"n{i:02d}" for i in range(20)])
    for chosen in ((), order, order[::3], order[:1], order[-1:]):
        assert from_bits(to_bits(chosen, order), order) == \
            tuple(n for n in order if n in set(chosen))


def test_a_bitmap_is_the_same_size_whoever_turned_up():
    """The point of the encoding: a certificate's size stops depending on
    attendance."""
    order = _order(*[f"n{i:03d}" for i in range(667)])
    assert len(to_bits(order[:1], order)) == len(to_bits(order, order))
    assert seats.bitmap_bytes(667) == 84


def test_a_seat_that_is_not_in_the_order_cannot_be_named():
    order = _order("a", "b")
    try:
        to_bits(["a", "z"], order)
    except SeatError as exc:
        assert "z" in str(exc)
    else:
        raise AssertionError("a stranger was encoded as a seat")


def test_a_bitmap_of_the_wrong_width_is_refused():
    """Reader and writer disagreeing about the seat count is the one way a
    bitmap can quietly mean something else, so it is never resolved by
    padding."""
    order = _order(*[f"n{i}" for i in range(9)])       # two bytes
    bits = to_bits(order, order)
    for bad in (bits[:2], bits + "00"):
        try:
            from_bits(bad, order)
        except SeatError:
            pass
        else:
            raise AssertionError(f"{bad!r} was accepted for 9 seats")


def test_a_bit_past_the_last_seat_is_refused():
    order = _order("a", "b", "c")                      # three of eight bits
    try:
        from_bits("80", order)
    except SeatError as exc:
        assert "past the last seat" in str(exc)
    else:
        raise AssertionError("a bit with no seat behind it was accepted")


# ── the header commits it ────────────────────────────────────────────────────

def _header(**kw):
    return NetworkBlockHeader(height=1, epoch=1, chain_id=CHAIN,
                              prev_hash="nb:zero", utxo_root=1, nf_root=2,
                              super_root=3, registers_root=4, **kw)


def test_the_seat_order_is_inside_the_block_hash():
    a = _header(seats_root=seats_root({GRID: _order("a", "b")}))
    b = _header(seats_root=seats_root({GRID: _order("a", "c")}))
    assert a.hash() != b.hash(), \
        "an uncommitted order is an order the producer picks per reader"


# ── the certificate ──────────────────────────────────────────────────────────

def test_compacting_leaves_the_root_alone():
    """The two encodings are one statement, so nothing that recorded the root
    of one fails to recognise the other."""
    s = _signers(["a", "b", "c"])
    cert = _cert([_att(s[n], n) for n in ("a", "b")])
    order = _order("a", "b", "c")
    small = cert.compact_form(GRID, order)
    assert small.root == cert.root
    assert small.signers == () and small.signer_bits
    assert small.expanded_form(GRID, order) == cert


def test_a_compact_certificate_verifies_against_the_committed_order():
    s = _signers(["a", "b", "c"])
    cert = _cert([_att(s[n], n) for n in ("a", "b", "c")])
    order = _order("a", "b", "c")
    ok, why = cert.compact_form(GRID, order).verify(
        3, "nb:one", validators=_roster("a", "b", "c"), seats=order,
        grid_id=GRID)
    assert ok, why


def test_a_compact_certificate_cannot_be_checked_without_the_order():
    s = _signers(["a", "b"])
    cert = _cert([_att(s[n], n) for n in ("a", "b")]).compact_form(
        GRID, _order("a", "b"))
    ok, why = cert.verify(2, "nb:one", validators=_roster("a", "b"))
    assert not ok and "seat order" in why


def test_a_bitmap_read_against_another_grids_order_is_refused():
    s = _signers(["a", "b"])
    order = _order("a", "b")
    cert = _cert([_att(s[n], n) for n in ("a", "b")]).compact_form(GRID, order)
    ok, why = cert.verify(2, "nb:one", validators=_roster("a", "b"),
                          seats=order, grid_id="genesis-1")
    assert not ok and "not over" in why


def test_asking_a_compact_certificate_who_voted_is_an_error_not_a_guess():
    s = _signers(["a", "b"])
    cert = _cert([_att(s[n], n) for n in ("a", "b")]).compact_form(
        GRID, _order("a", "b"))
    try:
        cert.voters()
    except SeatError as exc:
        assert "seat order" in str(exc)
    else:
        raise AssertionError("a compact certificate answered from nowhere")
    assert len(cert) == 2, "a popcount needs no order"


# ── the scheme is a value ────────────────────────────────────────────────────

def test_the_scheme_is_named_and_bound_into_the_root():
    s = _signers(["a", "b"])
    cert = _cert([_att(s[n], n) for n in ("a", "b")])
    assert cert.scheme == ED25519
    assert QuorumCert.compute_root(cert.signers, cert.signatures, "bls12-381") \
        != cert.root


def test_a_scheme_this_build_does_not_know_is_refused_not_attempted():
    """The same discipline as a protocol version this build cannot run: a
    verifier that cannot check these signatures has no business deciding they
    are fine."""
    s = _signers(["a", "b"])
    cert = dataclasses.replace(_cert([_att(s[n], n) for n in ("a", "b")]),
                               scheme="bls12-381")
    ok, why = cert.verify(2, "nb:one", validators=_roster("a", "b"))
    assert not ok and "this build knows" in why


# ── what the order buys today ────────────────────────────────────────────────

def test_a_roster_key_that_does_not_sit_in_the_grid_does_not_count():
    """The gap the committed order closes on its own, with no aggregation:
    quorum is a fraction of a *grid*, and until now any key the genesis
    document named counted toward any grid's quorum."""
    s = _signers(["a", "b", "outsider"])
    cert = _cert([_att(s[n], n) for n in ("a", "b", "outsider")])
    roster = _roster("a", "b", "outsider")
    ok, _ = cert.verify(3, "nb:one", validators=roster)
    assert ok, "without the seats, the outsider counts"
    ok, why = cert.verify(3, "nb:one", validators=roster,
                          seats=_order("a", "b"), grid_id=GRID)
    assert not ok and "outsider" in why


def test_the_sizes_this_is_all_about():
    """Measured through the real codec, not asserted from the design document.

    667 seats, the figure the review used. Compacting the seats takes the
    certificate from 56.2 KB to 47.1 KB — worth having, and visibly not the
    headline. The remaining 47 KB is signatures, one a seat, and collapsing
    those is the half that needs a pairing library.
    """
    import dataclasses

    from ..block import Attestation
    from ..store import codec

    names = [f"fin6-n{i:03d}" for i in range(667)]
    signers = {n: Signer.from_seed(n) for n in names}
    msg = Attestation.message(CHAIN, 1, "nb:one", 1, SEED)
    atts = [Attestation(node_id=n, public_hex=signers[n].public_hex,
                        chain_id=CHAIN, height=1, block_hash="nb:one", epoch=1,
                        grid_seed=SEED, signature=signers[n].sign(msg))
            for n in names]
    cert = QuorumCert.build(CHAIN, 1, "nb:one", 1, SEED, atts)
    order = canonical_order(names)
    small = cert.compact_form(GRID, order)

    def size(c):
        return len(codec.encode(dataclasses.asdict(c)))

    assert size(small) < size(cert) - 8_000, (size(cert), size(small))
    assert len(small.signer_bits) == 2 * seats.bitmap_bytes(667) == 168
    # And the honest half of the finding: what is left is signatures.
    assert sum(len(s) for s in cert.signatures) > 80_000


# ── and the header's commitment is checked, not merely written ───────────────

def test_a_network_block_whose_seat_order_is_not_the_committed_one_is_refused():
    """The validating half. A leader that proposes a block claiming some other
    grid membership must be refused by every seat — otherwise the commitment is
    a number the producer writes and nobody reads.

    The behaviour is handed to every node because the supreme leader is drawn
    from committed state and is not known in advance; it passes every block
    through untouched except a `NetworkBlockHeader`, which only the supreme
    tier builds.
    """
    import dataclasses

    from ..ceremony import HonestLeader
    from ..tiered import NetworkBlockHeader
    from ..tiers import run_tiered_epoch
    from .test_tiers import funded

    class ForgeSeats(HonestLeader):
        name = "forge-seats"

        def propose(self, leader, grid, meta, limit=None, workload=None):
            block = workload.build(leader, meta, limit=limit)
            if isinstance(block.header, NetworkBlockHeader):
                block = dataclasses.replace(
                    block, header=dataclasses.replace(
                        block.header,
                        seats_root=seats_root({GRID: _order("nobody")})))
            sp = leader.propose(block, meta.epoch, meta.grid_seed)
            return {**{n: sp for n in (grid.rows[0] if grid.rows else [])},
                    leader.id: sp}

    w, _, _ = funded()
    liars = {nid: ForgeSeats() for nid in w.nodes}
    res = run_tiered_epoch(w, 1, "seed", behaviours=liars)
    assert not res.finalised, "a forged seat order was finalised"


def test_a_certificate_signed_by_another_grids_seat_is_refused_by_the_world():
    """The wiring, on a real world rather than on a hand-made roster.

    `TierWorld.verify_cert` is the one place both the super tier and a
    one-tier node check a certificate, and it is the reason the committed
    order is worth something before any aggregation: the outsider here is a
    real validator with a real key and a real signature, seated in another
    grid. Against the roster alone it counts toward this grid's quorum.
    """
    from ..block import Attestation, QuorumCert
    from .test_tiers import world

    w, _ = world(n=20)
    grids = w.topology.grid_ids()
    if len(grids) < 2:                       # sizing changed; nothing to test
        return
    here, elsewhere = grids[0], grids[1]
    inside = list(w.seat_order(here))
    outsider = next(n for n in w.seat_order(elsewhere) if n not in inside)

    def att(nid):
        signer = w.nodes[nid].signer
        msg = Attestation.message(w.nodes[nid].chain_id, 1, "nb:one", 1, SEED)
        return Attestation(node_id=nid, public_hex=signer.public_hex,
                           chain_id=w.nodes[nid].chain_id, height=1,
                           block_hash="nb:one", epoch=1, grid_seed=SEED,
                           signature=signer.sign(msg))

    chain_id = w.nodes[inside[0]].chain_id
    honest = QuorumCert.build(chain_id, 1, "nb:one", 1, SEED,
                              [att(n) for n in inside[:2]])
    ok, why = w.verify_cert(here, honest, 2, "nb:one")
    assert ok, why

    mixed = QuorumCert.build(chain_id, 1, "nb:one", 1, SEED,
                             [att(inside[0]), att(outsider)])
    ok, _ = mixed.verify(2, "nb:one", validators=w.roster)
    assert ok, "against the roster alone the outsider counts — that is the gap"
    ok, why = w.verify_cert(here, mixed, 2, "nb:one")
    assert not ok and outsider in why, why
