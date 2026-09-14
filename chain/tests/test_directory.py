"""Finding the other seats, when you already know whose seats they are.

Review C6: peers come from the roster and `net.json`, so a network that grows
needs joiners to find each other. What keeps this small is that the identities
are already settled — the genesis document names every seat and its key — so
discovery is only ever about *addresses*. A record signed by a key the roster
does not name is not an unknown peer; it is noise.

That is the property these tests are mostly about. The rest is freshness: a
record has to age, or a node that moved is dialled at its old address for ever,
and a record must not be believed from the future, or one bad clock pins a
stale address in place.
"""
import dataclasses

from ..crypto import Signer
from ..net.directory import (MAX_AGE_EPOCHS, MAX_SKEW_EPOCHS, AddressRecord,
                             Directory, sign_address)

CHAIN = "fin6:" + "ab" * 32
SEATS = {f"n{i:02d}": Signer.from_seed(f"validator:n{i:02d}") for i in range(5)}
ROSTER = {nid: s.public_hex for nid, s in SEATS.items()}


def _record(node_id, host="10.0.0.1", port=9000, epoch=10, chain=CHAIN):
    return sign_address(SEATS[node_id], node_id, chain, (host, port), epoch)


def _directory(node_id="n00"):
    return Directory(CHAIN, ROSTER, node_id=node_id)


# ── the statement ────────────────────────────────────────────────────────────

def test_a_record_says_where_and_is_signed_over_all_of_it():
    rec = _record("n01")
    assert rec.verify() and rec.address == ("10.0.0.1", 9000)
    for change in ({"host": "10.0.0.9"}, {"port": 9001}, {"epoch": 11},
                   {"node_id": "n02"}, {"chain_id": "fin6:" + "cd" * 32}):
        assert not dataclasses.replace(rec, **change).verify(), change


def test_only_a_seat_can_say_where_that_seat_is():
    """The whole security argument. A record is about an address, and only the
    key the roster names for that seat may make it."""
    stranger = Signer.generate()
    forged = sign_address(stranger, "n01", CHAIN, ("10.0.0.9", 9000), 10)
    d = _directory()
    assert not d.learn(forged, 10)
    assert d.refused == 1 and len(d) == 0


def test_a_seat_nobody_named_is_not_discovered_into_existence():
    outsider = Signer.from_seed("validator:n99")
    rec = sign_address(outsider, "n99", CHAIN, ("10.0.0.9", 9000), 10)
    d = _directory()
    assert not d.learn(rec, 10)
    assert "n99" not in d.records


def test_a_record_from_another_chain_is_refused():
    d = _directory()
    assert not d.learn(_record("n01", chain="fin6:" + "cd" * 32), 10)


# ── freshness ────────────────────────────────────────────────────────────────

def test_the_newest_record_for_a_seat_wins():
    d = _directory()
    assert d.learn(_record("n01", host="10.0.0.1", epoch=10), 10)
    assert d.learn(_record("n01", host="10.0.0.2", epoch=11), 11)
    assert d.address_of("n01") == ("10.0.0.2", 9000)


def test_an_older_record_does_not_undo_a_newer_one():
    """Otherwise replaying yesterday's record is how you send a network to an
    address nobody is listening on."""
    d = _directory()
    assert d.learn(_record("n01", host="10.0.0.2", epoch=11), 11)
    assert not d.learn(_record("n01", host="10.0.0.1", epoch=10), 11)
    assert d.address_of("n01") == ("10.0.0.2", 9000)


def test_a_record_from_the_future_is_refused():
    d = _directory()
    assert not d.learn(_record("n01", epoch=100), 10)
    assert d.learn(_record("n01", epoch=10 + MAX_SKEW_EPOCHS), 10), \
        "a peer whose clock is a little fast should still be findable"


def test_a_record_nobody_refreshed_ages_out_of_the_gossip():
    d = _directory()
    assert d.learn(_record("n01", epoch=10), 10)
    now = 10 + MAX_AGE_EPOCHS + 1
    assert d.records["n01"] not in d.fresh(now), "stale addresses stop moving"
    assert not d.learn(_record("n02", epoch=10), now)


# ── what a node asks it ──────────────────────────────────────────────────────

def test_it_says_which_seats_it_is_not_talking_to():
    d = _directory("n00")
    for nid in ("n01", "n02", "n03"):
        d.learn(_record(nid), 10)
    assert d.unknown(known={"n01"}) == ["n02", "n03"]
    assert "n00" not in d.unknown(known=set()), "a node does not dial itself"


def test_it_says_which_seats_are_still_lost():
    d = _directory("n00")
    d.learn(_record("n01"), 10)
    assert d.missing() == ["n02", "n03", "n04"]


def test_it_is_bounded_by_the_roster():
    """Memory is the size of the network, not the size of what somebody
    sends."""
    d = _directory()
    for epoch in range(10, 40):
        for nid in SEATS:
            d.learn(_record(nid, host=f"10.0.0.{epoch}", epoch=epoch), epoch)
    assert len(d) <= len(ROSTER)


def test_absorbing_a_batch_counts_only_what_was_news():
    d = _directory()
    batch = [_record("n01"), _record("n02"), _record("n01")]
    assert d.absorb(batch, 10) == 2
    assert d.absorb(batch, 10) == 0


def test_rubbish_in_a_batch_is_dropped_rather_than_believed():
    d = _directory()
    assert d.absorb([None, "not a record", 7, _record("n01")], 10) == 1
    assert len(d) == 1


# ── on real sockets ──────────────────────────────────────────────────────────

def test_a_node_given_one_address_finds_the_rest():
    """The point of the whole module, on four processes.

    Three nodes are configured for each other as usual. The fourth is given
    exactly one peer's address — the situation a joiner is actually in, and the
    one `net.json` could not express before: every other seat's address is
    blank in its file, so it can only reach them by being told.
    """
    import glob
    import json
    import os
    import shutil
    import tempfile
    import time

    from ..net import supervisor as sv

    root = tempfile.mkdtemp(prefix="fin6-directory-")
    base_port = 9100 + (os.getpid() % 30) * 10
    try:
        sv.new_testnet(root, nodes=4, preset="local", epoch_millis=2500,
                       base_port=base_port, force=True)
        net = sv.Testnet(root)
        ids = sorted(net.net["nodes"])
        joiner, seed = ids[3], ids[0]
        # The joiner's own view: it knows where one seat is, and nothing else.
        # (Its own listen address stays, because that is where it *is*.)
        net.net["nodes"][joiner]["peers"] = {
            seed: net.net["nodes"][seed]["listen"]}
        with open(os.path.join(root, "net.json"), "w") as fh:
            json.dump(net.net, fh, indent=2)
        net = sv.Testnet(root)
        net.up(until_epoch=12, start_in_ms=4000)
        try:
            net.wait_for_height(2, timeout=90)
            deadline = time.time() + 60
            mine = None
            while time.time() < deadline:
                mine = net.status().get(joiner)
                if mine and mine.get("directory", {}).get("known", 0) >= 3:
                    break
                time.sleep(1.5)
            assert mine, f"{joiner} never answered"
            known = mine.get("directory", {}).get("known", 0)
            assert known >= 3, (f"{joiner} holds {known} addresses; it was "
                                f"given one and there are four seats")
            assert mine["peers"] >= 2, \
                f"{joiner} learned addresses and did not dial them"
            with open(os.path.join(root, joiner, "node.log")) as fh:
                said = [ln for ln in fh if "learned " in ln]
            assert said, "nothing was learned over the wire"
            # And it is a full member: same chain, same roots.
            live = {n: s for n, s in net.status().items() if s}
            top = max(s["height"] for s in live.values())
            at_top = [s for s in live.values() if s["height"] == top]
            for field in ("tip", "utxo_root"):
                assert len({s[field] for s in at_top}) == 1
        finally:
            net.down()
    finally:
        shutil.rmtree(root, ignore_errors=True)
