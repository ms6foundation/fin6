"""Accumulators, block application, and double-spend prevention."""
from ..block import Block, BlockHeader, CeremonyMeta
from ..network import transfer
from ..params import DEMO
from ..seal import SealAccumulator
from .helpers import funded_network, network

META = CeremonyMeta(epoch=1, leader_id="v00", rows=2, row_size=5,
                    grid_seed="seed")


def test_accumulator_root_is_canonical():
    a, b = SealAccumulator("utxo"), SealAccumulator("utxo")
    for i in range(8):
        a.add(f"cm:{i}")
        b.add(f"cm:{i}")
    assert a.root == b.root, "two nodes with the same set must agree"


def test_clone_reproduces_the_root():
    a = SealAccumulator("utxo")
    for i in range(8):
        a.add(f"cm:{i}")
    a.spend("cm:3")
    assert a.clone().root == a.root


def test_spending_moves_the_root_and_membership():
    a = SealAccumulator("utxo")
    for i in range(4):
        a.add(f"cm:{i}")
    before = a.root
    a.spend("cm:1")
    assert a.root != before
    assert "cm:1" not in a and a.ever_contained("cm:1")
    assert len(a) == 3


def test_label_separates_domains():
    u, n = SealAccumulator("utxo"), SealAccumulator("nf")
    u.add("x")
    n.add("x")
    assert u.root != n.root


def test_block_applies_and_all_nodes_agree():
    nodes, wallets, tx = funded_network()
    leader = nodes["v00"]
    block = leader.build_block(META)
    for node in nodes.values():
        ok, why = node.validate_block(block)
        assert ok, why
        node.apply(block)
    assert len({n.state.utxo.root for n in nodes.values()}) == 1
    assert len({n.state.nullifiers.root for n in nodes.values()}) == 1
    assert {n.state.height for n in nodes.values()} == {1}


def test_double_spend_across_blocks_is_rejected():
    nodes, wallets, tx = funded_network()
    leader = nodes["v00"]
    block = leader.build_block(META)
    for node in nodes.values():
        node.apply(block)
    # Resubmitting the same transaction must fail: the nullifier is published.
    ok, why = nodes["v01"].submit(tx)
    assert not ok and ("double spend" in why or "unspent" in why), why


def test_same_note_cannot_be_spent_twice_in_one_block():
    nodes, wallets, _ = network()
    params = DEMO
    note = wallets["alice"].take(500)
    from ..notes import Note
    from ..transaction import build_transaction
    outs_a = [Note.create(400, wallets["bob"].public_hex, params, asset=note.asset),
              Note.create(600, wallets["alice"].public_hex, params, asset=note.asset)]
    outs_b = [Note.create(300, wallets["bob"].public_hex, params, asset=note.asset),
              Note.create(700, wallets["alice"].public_hex, params, asset=note.asset)]
    tx_a = build_transaction([(note, wallets["alice"].signer)], outs_a, 0, params)
    tx_b = build_transaction([(note, wallets["alice"].signer)], outs_b, 0, params)

    leader = nodes["v00"]
    assert leader.submit(tx_a)[0]
    ok, why = leader.submit(tx_b)
    # The nullifier is a deterministic function of the note, so two honest
    # spends of one note collide on it before they collide on the commitment.
    assert not ok and ("already claimed" in why or "already being spent" in why), why

    # Forced into one block by hand — with a matching tx_root, so it is the
    # double spend and not the header that has to be what stops it.
    import dataclasses
    from ..seal import seal_root
    base = leader.build_block(META)
    header = dataclasses.replace(
        base.header, tx_root=seal_root("tx", [tx_a.txid, tx_b.txid]))
    forced = Block(header=header, transactions=(tx_a, tx_b))
    ok, why = nodes["v01"].validate_block(forced)
    # Validation applies each transaction to a shadow state as it goes, so the
    # second spend hits an already-tombstoned note before the within-block
    # guard even needs to fire.  Either phrasing means the same thing.
    assert not ok, "a block spending one note twice was accepted"
    assert ("twice in one block" in why or "not an unspent note" in why
            or "double spend" in why), why


def test_header_root_must_match_the_transactions():
    import dataclasses
    nodes, wallets, tx = funded_network()
    block = nodes["v00"].build_block(META)
    bad_header = dataclasses.replace(block.header, utxo_root=block.header.utxo_root + 1)
    ok, why = nodes["v01"].validate_block(Block(header=bad_header,
                                                transactions=block.transactions))
    assert not ok and "utxo_root" in why, why


def test_block_must_follow_the_tip():
    import dataclasses
    nodes, wallets, tx = funded_network()
    block = nodes["v00"].build_block(META)
    bad = dataclasses.replace(block.header, prev_hash="blk:deadbeef")
    ok, why = nodes["v01"].validate_block(Block(header=bad,
                                                transactions=block.transactions))
    assert not ok and "prev_hash" in why, why
