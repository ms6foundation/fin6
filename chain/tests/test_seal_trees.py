"""The two trees the ledger keeps, and the one an outsider can check.

The seal tree is what a validator agrees on; the witness tree is what it can
prove one leaf of, to somebody who was not there.  They hold the same leaves at
the same positions on purpose, so a client checking the witness root is
checking the ledger and not a summary of it.

The spine is the same structure again, over block hashes instead of notes.
"""
from ..seal import (HeaderHistory, SealAccumulator, WitnessTree, leaf_value,
                    verify_ancestry, verify_witness)


# ── the witness tree ─────────────────────────────────────────────────────────

def test_a_leaf_opens_to_the_root_and_a_wrong_one_does_not():
    tree = WitnessTree("utxo")
    for i in range(50):
        tree.append(f"utxo:cm{i}")
    proof = tree.path(7)
    assert verify_witness("utxo:cm7", proof, tree.root)
    assert not verify_witness("utxo:cm8", proof, tree.root)
    assert not verify_witness("utxo:cm7", proof, WitnessTree("utxo").root)


def test_a_proof_is_about_half_a_kilobyte():
    """The number the whole second tree exists for: the seal tree's own proof
    of the same leaf is 80 KiB at this size."""
    tree = WitnessTree("utxo")
    for i in range(50_000):
        tree.append(f"utxo:cm{i}")
    size = tree.size_bytes(31_337)
    assert 400 < size < 700, size
    assert len(tree.path(31_337)["siblings"]) == 16, "one per occupied level"


def test_an_update_moves_the_root_and_kills_the_old_proof():
    tree = WitnessTree("utxo")
    for i in range(20):
        tree.append(f"utxo:cm{i}")
    before, proof = tree.root, tree.path(5)
    tree.set(5, "utxo:fin6:spent:cm5")
    assert tree.root != before
    assert not verify_witness("utxo:cm5", proof, tree.root)
    assert verify_witness("utxo:fin6:spent:cm5", tree.path(5), tree.root)


def test_a_forged_proof_is_refused_rather_than_parsed():
    tree = WitnessTree("utxo")
    for i in range(20):
        tree.append(f"utxo:cm{i}")
    good = tree.path(3)
    for bad in ({}, {"pos": 3}, dict(good, present=0),
                dict(good, siblings=[]), dict(good, pos=4),
                dict(good, height=-1), dict(good, siblings=["zz"])):
        assert not verify_witness("utxo:cm3", bad, tree.root), bad


# ── the accumulator ──────────────────────────────────────────────────────────

def test_the_two_trees_hold_the_same_leaves():
    acc = SealAccumulator("utxo")
    for i in range(40):
        acc.add(f"nc:{i:064x}")
    cm = f"nc:{9:064x}"
    assert verify_witness(leaf_value("utxo", cm), acc.witness_path(cm),
                          acc.witness_root)
    rebuilt = SealAccumulator.load("utxo", acc.items, acc.dead)
    assert rebuilt.witness_root == acc.witness_root
    assert rebuilt.root == acc.root, "and the seal root, from the same dump"


def test_a_spent_note_has_no_proof_that_it_is_live():
    """§3 of the design: unspent is a positive statement, and this is it."""
    acc = SealAccumulator("utxo")
    for i in range(40):
        acc.add(f"nc:{i:064x}")
    cm = f"nc:{9:064x}"
    before = acc.witness_path(cm)
    acc.spend(cm)
    assert acc.witness_path(cm) is None
    assert not verify_witness(leaf_value("utxo", cm), before, acc.witness_root)
    assert f"nc:{8:064x}" in acc, "and its neighbours are untouched"


def test_a_clone_copies_the_witness_tree_rather_than_rebuilding_it():
    acc = SealAccumulator("utxo")
    for i in range(200):
        acc.add(f"nc:{i:064x}")
    twin = acc.clone()
    assert twin.witness_root == acc.witness_root
    twin.add("nc:" + "ff" * 32)
    assert twin.witness_root != acc.witness_root, "and they share nothing"


# ── the spine ────────────────────────────────────────────────────────────────

def test_ancestry_is_one_path_however_long_the_gap():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 4001))
    proof = spine.proof(1)
    assert verify_ancestry(f"nb:{1:064x}", proof, spine.root)
    assert 32 * len(proof["siblings"]) + 8 < 500, "4,000 blocks, one path"


def test_a_prefix_root_is_the_root_that_prefix_had():
    spine, roots = HeaderHistory(), {}
    for i in range(1, 60):
        roots[i - 1] = spine.root
        spine.append(f"nb:{i:064x}")
    assert all(spine.root_at(k) == r for k, r in roots.items())
    for cut in (1, 2, 17, 32, 33, 59):
        for target in (1, cut):
            proof = spine.proof(target, under=cut)
            assert verify_ancestry(proof["block_hash"], proof,
                                   spine.root_at(cut)), (target, cut)


def test_a_proof_under_one_root_does_not_verify_under_another():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 60))
    proof = spine.proof(3, under=10)
    assert not verify_ancestry(proof["block_hash"], proof, spine.root_at(11))
    assert not verify_ancestry(f"nb:{4:064x}", proof, spine.root_at(10))


def test_a_rolled_back_block_leaves_the_spine():
    spine = HeaderHistory(f"nb:{i:064x}" for i in range(1, 21))
    at_ten = spine.root_at(10)
    spine.truncate_to(10)
    assert len(spine) == 10 and spine.root == at_ten
    assert spine.hash_at(11) is None


def test_the_header_counts_what_the_chain_has_produced():
    """Two numbers, and they are what make a scan checkable."""
    acc = SealAccumulator("utxo")
    for i in range(10):
        acc.add(f"nc:{i:064x}")
    acc.spend(f"nc:{3:064x}")
    assert acc.size == 10, "size counts everything ever issued"
    assert len(acc) == 9, "length counts what is live"
