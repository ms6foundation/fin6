"""The archive container: canonical encoding, retention, and integrity.

The claims under test are the three the design rests on: that the encoding is
exact and canonical, that retention is the lever that actually shrinks an
archive while leaving it verifiable, and that a damaged segment is loud rather
than quiet.
"""
import dataclasses
import os
import tempfile

from mq.ms6.core import FIELD_BYTES

from ..hardening.history import HardenedBlock
from ..network import transfer
from ..params import DEMO
from ..proofs import get_backend
from ..store import archive, codec
from ..tiers import bootstrap_world, run_tiered_epoch
from ..transaction import verify_transaction
from .helpers import network

PARAMS = dataclasses.replace(DEMO, attend_threshold=3, grid_size=5, row_size=5)

_CACHE = {}


def epoch_blocks(n=2):
    """Two finalised network blocks, built once and shared — an epoch is slow
    and every test here wants the same one."""
    if n not in _CACHE:
        regions = {f"n{i:02d}": ("eu" if i % 2 else "us") for i in range(20)}
        w, wallets = bootstrap_world(
            regions, {"alice": [1000, 800, 700], "bob": [250]}, PARAMS)
        blocks = []
        for e in range(1, n + 1):
            tx, _ = transfer(wallets["alice"], wallets["bob"], 200 + e, 5, PARAMS)
            w.submit(tx)
            result = run_tiered_epoch(w, epoch=e, base_seed="s")
            assert result.finalised, result.reason
            w.apply_network_block(result.block)
            blocks.append(result.block)
        _CACHE[n] = blocks
    return _CACHE[n]


def one_transaction():
    _, wallets, tx = _funded()
    return tx


def _funded():
    nodes, wallets, gen = network(params=DEMO)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, DEMO)
    return nodes, wallets, tx


# ── the codec ────────────────────────────────────────────────────────────────

def test_primitives_round_trip():
    P = 2 ** 255 - 19
    for value in (None, True, False, 0, 1, 127, 128, 2 ** 63, 2 ** 200, -5,
                  b"", b"\x00\xff", "", "hello", [], (), {},
                  [1, 2, 3], (b"a", b"b"), {"k": [1, (2, 3)]},
                  [P - 1, P - 2, 3], "tx:" + "ab" * 32):
        assert codec.decode(codec.encode(value)) == value, value


def test_encoding_is_canonical():
    """Two dicts built in different orders must encode identically — the
    archive digests these bytes, so 'equal' has to mean 'byte-identical'."""
    a = {"z": 1, "a": [2, 3], "m": b"x"}
    b = {"m": b"x", "a": [2, 3], "z": 1}
    assert codec.encode(a) == codec.encode(b)


def test_a_tuple_does_not_decode_as_a_list():
    assert type(codec.decode(codec.encode((1, 2)))) is tuple
    assert type(codec.decode(codec.encode([1, 2]))) is list


def test_field_vectors_pack_and_small_lists_do_not():
    """Packing is chosen per list, by whichever is smaller.

    A vector of full-width elements packs to a flat array; a list of small
    integers would triple in size if it did, so it stays tagged."""
    big = [2 ** 250 + i for i in range(64)]
    small = list(range(64))
    assert len(codec.encode(big)) <= 64 * FIELD_BYTES + 32
    assert len(codec.encode(small)) < 64 * FIELD_BYTES
    assert codec.decode(codec.encode(big)) == big
    assert codec.decode(codec.encode(small)) == small


def test_hex_identifiers_are_stored_as_bytes():
    """Every identifier in this chain is hex, so the table halves them."""
    ids = ["cm:" + f"{i:064x}" for i in range(50)]
    packed = len(codec.encode(ids))
    assert packed < sum(len(s) for s in ids) * 0.6


def test_repeated_strings_are_stored_once():
    """A certificate names one block hash once per attestation."""
    h = "nb:" + "9f" * 32
    one, many = codec.encode([h]), codec.encode([h] * 64)
    assert len(many) - len(one) < 200, "repeats should cost an index, not a hash"


def test_a_transaction_round_trips_with_its_proofs():
    tx = one_transaction()
    back = codec.decode(codec.encode(tx))
    assert back == tx and back.txid == tx.txid
    ok, why = verify_transaction(back, DEMO, backend="mpcith")
    assert ok, why


def test_the_encoding_is_within_a_percent_of_the_tight_serialisers():
    """The per-protocol serialisers cannot be decoded; this one can.  That has
    to cost something, and the something has to be small."""
    tx = one_transaction()
    tight = sum(get_backend(n).size(p) for n, p in tx.proofs.items())
    assert len(codec.encode(tx)) < tight * 1.02


def test_a_network_block_round_trips():
    block = epoch_blocks()[0]
    back = codec.decode(codec.encode(block))
    assert back.hash() == block.hash()
    assert [t.txid for t in back.transactions()] == \
           [t.txid for t in block.transactions()]


def test_decode_refuses_rubbish():
    for bad in (b"", b"\x01", b"\xff" * 20, codec.encode([1, 2]) + b"\x00"):
        try:
            codec.decode(bad)
        except codec.CodecError:
            continue
        raise AssertionError(f"decoded {bad!r}")


# ── retention ────────────────────────────────────────────────────────────────

def test_retention_is_the_lever_that_shrinks_an_archive():
    """Three proofs of one statement is the tiers' diversity, not history's."""
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        sizes = {}
        for profile in (archive.FULL, archive.COMPACT, archive.HEADERS):
            path = os.path.join(d, f"{profile.name}.seg")
            with archive.ArchiveWriter(path, retention=profile) as w:
                for b in blocks:
                    w.append(b)
            sizes[profile.name] = os.path.getsize(path)
        assert sizes["compact"] * 5 < sizes["full"], sizes
        assert sizes["headers"] * 5 < sizes["compact"], sizes


def test_a_compact_archive_is_still_verifiable():
    """The point of keeping one proof rather than none."""
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "compact.seg")
        with archive.ArchiveWriter(path, retention=archive.COMPACT) as w:
            for b in blocks:
                w.append(b)
        block = archive.ArchiveReader(path).get(blocks[0].height)
        seen = 0
        for tx in block.transactions():
            assert sorted(tx.proofs) == ["mpcith"]
            ok, why = verify_transaction(tx, PARAMS, backend="mpcith")
            assert ok, why
            ok, why = verify_transaction(tx, PARAMS, backend="ssh5")
            assert not ok and "no ssh5 proof" in why
            seen += 1
        assert seen


def test_a_headers_archive_admits_it_cannot_verify():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "h.seg")
        with archive.ArchiveWriter(path, retention=archive.HEADERS) as w:
            for b in blocks:
                w.append(b)
        block = archive.ArchiveReader(path).get(blocks[0].height)
        assert block.hash() == blocks[0].hash(), "the history is still intact"
        for tx in block.transactions():
            assert tx.proofs == {}
            ok, _ = verify_transaction(tx, PARAMS, backend="mpcith")
            assert not ok


def test_the_writer_reports_what_it_dropped():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        with archive.ArchiveWriter(os.path.join(d, "c.seg"),
                                   retention=archive.COMPACT) as w:
            for b in blocks:
                w.append(b)
            stats = w.stats()
    assert stats["proofs_dropped"] > 0
    assert stats["proofs_kept"] == {"mpcith": stats["proofs_kept"]["mpcith"]}
    assert set(stats["proofs_seen"]) == {"mpcith", "ssh3", "ssh5"}


# ── the container ────────────────────────────────────────────────────────────

def test_every_block_comes_back_unchanged():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "full.seg")
        with archive.ArchiveWriter(path, era_id=7) as w:
            for b in blocks:
                w.append(b)
        rd = archive.ArchiveReader(path)
        assert rd.era_id == 7 and rd.retention == "full"
        assert rd.heights() == sorted(b.height for b in blocks)
        assert len(rd) == len(blocks)
        for b in blocks:
            assert rd.get(b.height).hash() == b.hash()
        ok, problems = rd.verify()
        assert ok, problems


def test_the_index_is_rebuilt_from_the_segment_itself():
    """A lost index must never be what loses an archive, so there isn't one."""
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path) as w:
            for b in blocks:
                w.append(b)
        first = archive.ArchiveReader(path).heights()
        assert archive.ArchiveReader(path).heights() == first
        assert set(os.listdir(d)) == {"a.seg"}, "no sidecar to lose"


def test_appending_to_a_closed_segment_continues_it():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path) as w:
            w.append(blocks[0])
        with archive.ArchiveWriter(path) as w:
            w.append(blocks[1])
        assert archive.ArchiveReader(path).heights() == \
            sorted(b.height for b in blocks)


def test_a_segment_refuses_to_mix_retention_profiles():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path, retention=archive.FULL) as w:
            w.append(blocks[0])
        try:
            archive.ArchiveWriter(path, retention=archive.COMPACT)
        except archive.ArchiveError:
            return
        raise AssertionError("mixed profiles in one segment")


def test_bit_rot_is_loud():
    """The open item this closes: nothing else in the design notices a flipped
    bit in a segment file."""
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path, retention=archive.HEADERS) as w:
            w.append(blocks[0])
            w.append(blocks[1])
        with open(path, "r+b") as fh:
            fh.seek(os.path.getsize(path) - 200)
            byte = fh.read(1)
            fh.seek(os.path.getsize(path) - 200)
            fh.write(bytes([byte[0] ^ 0x01]))
        rd = archive.ArchiveReader(path)
        ok, problems = rd.verify()
        assert not ok and problems
        assert rd.get(blocks[0].height).hash() == blocks[0].hash(), \
            "the undamaged record must still be readable"


def test_proofs_are_never_deflated_and_structure_usually_is():
    """Compressing a proof makes it bigger; the format has to know that."""
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path) as w:
            for b in blocks:
                w.append(b)
        stats = archive.ArchiveReader(path).stats()
    assert all(sec != archive.SEC_PROOFS or name == "raw"
               for sec, name in stats["codecs"])
    assert stats["deflate_ratio"] > 1.0
    assert stats["structure"][1] < stats["structure"][0]


def test_a_section_is_never_stored_larger_than_it_arrived():
    incompressible = os.urandom(50_000)
    for sec in (archive.SEC_STRUCTURE, archive.SEC_PROOFS):
        codec_id, stored = archive.pack_section(sec, incompressible)
        assert len(stored) <= len(incompressible)
        assert archive.unpack_section(codec_id, stored,
                                      len(incompressible)) == incompressible


def test_pruning_an_era_is_deleting_one_file():
    blocks = epoch_blocks()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "era3.seg")
        with archive.ArchiveWriter(path, era_id=3) as w:
            w.append(blocks[0])
        assert archive.prune(path) == 3
        assert not os.path.exists(path)


def test_a_hardened_block_archives_with_its_stamps():
    """The archive's unit is what the hardening layer produced, not what the
    supreme grid agreed."""
    blocks = epoch_blocks()
    hardened = HardenedBlock(block_hash=blocks[0].hash(), height=blocks[0].height,
                             prev_hash="nb:genesis", era_id=0, drawn=(1, 2, 3),
                             stamps=(), weight=1 << 20, cumulative=1 << 20,
                             spent_root=0, block=blocks[0])
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.seg")
        with archive.ArchiveWriter(path, retention=archive.COMPACT) as w:
            w.append(hardened)
        back = archive.ArchiveReader(path).get(hardened.height)
        assert back.block_hash == hardened.block_hash
        assert back.cumulative == hardened.cumulative
        assert back.block.hash() == blocks[0].hash()
        assert all(sorted(t.proofs) == ["mpcith"] for t in back.block.transactions())
