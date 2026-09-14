"""A state that arrives in pieces.

Review C7: past the body window, catch-up falls back to `getsnapshot`, and that
fallback was one frame carrying the whole state — which worked until a state
outgrew a frame, and then stopped working entirely with a log line saying
chunked transfer was not built. `store/snapshot.py` was chunked from the
beginning, precisely so ranges could be fetched separately and each carry its
own digest; nothing used it.

Two things were wrong, and they are different. The transfer was one frame. And
the *serving* node exported a full copy of its state per request, on the thread
that also has to attest — so three peers behind the window meant three copies.

What makes the chunked version safe is the manifest: it lists every chunk and
commits a digest for each, so a receiver knows exactly what to ask for, checks
each piece as it lands rather than at the end of the fold, and can tell which
peer served a bad range instead of only that the roots did not match.
"""
import os
import tempfile

from ..crypto import Signer
from ..notes import Note, note_id, note_vector
from ..params import DEMO
from ..register import GridRegister
from ..state import ChainState
from ..store import snapshot as snap

HOLDER = Signer.from_seed("holder")


def _state(n_notes=40):
    state = ChainState(DEMO)
    for i in range(n_notes):
        note = Note.create(10 + i, HOLDER.public_hex, DEMO)
        state.issue(note_id(note_vector(note, DEMO)))
    state.height = 0
    state.tip = "nb:genesis"
    registers = {"g0": GridRegister.genesis("g0", [f"n{i}" for i in range(4)],
                                            attend_threshold=2)}
    return state, registers


def _exported(chunk=7):
    state, registers = _state()
    root = tempfile.mkdtemp(prefix="fin6-snapchunk-")
    path = os.path.join(root, "a.snap")
    manifest = snap.export(state, registers, path, chunk=chunk)
    return state, registers, path, manifest, root


def _roots(state, manifest):
    return {"utxo_root": state.utxo.root, "nf_root": state.nullifiers.root,
            "registers_root": manifest["registers_root"]}


# ── the manifest says what the chunks are ────────────────────────────────────

def test_the_manifest_lists_every_chunk_and_commits_a_digest():
    state, _, path, manifest, _ = _exported()
    parts = manifest["parts"]
    assert len(parts) > 1, "a snapshot of 40 notes in sevens is several chunks"
    for kind, index, size, digest in parts:
        payload = snap.read_chunk(path, kind, index)
        assert len(payload) == size
        assert snap.chunk_digest(kind, index, payload) == digest


def test_the_manifest_can_be_read_without_the_chunks():
    """What a peer is offered first, and what it decides on."""
    _, _, path, manifest, _ = _exported()
    assert snap.manifest_of(path) == manifest


def test_asking_for_a_chunk_that_is_not_there_is_an_error_not_a_guess():
    _, _, path, _, _ = _exported()
    try:
        snap.read_chunk(path, 0, 99)
    except snap.SnapshotError as exc:
        assert "no chunk" in str(exc)
    else:
        raise AssertionError("invented a chunk")


# ── and a receiver reassembles from them ─────────────────────────────────────

def test_chunks_fetched_one_at_a_time_rebuild_the_state():
    state, _, path, manifest, root = _exported()
    parts = [(k, i, snap.read_chunk(path, k, i))
             for k, i, _, _ in manifest["parts"]]
    out = os.path.join(root, "rebuilt.snap")
    snap.write_parts(manifest, parts, out)
    rebuilt, registers = snap.load(out, DEMO, expect_roots=_roots(state,
                                                                 manifest))
    assert rebuilt.utxo.root == state.utxo.root
    assert rebuilt.height == state.height and rebuilt.tip == state.tip
    assert set(registers) == {"g0"}


def test_a_chunk_that_was_tampered_with_is_caught_by_name():
    """Not at the fold, where all anybody knows is that the roots do not
    match — here, where the peer that served it can be named."""
    state, _, path, manifest, root = _exported()
    parts = [(k, i, snap.read_chunk(path, k, i))
             for k, i, _, _ in manifest["parts"]]
    kind, index, payload = parts[0]
    # Same length, different bytes: the size check must not be what saves us.
    flipped = bytes([payload[0] ^ 0xFF]) + payload[1:]
    parts[0] = (kind, index, flipped)
    try:
        snap.write_parts(manifest, parts, os.path.join(root, "bad.snap"))
    except snap.SnapshotError as exc:
        assert "digest" in str(exc) and f"({kind}, {index})" in str(exc)
    else:
        raise AssertionError("a tampered range was assembled")


def test_a_missing_chunk_is_not_a_snapshot():
    state, _, path, manifest, root = _exported()
    parts = [(k, i, snap.read_chunk(path, k, i))
             for k, i, _, _ in manifest["parts"]][1:]
    try:
        snap.write_parts(manifest, parts, os.path.join(root, "short.snap"))
    except snap.SnapshotError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("assembled a state with a hole in it")


def test_a_chunk_of_the_wrong_length_is_refused():
    state, _, path, manifest, root = _exported()
    parts = [(k, i, snap.read_chunk(path, k, i))
             for k, i, _, _ in manifest["parts"]]
    parts[0] = (parts[0][0], parts[0][1], parts[0][2] + b"\x00")
    try:
        snap.write_parts(manifest, parts, os.path.join(root, "long.snap"))
    except snap.SnapshotError as exc:
        assert "bytes" in str(exc)
    else:
        raise AssertionError("assembled an overlong range")


# ── what a chunk costs on the wire ───────────────────────────────────────────

def test_the_serving_chunk_size_fits_a_frame_with_room_to_spare():
    """50,000 commitments is 3.4 MB, which fits a frame and nothing else.
    Serving is not the only thing a node is doing."""
    from ..net.catchup import MAX_SNAPSHOT

    state, registers = _state(n_notes=200)
    parts, _, _ = snap.parts_of(state, registers, snap.SERVE_CHUNK)
    biggest = max(len(p) for _, _, p in parts)
    assert snap.SERVE_CHUNK == 10_000
    assert biggest < MAX_SNAPSHOT // 4, biggest


def test_every_chunk_of_a_real_state_is_under_the_ceiling():
    from ..net.catchup import MAX_SNAPSHOT

    state, registers = _state(n_notes=500)
    parts, _, _ = snap.parts_of(state, registers, snap.SERVE_CHUNK)
    assert all(len(p) <= MAX_SNAPSHOT for _, _, p in parts)
