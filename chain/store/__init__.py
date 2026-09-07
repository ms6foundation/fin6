"""Durable storage for the chain.

    codec.py       canonical binary encoding — the store and the wire want the
                   same thing, so there is one of it
    db.py          the node's SQLite store, one commit point per network block
    undo.py        undo records, LIFO rollback, retention from the fork ceiling
    snapshot.py    state that proves itself against a block header
    high_water.py  the one write that must precede the thing it protects
    archive.py     append-only segments for hardened history

`docs/persistence_design.md` explains why each of these is shaped the way it is,
and `python3 -m chain.demo_persistence` stops a chain and starts it again.
"""
from .archive import (COMPACT, FULL, HEADERS, PROFILES, ArchiveError,
                      ArchiveReader, ArchiveWriter, Retention, join_proofs,
                      prune, split_proofs)
from .codec import CodecError, decode, encode
from .db import ChainStore, StoreError
from .high_water import HighWater, HighWaterError
from .undo import UndoError, UndoRecord, apply_undo, capture, retention_depth

__all__ = [
    "encode", "decode", "CodecError",
    "ChainStore", "StoreError",
    "UndoRecord", "UndoError", "capture", "apply_undo", "retention_depth",
    "HighWater", "HighWaterError",
    "ArchiveWriter", "ArchiveReader", "Retention", "FULL", "COMPACT",
    "HEADERS", "PROFILES", "ArchiveError", "split_proofs", "join_proofs",
    "prune",
]
