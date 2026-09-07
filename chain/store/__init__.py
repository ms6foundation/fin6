"""Durable storage for the chain.

Only the archive container is implemented so far; `docs/persistence_design.md`
sketches the rest (the SQLite index, snapshots, undo, the signing high-water
mark).  The codec here is the piece both halves need, since a store and a wire
format want the same canonical encoding.
"""
from .archive import (COMPACT, FULL, HEADERS, PROFILES, ArchiveError,
                      ArchiveReader, ArchiveWriter, Retention, join_proofs,
                      prune, split_proofs)
from .codec import CodecError, decode, encode

__all__ = ["encode", "decode", "CodecError", "ArchiveWriter", "ArchiveReader",
           "Retention", "FULL", "COMPACT", "HEADERS", "PROFILES",
           "ArchiveError", "split_proofs", "join_proofs", "prune"]
