"""The node's store: one SQLite file, one writer, one commit point per block.

Why SQLite and not something faster: the commit boundary in this design is
"apply a whole network block or none of it", and one atomic multi-table
transaction *is* that boundary.  Everything else — an embedded key-value store
plus a hand-written write-ahead log — would be reimplementing the part SQLite
already gets right, for a workload whose bulk lives in archive segments anyway.

What is in here is only the state a node needs to keep validating: the utxo
values and their dead bits, the nullifiers, the registers, the block headers,
the hardened chain, spent turns, and undo records.  Bodies and proofs live in
`archive.py`, which is a different problem with a different answer.

Two details worth naming, because they are where the design and the schema meet:

  * `utxo.dead` is a column rather than a deletion.  The seal tree keeps a spent
    slot so every later note keeps its index, and the table agrees.
  * `cm` is unique *including dead rows*, which is what implements
    `ever_contained` — an output replay is caught by an index rather than a
    scan.

Roots are stored as decimal text.  They are 255-bit field elements and SQLite
integers are 64-bit; text is exact, comparable, and never silently truncates.
"""
from __future__ import annotations

import os
import sqlite3

from ..params import ChainParams
from ..register import GridRegister
from ..state import ChainState
from . import codec
from .undo import UndoRecord, apply_undo

SCHEMA_VERSION = 3

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta("
    "  key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    # `height` and `sealed` are here for the reader, not the ledger: an output
    # is exactly the row a scanning wallet wants, so the UTXO table is the
    # output index and there is no second copy to keep in step.  Part eight
    # found the alternative — an unbounded list in the node's memory — which is
    # fine for a testnet and wrong for anything that stays up.
    "CREATE TABLE IF NOT EXISTS utxo("
    "  pos INTEGER PRIMARY KEY, cm TEXT NOT NULL UNIQUE,"
    "  dead INTEGER NOT NULL DEFAULT 0, height INTEGER, sealed BLOB,"
    "  tag BLOB)",
    "CREATE TABLE IF NOT EXISTS nullifier("
    "  pos INTEGER PRIMARY KEY, nf TEXT NOT NULL UNIQUE, height INTEGER)",
    "CREATE TABLE IF NOT EXISTS txblock("
    "  txid TEXT PRIMARY KEY, height INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS utxo_height ON utxo(height)",
    "CREATE INDEX IF NOT EXISTS nullifier_height ON nullifier(height)",
    "CREATE TABLE IF NOT EXISTS grid_register("
    "  grid_id TEXT PRIMARY KEY, blob BLOB NOT NULL)",
    # `blob` is the whole header, canonically encoded.  The columns beside it
    # are for looking at; the blob is what a client is served, because a header
    # a node has reassembled from columns is a header a node could get wrong.
    "CREATE TABLE IF NOT EXISTS netblock("
    "  height INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, prev TEXT,"
    "  epoch INTEGER, utxo_root TEXT, nf_root TEXT, super_root TEXT,"
    "  registers_root TEXT, blob BLOB, cert BLOB)",
    # The stamps are kept, not just their weight: a client that has to weigh
    # two branches has to be able to check the work, and a number a node
    # reports is not work.
    "CREATE TABLE IF NOT EXISTS hardened("
    "  block_hash TEXT PRIMARY KEY, height INTEGER, prev TEXT, era_id INTEGER,"
    "  weight TEXT, cumulative TEXT, spent_root TEXT, stamps BLOB, drawn BLOB)",
    "CREATE TABLE IF NOT EXISTS spent_turn("
    "  era_id INTEGER, leaf_index INTEGER, block_hash TEXT,"
    "  PRIMARY KEY(era_id, leaf_index))",
    "CREATE TABLE IF NOT EXISTS undo("
    "  height INTEGER PRIMARY KEY, blob BLOB NOT NULL)",
    "CREATE INDEX IF NOT EXISTS utxo_live ON utxo(dead)",
)


class StoreError(Exception):
    pass


class ChainStore:
    """One node's durable state.

    Open it, load what is there, and commit once per network block.  Nothing
    here validates anything: a store that second-guesses consensus is a second
    consensus, and there is only supposed to be one.
    """

    def __init__(self, path, *, undo_depth: int = 729,
                 read_only: bool = False):
        """`read_only` opens a second connection for serving clients.

        The epoch loop writes and the mesh's reader thread reads, so they get
        separate connections: WAL lets a reader see a consistent snapshot while
        a write is in flight, which is the property that keeps answering a
        wallet off the critical path of agreeing a block.
        """
        self.path = str(path)
        self.undo_depth = undo_depth
        self.read_only = read_only
        self.db = sqlite3.connect(self.path, check_same_thread=not read_only)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        if read_only:
            self.db.execute("PRAGMA query_only=ON")
            return
        for stmt in SCHEMA:
            self.db.execute(stmt)
        got = self.get_meta("schema_version")
        if got is None:
            self.set_meta("schema_version", str(SCHEMA_VERSION))
        elif int(got) != SCHEMA_VERSION:
            raise StoreError(f"store is schema {got}, this build speaks "
                             f"{SCHEMA_VERSION}")
        self.db.commit()

    # ── meta ─────────────────────────────────────────────────────────────────

    def get_meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?",
                              (key,)).fetchone()
        return default if row is None else row[0]

    def set_meta(self, key, value):
        self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, str(value)))

    def is_empty(self) -> bool:
        return self.get_meta("tip") is None

    @property
    def height(self) -> int:
        return int(self.get_meta("height", -1))

    @property
    def tip(self) -> str:
        return self.get_meta("tip", "genesis")

    # ── genesis ──────────────────────────────────────────────────────────────

    def initialise(self, state: ChainState):
        """Write a whole state down for the first time.

        Only for genesis, or for adopting a snapshot.  Every later change goes
        through `commit`, which writes what the block changed and nothing else.
        """
        if not self.is_empty():
            raise StoreError("store already holds a chain")
        dump = state.dump()
        with self._write():
            self.db.executemany(
                "INSERT INTO utxo(pos,cm,dead,height,sealed,tag) "
                "VALUES(?,?,?,0,NULL,NULL)",
                [(i, cm, 1 if i in set(dump["utxo_dead"]) else 0)
                 for i, cm in enumerate(dump["utxo"])])
            self.db.executemany(
                "INSERT INTO nullifier(pos,nf,height) VALUES(?,?,0)",
                list(enumerate(dump["nullifiers"])))
            self.set_meta("chain_id", dump["chain_id"])
            self.set_meta("height", dump["height"])
            self.set_meta("tip", dump["tip"])
            self.set_meta("burned_fees", dump["burned_fees"])

    def save_registers(self, registers: dict):
        with self._write():
            self._put_registers(registers)

    # ── loading ──────────────────────────────────────────────────────────────

    def load_state(self, params: ChainParams) -> ChainState:
        """Rebuild the ledger.

        The accumulators come back from their values in one pass — 4.1 us a
        leaf — rather than by replaying blocks, which would re-verify every
        proof the chain has ever carried.
        """
        if self.is_empty():
            raise StoreError("store holds no chain; initialise it first")
        utxo, dead = [], []
        for pos, cm, is_dead in self.db.execute(
                "SELECT pos,cm,dead FROM utxo ORDER BY pos"):
            if pos != len(utxo):
                raise StoreError(f"utxo positions are not contiguous at {pos}")
            utxo.append(cm)
            if is_dead:
                dead.append(pos)
        nfs = []
        for pos, nf in self.db.execute("SELECT pos,nf FROM nullifier ORDER BY pos"):
            if pos != len(nfs):
                raise StoreError(f"nullifier positions jump at {pos}")
            nfs.append(nf)
        # The spine comes back from the block table in height order, the same
        # one pass everything else here uses.
        spine = [row[1] for row in self.db.execute(
            "SELECT height,hash FROM netblock ORDER BY height")]
        return ChainState.load(params, {
            "chain_id": self.get_meta("chain_id"),
            "height": int(self.get_meta("height", -1)),
            "tip": self.get_meta("tip", "genesis"),
            "burned_fees": int(self.get_meta("burned_fees", 0)),
            "utxo": utxo, "utxo_dead": dead, "nullifiers": nfs,
            "history": spine})

    def load_registers(self) -> dict:
        return {gid: GridRegister.load(codec.decode(blob))
                for gid, blob in self.db.execute(
                    "SELECT grid_id, blob FROM grid_register")}

    def headers(self, since: int = 1, to: int | None = None, limit: int = 512):
        """Whole headers, with the certificate that finalised each, in height
        order.  Bounded: a client asking for everything gets a page and a
        promise, not a frame the protocol refuses to send."""
        rows = self.db.execute(
            "SELECT height,blob,cert FROM netblock WHERE height>=? AND height<=? "
            "ORDER BY height LIMIT ?",
            (int(since), int(to) if to is not None else 1 << 62, int(limit) + 1)
        ).fetchall()
        more = len(rows) > limit
        out = []
        for height, blob, cert in rows[:limit]:
            if blob is None:
                continue
            out.append((height, codec.decode(blob),
                        codec.decode(cert) if cert else None))
        return out, more

    # ── what a wallet reads ──────────────────────────────────────────────────

    def outputs(self, since: int = 0, to: int | None = None,
                limit: int = 8000):
        """(height, cm, sealed) in height order, cut on a height boundary.

        Cut on a boundary because a client resumes at the first height it has
        not been shown *completely*; a page that ends inside a height and says
        so by offset would skip an output the moment two pages disagree about
        where they stopped.
        """
        end = int(to) if to is not None else 1 << 62
        rows = self.db.execute(
            "SELECT height,cm,sealed,pos FROM utxo WHERE height>=? AND height<=? "
            "ORDER BY height,pos", (int(since), end)).fetchall()
        nfs = self.db.execute(
            "SELECT height,nf,pos FROM nullifier WHERE height>=? AND height<=? "
            "ORDER BY height,pos", (int(since), end)).fetchall()
        return _cut_on_height(rows, nfs, int(since), int(limit))

    def tagged(self, since: int = 0, to: int | None = None,
               limit: int = 8000):
        """(height, cm, sealed, pos, tag) for a height range, tags included.

        The rows a `tags` query filters.  Deliberately the same rows
        `outputs` serves, so a client that filters and a client that does not
        are reading one table and cannot be shown two different chains.
        """
        end = int(to) if to is not None else 1 << 62
        return self.db.execute(
            "SELECT height,cm,sealed,pos,tag FROM utxo "
            "WHERE height>=? AND height<=? ORDER BY height,pos LIMIT ?",
            (int(since), end, int(limit))).fetchall()

    def tx_height(self, txid: str):
        row = self.db.execute("SELECT height FROM txblock WHERE txid=?",
                              (txid,)).fetchone()
        return row[0] if row else None

    def block_headers(self):
        return list(self.db.execute(
            "SELECT height,hash,prev,epoch,utxo_root,nf_root,super_root,"
            "registers_root FROM netblock ORDER BY height"))

    # ── the commit ───────────────────────────────────────────────────────────

    def commit(self, *, block, delta, state: ChainState, undo: UndoRecord,
               registers: dict | None = None):
        """One network block, applied or not applied.

        The caller has already moved its in-memory state forward; this makes
        that durable.  Everything below tier 2 was a journal and is not written
        at all, so a crash in the middle of an epoch costs the epoch and
        nothing else.
        """
        header = block.header
        if state.height != header.height:
            raise StoreError(f"state is at {state.height}, block is "
                             f"{header.height}")
        with self._write():
            for cm in delta.spent:
                cur = self.db.execute(
                    "UPDATE utxo SET dead=1 WHERE cm=? AND dead=0", (cm,))
                if cur.rowcount != 1:
                    raise StoreError(f"{cm[:14]}… was not an unspent note")
            sealed = _sealed_openings(block)
            pos = self._count("utxo")
            self.db.executemany(
                "INSERT INTO utxo(pos,cm,dead,height,sealed,tag) "
                "VALUES(?,?,0,?,?,?)",
                [(pos + i, cm, header.height, sealed.get(cm, (None, None))[0],
                  sealed.get(cm, (None, None))[1])
                 for i, cm in enumerate(delta.created)])
            pos = self._count("nullifier")
            self.db.executemany(
                "INSERT INTO nullifier(pos,nf,height) VALUES(?,?,?)",
                [(pos + i, nf, header.height)
                 for i, nf in enumerate(delta.nullifiers)])
            self.db.executemany(
                "INSERT OR REPLACE INTO txblock(txid,height) VALUES(?,?)",
                [(tx.txid, header.height) for tx in block.transactions()])
            self.db.execute(
                "INSERT INTO netblock(height,hash,prev,epoch,utxo_root,nf_root,"
                "super_root,registers_root,blob,cert) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (header.height, block.hash(), header.prev_hash, header.epoch,
                 str(header.utxo_root), str(header.nf_root),
                 str(header.super_root), str(header.registers_root),
                 codec.encode(header),
                 codec.encode(block.quorum_cert) if block.quorum_cert else None))
            if registers:
                self._put_registers(registers)
            self.db.execute("INSERT INTO undo(height,blob) VALUES(?,?)",
                            (undo.height, codec.encode(_undo_dump(undo))))
            self._prune_undo(header.height)
            self.set_meta("height", state.height)
            self.set_meta("tip", state.tip)
            self.set_meta("burned_fees", state.burned_fees)

    def commit_hardened(self, hardened):
        """A block entering history is a second, separate durable write."""
        with self._write():
            self.db.execute(
                "INSERT OR REPLACE INTO hardened(block_hash,height,prev,"
                "era_id,weight,cumulative,spent_root,stamps,drawn) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (hardened.block_hash, hardened.height, hardened.prev_hash,
                 hardened.era_id, str(hardened.weight),
                 str(hardened.cumulative), str(hardened.spent_root),
                 codec.encode(list(hardened.stamps)),
                 codec.encode([int(t) for t in hardened.drawn])))
            self.db.executemany(
                "INSERT OR IGNORE INTO spent_turn(era_id,leaf_index,block_hash)"
                " VALUES(?,?,?)",
                [(hardened.era_id, int(t), hardened.block_hash)
                 for t in hardened.drawn])

    def hardened_range(self, since: int = 1, to: int | None = None,
                       limit: int = 256):
        """Hardened blocks in height order, with the stamps that hardened them."""
        rows = self.db.execute(
            "SELECT height,block_hash,prev,era_id,weight,cumulative,"
            "spent_root,stamps,drawn FROM hardened "
            "WHERE height>=? AND height<=? ORDER BY height LIMIT ?",
            (int(since), int(to) if to is not None else 1 << 62,
             int(limit) + 1)).fetchall()
        more = len(rows) > limit
        out = []
        for (height, bh, prev, era_id, weight, cumulative, spent_root,
             stamps, drawn) in rows[:limit]:
            out.append({
                "height": height, "block_hash": bh, "prev": prev,
                "era_id": era_id, "weight": weight, "cumulative": cumulative,
                "spent_root": spent_root,
                "stamps": codec.decode(stamps) if stamps else [],
                "drawn": codec.decode(drawn) if drawn else []})
        return out, more

    def turn_is_spent(self, era_id: int, leaf_index: int) -> bool:
        return self.db.execute(
            "SELECT 1 FROM spent_turn WHERE era_id=? AND leaf_index=?",
            (era_id, leaf_index)).fetchone() is not None

    # ── going backwards ──────────────────────────────────────────────────────

    def undo_heights(self):
        return [h for (h,) in self.db.execute(
            "SELECT height FROM undo ORDER BY height")]

    def rollback(self, state: ChainState, registers: dict | None = None):
        """Roll the tip off, in memory and on disk, or neither.

        The record is applied to the live state first: if it does not reproduce
        the roots it claimed, nothing is written and the store is untouched.
        """
        row = self.db.execute(
            "SELECT height, blob FROM undo ORDER BY height DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise StoreError("no undo record — this block is beyond the "
                             "rewrite ceiling and is irreversible here")
        height, blob = row
        record = _undo_load(codec.decode(blob))
        if height != self.height:
            raise StoreError(f"newest undo is {height}, tip is {self.height}")
        apply_undo(state, record)
        with self._write():
            if record.created:
                self.db.execute("DELETE FROM utxo WHERE cm IN (%s)" %
                                ",".join("?" * len(record.created)),
                                tuple(record.created))
            if record.nullifiers:
                self.db.execute("DELETE FROM nullifier WHERE nf IN (%s)" %
                                ",".join("?" * len(record.nullifiers)),
                                tuple(record.nullifiers))
            for cm in record.unspend:
                self.db.execute("UPDATE utxo SET dead=0 WHERE cm=?", (cm,))
            self.db.execute("DELETE FROM txblock WHERE height=?", (height,))
            self.db.execute("DELETE FROM netblock WHERE height=?", (height,))
            self.db.execute("DELETE FROM undo WHERE height=?", (height,))
            if record.registers:
                restored = {d["grid_id"]: GridRegister.load(d)
                            for d in record.registers}
                self._put_registers(restored)
                if registers is not None:
                    registers.update(restored)
            self.set_meta("height", state.height)
            self.set_meta("tip", state.tip)
            self.set_meta("burned_fees", state.burned_fees)
        return record

    # ── internals ────────────────────────────────────────────────────────────

    def _write(self):
        return _Transaction(self.db)

    def _count(self, table) -> int:
        return self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def _put_registers(self, registers: dict):
        self.db.executemany(
            "INSERT INTO grid_register(grid_id,blob) VALUES(?,?) "
            "ON CONFLICT(grid_id) DO UPDATE SET blob=excluded.blob",
            [(gid, codec.encode(reg.dump())) for gid, reg in registers.items()])

    def _prune_undo(self, height: int):
        """Past the fork ceiling a block cannot be rewritten, so the record that
        would rewrite it is dead weight."""
        self.db.execute("DELETE FROM undo WHERE height <= ?",
                        (height - self.undo_depth,))

    def stats(self):
        return {
            "path": self.path,
            "bytes": os.path.getsize(self.path),
            "height": self.height,
            "tip": self.tip,
            "utxo_rows": self._count("utxo"),
            "utxo_live": self.db.execute(
                "SELECT COUNT(*) FROM utxo WHERE dead=0").fetchone()[0],
            "nullifiers": self._count("nullifier"),
            "netblocks": self._count("netblock"),
            "undo_records": self._count("undo"),
            "registers": self._count("grid_register"),
            "hardened": self._count("hardened"),
        }

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _Transaction:
    """BEGIN IMMEDIATE … COMMIT, or ROLLBACK and let the exception out.

    IMMEDIATE rather than DEFERRED so the writer takes its lock up front: a
    node that discovers halfway through a block that it cannot have the write
    lock has already done the expensive half for nothing.
    """

    def __init__(self, db):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.db.commit()
        else:
            self.db.rollback()
        return False


def _undo_dump(rec: UndoRecord) -> dict:
    return {"height": rec.height, "block_hash": rec.block_hash,
            "prev_tip": rec.prev_tip, "prev_height": rec.prev_height,
            "unspend": list(rec.unspend), "created": list(rec.created),
            "nullifiers": list(rec.nullifiers), "fees": rec.fees,
            "prev_utxo_root": rec.prev_utxo_root,
            "prev_nf_root": rec.prev_nf_root,
            "registers": list(rec.registers)}


def _undo_load(d: dict) -> UndoRecord:
    return UndoRecord(
        height=d["height"], block_hash=d["block_hash"], prev_tip=d["prev_tip"],
        prev_height=d["prev_height"], unspend=tuple(d["unspend"]),
        created=tuple(d["created"]), nullifiers=tuple(d["nullifiers"]),
        fees=d["fees"], prev_utxo_root=d["prev_utxo_root"],
        prev_nf_root=d["prev_nf_root"], registers=tuple(d["registers"]))


def _sealed_openings(block) -> dict:
    """cm -> (sealed opening, detection tag) for every output in a block."""
    out = {}
    for tx in block.transactions():
        blobs = list(tx.output_notes) + [None] * len(tx.output_cms)
        tags = list(tx.output_tags) + [None] * len(tx.output_cms)
        for cm, blob, tag in zip(tx.output_cms, blobs, tags):
            out[cm] = (blob or None, tag or None)
    return out


def _cut_on_height(outputs, nullifiers, since: int, limit: int):
    """Take whole heights until the page is full.  Returns (outs, nfs, next).

    A single height that does not fit on its own is served whole anyway: half a
    height is worse than a large frame, because the client cannot tell that it
    got half.
    """
    if len(outputs) <= limit and len(nullifiers) <= limit:
        return list(outputs), list(nullifiers), None
    heights = sorted({h for h, *_ in outputs} | {h for h, *_ in nullifiers})
    cut = heights[0] if heights else since
    for candidate in heights:
        n_out = sum(1 for h, *_ in outputs if h <= candidate)
        n_nf = sum(1 for h, *_ in nullifiers if h <= candidate)
        if max(n_out, n_nf) > limit and candidate != heights[0]:
            break
        cut = candidate
    return ([r for r in outputs if r[0] <= cut],
            [r for r in nullifiers if r[0] <= cut], cut + 1)
