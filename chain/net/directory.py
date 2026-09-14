"""Finding a seat, when you already know whose seat it is.

Review C6: peers come from the roster and `net.json`, so a network that grows
needs joiners to find each other. What makes this a small problem rather than
the usual one is that **the identities are already settled**. The genesis
document names every founder and its key, and admissions add to that set
through the chain; discovery is only ever about *addresses*. There is no sybil
question here, because a record signed by a key the roster does not name is not
an unknown peer — it is noise, and it is dropped without a second thought.

So the whole of it is one signed statement:

    "I am `fin6-n03`, I am listening on this host and port, as of epoch 41."

Signed by the roster key, gossiped between peers, newest-per-node wins. A node
that moves signs a new one and it supersedes the old; a node that is shouted
about by somebody else is unaffected, because only its own key can say where it
is.

What this deliberately does not do is decide *who* may join. A record is a
claim about an address, never about a seat: `Topology.assign_newcomer` and the
register decide membership, and this module only ever answers "where".
"""
from __future__ import annotations

from dataclasses import dataclass

from ..crypto import h_bytes, verify_sig

#: How many epochs an address record is believed for after the epoch it names.
#: Long enough that a node which is briefly down does not vanish from everyone
#: else's directory, short enough that an address somebody abandoned stops
#: being dialled. At the shipped 19.75 s epoch, 180 epochs is about an hour.
MAX_AGE_EPOCHS = 180

#: And how far into the future a record may claim to be from, which is a clock
#: allowance rather than a policy: a peer whose clock is minutes fast should
#: still be findable.
MAX_SKEW_EPOCHS = 4


@dataclass(frozen=True)
class AddressRecord:
    """Where one seat says it is listening."""
    node_id: str
    public_hex: str
    chain_id: str
    host: str
    port: int
    epoch: int
    signature: str = ""

    @property
    def address(self) -> tuple:
        return (self.host, int(self.port))

    @staticmethod
    def message(chain_id, node_id, host, port, epoch) -> bytes:
        return h_bytes("address", chain_id, node_id, host, int(port),
                       int(epoch))

    def verify(self) -> bool:
        return verify_sig(self.public_hex, self.message(
            self.chain_id, self.node_id, self.host, self.port, self.epoch),
            self.signature)


def sign_address(signer, node_id: str, chain_id: str, listen, epoch: int
                 ) -> AddressRecord:
    host, port = listen
    msg = AddressRecord.message(chain_id, node_id, host, port, epoch)
    return AddressRecord(node_id=node_id, public_hex=signer.public_hex,
                         chain_id=chain_id, host=str(host), port=int(port),
                         epoch=int(epoch), signature=signer.sign(msg))


class Directory:
    """The addresses this node believes, newest per seat.

    Bounded by the roster: at most one entry per node the genesis document
    names, so the memory this can consume is the size of the network and not
    the size of what somebody sends.
    """

    def __init__(self, chain_id: str, validators: dict, node_id: str = "",
                 max_age: int = MAX_AGE_EPOCHS,
                 max_skew: int = MAX_SKEW_EPOCHS):
        self.chain_id = chain_id
        self.validators = dict(validators)
        self.node_id = node_id
        self.max_age = max_age
        self.max_skew = max_skew
        self.records: dict = {}          # node_id -> AddressRecord
        self.refused = 0

    # ── learning ─────────────────────────────────────────────────────────────

    def learn(self, record, now_epoch: int) -> bool:
        """Believe a record, or say why not by returning False.

        Four ways to be ignored, and each is a different attack or mistake:
        not a seat this chain knows, not signed by that seat's key, from
        another chain, or stale — and one way to be uninteresting, which is
        being older than what is already held.
        """
        if not isinstance(record, AddressRecord):
            self.refused += 1
            return False
        key = self.validators.get(record.node_id)
        if key is None or key != record.public_hex:
            self.refused += 1
            return False                  # not a seat, or not its key
        if record.chain_id != self.chain_id:
            self.refused += 1
            return False
        if record.epoch > now_epoch + self.max_skew:
            self.refused += 1
            return False                  # from the future
        if now_epoch - record.epoch > self.max_age:
            self.refused += 1
            return False                  # somebody's old address
        if not record.port or not record.host:
            self.refused += 1
            return False
        if not record.verify():
            self.refused += 1
            return False
        held = self.records.get(record.node_id)
        if held is not None and held.epoch >= record.epoch:
            return False                  # not news
        self.records[record.node_id] = record
        return True

    def absorb(self, records, now_epoch: int) -> int:
        return sum(1 for r in (records or ()) if self.learn(r, now_epoch))

    # ── telling ──────────────────────────────────────────────────────────────

    def fresh(self, now_epoch: int) -> list:
        """What is worth gossiping: everything still inside its window."""
        return [r for r in self.records.values()
                if now_epoch - r.epoch <= self.max_age]

    def address_of(self, node_id: str):
        record = self.records.get(node_id)
        return None if record is None else record.address

    def unknown(self, known) -> list:
        """Seats this node holds an address for and is not talking to.

        The question the dial loop asks. `known` is whoever it is already
        configured for or connected to.
        """
        return sorted(set(self.records) - set(known) - {self.node_id})

    def missing(self) -> list:
        """Seats on the roster nobody has told us where to find."""
        return sorted(set(self.validators) - set(self.records)
                      - {self.node_id})

    def __len__(self) -> int:
        return len(self.records)
