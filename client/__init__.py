"""What talks to a node without being one.

    from client import Client, LightClient, Adjudicator

Three levels of doubt, and they are different clients rather than settings on
one.  `Client` asks and believes; `LightClient` verifies the tip, its ancestry
and its own notes against roots it checked; `Adjudicator` is convened when two
nodes disagree and only work can settle it.

Nothing here is a peer.  A client dials, asks one thing, and is answered on the
same connection; it never joins a ceremony and cannot become a validator by
asking nicely — `chain.net.frame.CLIENT_KINDS` is where that boundary is drawn.
"""
from .adjudicate import Adjudicator, Branch
from .light import Checked, LightClient, LightError, Trusted
from .rpc import Client, ClientError

__all__ = ["Adjudicator", "Branch", "Checked", "Client", "ClientError",
           "LightClient", "LightError", "Trusted"]
