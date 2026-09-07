"""fin6 private chain — a transaction-based ledger verified with mq/ms6.

    from chain import DEMO, bootstrap, transfer, run_epoch

    nodes, wallets, genesis = bootstrap(["v0", "v1", "v2"],
                                        {"alice": [1000], "bob": []}, DEMO)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, DEMO)
    for n in nodes.values():
        n.submit(tx)
    epoch = run_epoch(nodes, DEMO, height=1, epoch=1, base_seed="s")
    for n in nodes.values():
        n.apply(epoch.result.block)

Run the demo with   python3 -m chain.demo
Run the tests with  python3 -m chain.tests.run_all
"""
from .block import (Attestation, Block, BlockHeader, CeremonyMeta, FaultReport,
                    QuorumCert, SignedProposal)
from .ceremony import (Ceremony, CeremonyResult, EquivocatingLeader, Grid,
                       HonestLeader, NodeWorkload, SilentLeader, run_epoch)
from .locality import (Enrolment, GridSpec, Topology, partition_of_nullifier,
                       sign_enrolment, tx_partition)
from .proofs import BACKENDS, available_backends, get_backend
from .register import AttendanceRoll, GridRegister, MemberRecord, Standing
from .tiered import CeremonyBlock, NetworkBlock, SuperBlock
from .trustlist import TrustList
from . import hardening
from .hardening import Era, NetworkHistory, HardeningParams
from .crypto import Signer
from .network import Wallet, bootstrap, transfer
from .node import Node
from .notes import Note, note_id, note_vector
from .params import DEMO, PRESETS, STRONG, ChainParams
from .seal import SealAccumulator, seal_root
from .state import ChainState, UtxoDelta, merge_deltas
from .transaction import (Transaction, TxError, build_transaction,
                          verify_transaction, verify_transaction_vs6)
from .txsystem import TxSystem, tx_system

__all__ = [
    "ChainParams", "DEMO", "STRONG", "PRESETS",
    "Note", "note_id", "note_vector",
    "TxSystem", "tx_system",
    "Transaction", "TxError", "build_transaction", "verify_transaction",
    "verify_transaction_vs6",
    "SealAccumulator", "seal_root", "ChainState",
    "Block", "BlockHeader", "CeremonyMeta", "SignedProposal", "Attestation",
    "FaultReport", "QuorumCert",
    "Grid", "Ceremony", "CeremonyResult", "run_epoch",
    "HonestLeader", "SilentLeader", "EquivocatingLeader",
    "Node", "Signer", "Wallet", "bootstrap", "transfer",
    # tiered design
    "Standing", "GridRegister", "MemberRecord", "AttendanceRoll",
    "Topology", "GridSpec", "Enrolment", "sign_enrolment",
    "partition_of_nullifier", "tx_partition",
    "TrustList", "UtxoDelta", "merge_deltas",
    "CeremonyBlock", "SuperBlock", "NetworkBlock",
    "get_backend", "available_backends", "BACKENDS", "NodeWorkload",
    # hardening
    "hardening", "Era", "NetworkHistory", "HardeningParams",
]
