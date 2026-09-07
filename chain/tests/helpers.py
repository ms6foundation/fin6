"""Shared fixtures, and a raw transaction forger used to test soundness.

build_transaction refuses to build a nonsense transaction, which is the right
behaviour for a wallet and useless for testing a verifier.  forge_transaction
runs the same machinery with the guard rails removed, so the tests can hand the
verifier things a well-behaved builder would never produce.
"""
from __future__ import annotations

from mq.ms6 import P

from ..proofs import get_backend

from ..crypto import Signer
from ..network import bootstrap, transfer
from ..notes import Note, note_id, note_vector, nullifier_id
from ..params import DEMO
from ..transaction import (TX_VERSION, Transaction, TxInput, binding_scalar,
                           sig_message)
from ..txsystem import tx_system

VALIDATORS = [f"v{i:02d}" for i in range(7)]


def network(validators=None, endow=None, params=DEMO):
    return bootstrap(validators or VALIDATORS,
                     endow or {"alice": [1000], "bob": [250]}, params)


def funded_network(params=DEMO, validators=None):
    """A network with one transaction already in every mempool."""
    nodes, wallets, gen = network(validators, params=params)
    tx, _ = transfer(wallets["alice"], wallets["bob"], 300, 5, params)
    for n in nodes.values():
        n.submit(tx)
    return nodes, wallets, tx


def raw_note(value, owner_pub, params, asset=None, rho=None):
    """A note built without the range check build_transaction would apply."""
    from ..crypto import owner_field, rand_field
    from ..notes import asset_field
    return Note(value=value % P,
                asset=asset if asset is not None else asset_field("USD"),
                owner=owner_field(owner_pub),
                rho=rand_field() if rho is None else rho,
                blinders=tuple(rand_field() for _ in range(params.note_blinders)))


def forge_transaction(spends, outputs, params, declared_fee=0, chain_id=None,
                      mutate_v=None, sign_with=None, declared_out_cms=None,
                      binding_override=None):
    """Build a transaction bypassing every caller-side sanity check."""
    chain_id = chain_id or params.chain_id
    in_notes = [n for n, _ in spends]
    signers = [s for _, s in spends]

    in_cms = [note_id(note_vector(n, params)) for n in in_notes]
    out_cms = [note_id(note_vector(n, params)) for n in outputs]
    declared = list(declared_out_cms) if declared_out_cms else out_cms
    owner_pubs = [(sign_with[j] if sign_with else s).public_hex
                  for j, s in enumerate(signers)]

    beta = binding_scalar(chain_id, TX_VERSION, declared_fee, in_cms, declared,
                          owner_pubs)
    if binding_override is not None:
        beta = binding_override

    ts = tx_system(params, len(in_notes), len(outputs))
    x_base = []
    for n in in_notes + outputs:
        x_base.extend(n.coords())
    x_base.append(beta)
    X = ts.lift(x_base)
    v = ts.F(X)
    if mutate_v is not None:
        v = mutate_v(list(v), ts)

    z = [X[i] for i in range(ts.N) if i != ts.bind_pos]
    proofs = {}
    for nm in params.proof_backends:
        b = get_backend(nm)
        rounds = params.zk_rounds if nm == "ssh5" else b.rounds_for(params.security_bits)
        proofs[nm] = b.prove(ts, v, {ts.bind_pos: beta}, z, rounds=rounds)

    msg = sig_message(beta)
    keys = sign_with or signers
    inputs = tuple(
        TxInput(cm=cm, nullifier=nullifier_id(v[ts.nf_rows[j]]),
                owner_pub=keys[j].public_hex, signature=keys[j].sign(msg))
        for j, cm in enumerate(in_cms))
    return Transaction(version=TX_VERSION, chain_id=chain_id, fee=declared_fee,
                       inputs=inputs, output_cms=tuple(declared),
                       v=tuple(int(a) for a in v), binding=beta, proofs=proofs), ts
