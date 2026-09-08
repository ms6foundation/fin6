"""The user's side of the chain: one seed, and the notes it can spend.

    from wallet import WalletKeys, Wallet

    keys = WalletKeys.generate()
    w = Wallet(keys, params, chain_id=chain_id)
    w.scan(outputs)                     # find money by trial decryption
    tx, change = w.send(address, 250)   # build, seal and prove a transfer

A wallet holds exactly one secret.  Everything else — the spend key, the
viewing key, the detection key, the address — is derived from it, and every
note it holds can be recovered by scanning the chain, so losing the note file
costs a rescan rather than the money.

This package depends on `chain` and nothing depends on it.  The ledger does not
know that anyone is watching.
"""
from .keys import Address, AddressError, WalletKeys, ephemeral
from .sealing import (NoteCipherError, decrypt_opening, detection_tag,
                      encrypt_opening, seal_output)
from .store import Held, Wallet, WalletError

__all__ = ["Address", "AddressError", "Held", "NoteCipherError", "Wallet",
           "WalletError", "WalletKeys", "decrypt_opening", "detection_tag",
           "encrypt_opening", "ephemeral", "seal_output"]
