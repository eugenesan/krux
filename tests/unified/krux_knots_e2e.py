#!/usr/bin/env python3
"""Drive Krux's own signing code against Bitcoin Knots.

Uses krux.key.Key / krux.wallet.Wallet and krux.sighash.sign_with, the same
call the app makes in PSBTSigner.add_signatures, and requires Knots to accept
and mine the result. Then checks the claim the review screen makes, carried
through to the transaction a node accepts.
"""

import os
import sys

# Krux's own source, so its own Key/Wallet/sighash code is exercised rather
# than a reimplementation. embit comes from the environment, i.e. the editable
# install pyproject.toml points at vendor/embit.
_KRUX = os.environ.get("KRUX_SRC")
if not _KRUX:
    _KRUX = os.path.join(os.path.dirname(__file__), "..", "..", "src")
sys.path.insert(0, os.path.abspath(_KRUX))

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet

from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput
from embit import bip32, ec, script

from krux.key import Key, TYPE_SINGLESIG
from krux.wallet import Wallet

ACTIVATION_HEIGHT = 150
MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
PATH = "m/84h/1h/0h/0/0"


class KruxKnotsE2E(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}", "-corepolicy=0"]
        ]

    def run_test(self):
        from krux import sighash as krux_sighash

        node = self.nodes[0]
        mini = MiniWallet(node)
        self.generate(mini, ACTIVATION_HEIGHT + 10)

        wallet = Wallet(Key(MNEMONIC, TYPE_SINGLESIG, NETWORKS["regtest"]))
        self.log.info(
            "Krux wallet loaded, fingerprint %s", wallet.key.fingerprint.hex()
        )
        child = wallet.key.root.derive(PATH)
        spk = script.p2wpkh(child.key.get_public_key())
        derivation = DerivationPath(wallet.key.fingerprint, bip32.parse_path(PATH))
        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("33" * 32)).get_public_key())

        # The same transaction three times: the coordinator asking for the
        # unified message, asking for the standard one, and saying nothing.
        for declared, expected_byte in (
            (SIGHASH.ALL | SIGHASH.UNIFIED, 0x21),
            (SIGHASH.ALL, 0x01),
            (None, 0x01),
        ):
            value = 100_000_000
            utxo = mini.send_to(
                from_node=node, scriptPubKey=bytes(spk.data), amount=value
            )
            self.generate(mini, 1)

            tx = Transaction(
                vin=[
                    TransactionInput(
                        bytes.fromhex(utxo["txid"]),
                        utxo["sent_vout"],
                        sequence=0xFFFFFFFE,
                    )
                ],
                vout=[TransactionOutput(value - 10_000, sink)],
            )
            psbt = PSBT(tx)
            psbt.inputs[0].witness_utxo = TransactionOutput(value, spk)
            psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = derivation
            if declared is not None:
                psbt.inputs[0].sighash_type = declared

            # the device's own decision, so this cannot drift from the screen
            shown, reason = krux_sighash.screen_sighash_type(psbt, wallet.key)
            assert shown is not None, f"declared {declared}: refused ({reason})"
            assert (
                shown == expected_byte
            ), f"expected {hex(expected_byte)}, screen says {hex(shown)}"

            before = len(psbt.inputs[0].partial_sigs)
            krux_sighash.sign_with(psbt, wallet.key)
            assert len(psbt.inputs[0].partial_sigs) > before, "no signature was added"

            pub, sigbytes = list(psbt.inputs[0].partial_sigs.items())[0]
            assert (
                sigbytes[-1] == shown
            ), f"screen said {hex(shown)}, signature carries {hex(sigbytes[-1])}"
            self.log.info(
                "  declared %s: screen says %s, signature carries %s",
                hex(declared) if declared is not None else "nothing",
                hex(shown),
                hex(sigbytes[-1]),
            )

            tx.vin[0].witness = script.Witness([sigbytes, pub.sec()])
            raw = tx.serialize().hex()
            res = node.testmempoolaccept([raw])[0]
            assert res["allowed"], (declared, res)
            txid = node.sendrawtransaction(raw)
            blk = self.generate(mini, 1)[0]
            assert txid in node.getblock(blk)["tx"], "was not mined"

            mined = node.getrawtransaction(txid, True, blk)
            witness_sig = bytes.fromhex(mined["vin"][0]["txinwitness"][0])
            assert witness_sig[-1] == shown, (
                f"mined transaction carries {hex(witness_sig[-1])}, "
                f"screen said {hex(shown)}"
            )
            self.log.info(
                "    accepted and mined by Knots, witness carries %s",
                hex(witness_sig[-1]),
            )

    def test_device_refuses_a_type_it_cannot_name(self):
        """The two refusals, and that neither one signs anything"""
        from krux import sighash as krux_sighash

        wallet = Wallet(Key(MNEMONIC, TYPE_SINGLESIG, NETWORKS["regtest"]))
        child = wallet.key.root.derive(PATH)
        spk = script.p2wpkh(child.key.get_public_key())
        derivation = DerivationPath(wallet.key.fingerprint, bip32.parse_path(PATH))

        for declared, expected_reason in (
            (SIGHASH.NONE, krux_sighash.REFUSED_PARTIAL),
            (SIGHASH.ALL | SIGHASH.ANYONECANPAY, krux_sighash.REFUSED_PARTIAL),
            (SIGHASH.SINGLE, krux_sighash.REFUSED_PARTIAL),
        ):
            tx = Transaction(
                vin=[TransactionInput(b"\x11" * 32, 0, sequence=0xFFFFFFFE)],
                vout=[TransactionOutput(90_000, spk)],
            )
            psbt = PSBT(tx)
            psbt.inputs[0].witness_utxo = TransactionOutput(100_000, spk)
            psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = derivation
            psbt.inputs[0].sighash_type = declared

            shown, reason = krux_sighash.screen_sighash_type(psbt, wallet.key)
            assert shown is None, f"{hex(declared)} should not be signable"
            assert reason == expected_reason, (hex(declared), reason)

            try:
                krux_sighash.sign_with(psbt, wallet.key)
            except krux_sighash.PSBTRefusedError as e:
                assert e.reason == expected_reason
            else:
                raise AssertionError(f"{hex(declared)} was signed anyway")
            assert not psbt.inputs[0].partial_sigs


if __name__ == "__main__":
    KruxKnotsE2E(__file__).main()
