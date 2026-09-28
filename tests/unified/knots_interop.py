#!/usr/bin/env python3
"""Cross-implementation check: a signature produced by the vendored embit must
be accepted by Bitcoin Knots.

embit comes from the environment, i.e. the editable install pyproject.toml
points at vendor/embit, so this tests what the firmware actually links against.
"""

import os
import sys

# Krux's own source, for the PSBTSigner the app really uses.
_KRUX = os.environ.get("KRUX_SRC")
if not _KRUX:
    _KRUX = os.path.join(os.path.dirname(__file__), "..", "..", "src")
sys.path.insert(0, os.path.abspath(_KRUX))

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

from embit.networks import NETWORKS
from embit.psbt import PSBT
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput
from embit import bip32, bip39, ec, script

from krux.key import Key, TYPE_SINGLESIG
from krux.wallet import Wallet

ACTIVATION_HEIGHT = 150
MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
).split()


class EmbitInteropTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}", "-corepolicy=0"]
        ]

    def build_wallet(self):
        """A real Krux wallet, as the device would hold it"""
        return Wallet(
            Key(
                " ".join(MNEMONIC),
                TYPE_SINGLESIG,
                NETWORKS["regtest"],
            )
        )

    def psbt_for(self, wallet, utxo, sink, script_pubkey, value):
        """A single-input p2wpkh PSBT declaring the unified opt-in"""
        root = wallet.key.root
        path = "m/84h/1h/0h/0/0"
        child = root.derive(path)
        psbt = PSBT(
            Transaction(
                vin=[
                    TransactionInput(
                        bytes.fromhex(utxo["txid"]),
                        utxo["sent_vout"],
                        sequence=0xFFFFFFFE,
                    )
                ],
                vout=[TransactionOutput(value - 10_000, sink)],
            )
        )
        psbt.inputs[0].witness_utxo = TransactionOutput(value, script_pubkey)
        psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = __import__(
            "embit.psbt", fromlist=["DerivationPath"]
        ).DerivationPath(root.child(0).fingerprint, bip32.parse_path(path))
        return psbt

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, ACTIVATION_HEIGHT + 10)
        self.log.info(
            "hardfork deployment: %s", node.getdeploymentinfo().get("blake2b")
        )

        krux_wallet = self.build_wallet()
        path = "m/84h/1h/0h/0/0"
        child = krux_wallet.key.root.derive(path)
        spk = script.p2wpkh(child.key.get_public_key())
        self.log.info(
            "Krux wallet loaded, fingerprint %s", krux_wallet.key.fingerprint.hex()
        )

        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("33" * 32)).get_public_key())
        value = 100_000_000

        for declared, expected in (
            (SIGHASH.ALL | SIGHASH.UNIFIED, 0x21),
            (SIGHASH.ALL, 0x01),
            (None, 0x01),
        ):
            utxo = wallet.send_to(
                from_node=node, scriptPubKey=bytes(spk.data), amount=value
            )
            self.generate(wallet, 1)

            psbt = self.psbt_for(krux_wallet, utxo, sink, spk, value)
            if declared is not None:
                psbt.inputs[0].sighash_type = declared

            from krux import sighash as krux_sighash

            shown, reason = krux_sighash.screen_sighash_type(psbt, krux_wallet.key)
            assert shown is not None, f"declared {declared}: refused ({reason})"
            assert (
                shown == expected
            ), f"expected {hex(expected)}, screen says {hex(shown)}"

            # the call the app makes
            krux_sighash.sign_with(psbt, krux_wallet.key)
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

            raw = Transaction(
                vin=[
                    TransactionInput(
                        bytes.fromhex(utxo["txid"]),
                        utxo["sent_vout"],
                        sequence=0xFFFFFFFE,
                    )
                ],
                vout=[TransactionOutput(value - 10_000, sink)],
            )
            raw.vin[0].witness = script.Witness([sigbytes, pub.sec()])
            txid = node.sendrawtransaction(raw.serialize().hex())
            blk = self.generate(wallet, 1)[0]
            assert txid in node.getblock(blk)["tx"], "was not mined"
            self.log.info("    accepted and mined by Knots")

            mined = node.getrawtransaction(txid, True, blk)
            witness_sig = bytes.fromhex(mined["vin"][0]["txinwitness"][0])
            assert (
                witness_sig[-1] == shown
            ), f"mined transaction carries {hex(witness_sig[-1])}, screen said {hex(shown)}"

        # Control, on its own unspent output so the rejection cannot be
        # "missing-inputs": the legacy segwit digest carrying the opt-in byte
        # must fail signature verification, not be waved through.
        key = ec.PrivateKey(bytes.fromhex("11" * 32))
        spk2 = script.p2wpkh(key.get_public_key())
        utxo2 = wallet.send_to(
            from_node=node, scriptPubKey=bytes(spk2.data), amount=value
        )
        self.generate(wallet, 1)
        tx2 = Transaction(
            vin=[
                TransactionInput(
                    bytes.fromhex(utxo2["txid"]),
                    utxo2["sent_vout"],
                    sequence=0xFFFFFFFE,
                )
            ],
            vout=[TransactionOutput(value - 10_000, sink)],
        )
        psbt2 = PSBT(tx2)
        psbt2.inputs[0].witness_utxo = TransactionOutput(value, spk2)
        ht = SIGHASH.ALL | SIGHASH.UNIFIED

        # first prove this output IS spendable with a correct unified signature
        good2 = key.sign(psbt2.sighash(0, sighash=ht)).serialize() + bytes([ht])
        tx2.vin[0].witness = script.Witness([good2, key.get_public_key().sec()])
        ok2 = node.testmempoolaccept([tx2.serialize().hex()])[0]
        assert ok2["allowed"], ("control output must be spendable", ok2)
        self.log.info("  control: correct unified signature accepted")

        # now the same output with the legacy digest under the opt-in byte
        sig_bad = key.sign(psbt2.sighash(0, sighash=SIGHASH.ALL)).serialize() + bytes(
            [ht]
        )
        tx2.vin[0].witness = script.Witness([sig_bad, key.get_public_key().sec()])
        bad = node.testmempoolaccept([tx2.serialize().hex()])[0]
        assert not bad[
            "allowed"
        ], "a legacy digest with the opt-in byte must not verify"
        assert "missing-inputs" not in bad.get("reject-reason", ""), (
            "wrong rejection reason",
            bad,
        )
        self.log.info(
            "  control: same unspent output, legacy digest rejected (%s)",
            bad.get("reject-reason", ""),
        )

        assert_equal(len(psbt2.inputs), 1)


if __name__ == "__main__":
    EmbitInteropTest(__file__).main()
