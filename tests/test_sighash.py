"""The unified opt-in sighash, as this device uses it.

Covers what the review screen claims, what ends up on the signature, and the
cases the device refuses to sign at all.
"""

import pytest

from .test_psbt import tdata as psbt_tdata  # noqa: F401  re-exported fixture

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
UNIFIED_ALL = 0x21  # SIGHASH.ALL | SIGHASH.UNIFIED
ZERO_FINGERPRINT = b"\x00\x00\x00\x00"


def sighash():
    from krux import sighash

    return sighash


def signer(wallet, psbt):
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE

    return PSBTSigner(wallet, psbt, FORMAT_NONE)


def singlesig(script_type=None):
    from embit.networks import NETWORKS
    from krux.key import Key, TYPE_SINGLESIG, P2WPKH
    from krux.wallet import Wallet

    return Wallet(
        Key(
            MNEMONIC,
            TYPE_SINGLESIG,
            NETWORKS["test"],
            script_type=script_type or P2WPKH,
        )
    )


def multisig():
    from embit.networks import NETWORKS
    from krux.key import Key, TYPE_MULTISIG
    from krux.wallet import Wallet

    return Wallet(Key(MNEMONIC, TYPE_MULTISIG, NETWORKS["test"]))


@pytest.fixture(autouse=True)
def _device(m5stickv, mp_modules):  # pylint: disable=W0613
    """The device modules every krux import needs stood in for"""


@pytest.fixture
def segwit(psbt_tdata):  # pylint: disable=W0613
    """A native segwit single-sig PSBT declaring nothing"""
    return signer(singlesig(), psbt_tdata.P2WPKH_PSBT)


@pytest.fixture
def taproot(psbt_tdata):  # pylint: disable=W0613
    """A taproot single-sig PSBT declaring nothing"""
    from krux.key import P2TR

    return signer(singlesig(P2TR), psbt_tdata.P2TR_PSBT)


def test_unified_opt_in_is_an_allowlisted_type():
    """The opt-in is the one non-default byte this device will ask for"""
    from embit.transaction import SIGHASH

    assert SIGHASH.UNIFIED == 0x20
    assert UNIFIED_ALL == SIGHASH.ALL | SIGHASH.UNIFIED
    assert UNIFIED_ALL in sighash().SIGNABLE_SIGHASH_TYPES


@pytest.mark.parametrize(
    "declared, expected",
    [
        (None, 0x00),  # SIGHASH.DEFAULT
        (0x00, 0x00),
        (0x01, 0x01),  # SIGHASH.ALL
        (UNIFIED_ALL, UNIFIED_ALL),
    ],
)
def test_sighash_type_follows_the_psbt(segwit, declared, expected):
    """One type across every input is what gets asked for"""
    for inp in segwit.psbt.inputs:
        inp.sighash_type = declared
    assert sighash().sighash_type(segwit.psbt) == expected


def test_sighash_type_falls_back_on_disagreement(psbt_tdata):
    """Inputs asking for different things get the default, not one of them"""
    sgn = signer(singlesig(), psbt_tdata.P2PKH_PSBT)
    assert len(sgn.psbt.inputs) == 3
    sgn.psbt.inputs[0].sighash_type = 0x01
    sgn.psbt.inputs[1].sighash_type = UNIFIED_ALL
    assert sighash().sighash_type(sgn.psbt) == 0x00


def test_sighash_type_ignores_unsignable_declarations(segwit):
    """A type the device will never sign falls back rather than being asked for"""
    segwit.psbt.inputs[0].sighash_type = 0x02  # SIGHASH_NONE
    assert sighash().sighash_type(segwit.psbt) == 0x00


def test_screen_names_all_off_taproot(segwit):
    """0x01 off taproot is BIP143's message, which is what will be signed"""
    shown, reason = sighash().screen_sighash_type(segwit.psbt, segwit.wallet.key)
    assert (shown, reason) == (0x01, None)


def test_screen_names_default_on_taproot(taproot):
    """0x00 on taproot is BIP341's, and it is the type the signature will carry"""
    shown, reason = sighash().screen_sighash_type(taproot.psbt, taproot.wallet.key)
    assert (shown, reason) == (0x00, None)


def test_screen_names_the_unified_opt_in(segwit):
    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    shown, reason = sighash().screen_sighash_type(segwit.psbt, segwit.wallet.key)
    assert (shown, reason) == (UNIFIED_ALL, None)


def test_screen_names_all_when_the_psbt_declares_default(segwit):
    """A screen naming a type no signature carries is worse than saying nothing"""
    segwit.psbt.inputs[0].sighash_type = 0x00
    shown, reason = sighash().screen_sighash_type(segwit.psbt, segwit.wallet.key)
    assert reason is None
    assert shown == 0x01


def test_effective_sighash_type_mirrors_sign_with(segwit):
    """The two differ for the commonest PSBTs, and the screen shows the former"""
    segwit.psbt.inputs[0].sighash_type = 0x00
    assert sighash().effective_sighash_type(segwit.psbt.inputs[0], 0x00) == 0x01


@pytest.mark.parametrize(
    "declared",
    [
        0x02,  # SIGHASH_NONE: commits to no outputs
        0x03,  # SIGHASH_SINGLE: a constant on a legacy input
        0x81,  # SIGHASH_ALL | ANYONECANPAY: the other inputs uncommitted
        0x83,  # SIGHASH_SINGLE | ANYONECANPAY
    ],
)
def test_screen_refuses_types_that_would_not_commit(segwit, declared):
    """None of these are shown to the user, so none may be signed quietly"""
    segwit.psbt.inputs[0].sighash_type = declared
    result = sighash().screen_sighash_type(segwit.psbt, segwit.wallet.key)
    assert result == (None, sighash().REFUSED_PARTIAL)


def test_screen_refuses_a_bare_opt_in_on_taproot(taproot):
    """The bit cannot ride on DEFAULT, so 0x20 alone is not something to sign.
    Partial rather than mixed because that is what would happen: embit skips the
    input rather than upgrading it to 0x21."""
    taproot.psbt.inputs[0].sighash_type = 0x20
    result = sighash().screen_sighash_type(taproot.psbt, taproot.wallet.key)
    assert result == (None, sighash().REFUSED_PARTIAL)


def test_refusal_leaves_nothing_signed(segwit):
    from krux.sighash import PSBTRefusedError

    segwit.psbt.inputs[0].sighash_type = 0x02
    with pytest.raises(PSBTRefusedError):
        segwit.sign()
    assert not segwit.psbt.inputs[0].partial_sigs


def test_signing_carries_the_unified_byte(segwit):
    """The opt-in reaches the signature, which is the whole point of it"""
    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    segwit.sign()
    sig = list(segwit.psbt.inputs[0].partial_sigs.values())[0]
    assert sig[-1] == UNIFIED_ALL


def test_signing_uses_the_standard_byte_by_default(segwit):
    segwit.sign()
    sig = list(segwit.psbt.inputs[0].partial_sigs.values())[0]
    assert sig[-1] == 0x01


def test_taproot_signature_stays_64_bytes(taproot):
    """SIGHASH_DEFAULT appends nothing, so there is no byte for the bit to live in"""
    taproot.sign()
    assert len(taproot.psbt.inputs[0].taproot_key_sig) == 64


def test_the_claim_on_the_screen_is_what_is_signed(segwit):
    """Read back off the signatures, not predicted: this is the screen's promise"""
    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    shown, _ = sighash().screen_sighash_type(segwit.psbt, segwit.wallet.key)
    segwit.sign()
    produced = {ht for ht, _ in sighash().signed_hash_types(segwit.psbt).values()}
    assert produced == {shown}


def test_signed_hash_types_sees_every_slot(segwit):
    segwit.sign()
    found = sighash().signed_hash_types(segwit.psbt)
    assert len(found) == 1
    _where, (hash_type, raw) = list(found.items())[0]
    assert hash_type == 0x01
    assert raw[-1] == hash_type


def test_a_planted_signature_does_not_pass_as_ours(segwit):
    """A host can pre-fill the slot this device is about to write to, so the
    check has to compare bytes rather than which slots are occupied."""
    before = sighash().signed_hash_types(segwit.psbt)
    segwit.sign()
    after = sighash().signed_hash_types(segwit.psbt)
    added = {
        where: ht
        for where, (ht, raw) in after.items()
        if before.get(where, (None, None))[1] != raw
    }
    assert len(added) == 1
    assert list(added.values()) == [0x01]


def test_trim_carries_the_declared_type_to_a_co_signer(segwit):
    """The next signer has to be told the opt-in was asked for"""
    from krux.psbt import PSBTSigner

    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    segwit.sign()
    assert segwit.psbt.inputs[0].sighash_type == UNIFIED_ALL
    assert segwit.psbt.serialize() == PSBTSigner.trim(segwit.psbt).serialize()


def test_trim_carries_the_type_the_signature_uses(taproot):
    """embit records the effective type, and a co-signer needs to see it"""
    taproot.psbt.inputs[0].sighash_type = 0x00
    taproot.sign()
    assert taproot.psbt.inputs[0].sighash_type == 0x00


def test_a_failing_sign_leaves_nothing_behind(segwit, mocker):
    """A raise partway through must not leave a half-signed object behind"""
    from krux.sighash import PSBTSignError

    partial = dict(segwit.psbt.inputs[0].partial_sigs)

    from embit import ec

    def boom(root, sighash=None, fingerprint=None):  # pylint: disable=W0613
        # a signature written before the failure: it must not survive
        segwit.psbt.inputs[0].partial_sigs[
            ec.PublicKey(b"\x02" + b"\x11" * 32 + b"\x00" * 31)
        ] = (b"\x30" * 71)
        raise ValueError("crafted")

    mocker.patch.object(segwit.psbt, "sign_with", boom)
    with pytest.raises(PSBTSignError, match="crafted"):
        segwit.sign()
    assert dict(segwit.psbt.inputs[0].partial_sigs) == partial


def test_a_wrong_hash_type_is_refused_rather_than_emitted(segwit, mocker):
    """Nothing reaches the QR unless every signature carries the byte shown"""
    from krux.sighash import PSBTSignError

    from embit import ec

    def wrong(root, sighash=None, fingerprint=None):  # pylint: disable=W0613
        # the standard byte, where the screen promised the opt-in
        segwit.psbt.inputs[0].partial_sigs[
            ec.PublicKey(b"\x02" + b"\x11" * 32 + b"\x00" * 31)
        ] = b"\x30" * 70 + bytes([0x01])
        return 1

    # the screen promises the opt-in; the signer produces the standard byte
    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    mocker.patch.object(segwit.psbt, "sign_with", wrong)
    with pytest.raises(PSBTSignError, match="do not match"):
        segwit.sign()


def test_zero_signatures_is_a_failure_not_a_success(segwit, mocker):
    """A sign that added nothing is reported, never passed off as signed"""
    from krux.sighash import PSBTSignError

    mocker.patch.object(segwit.psbt, "sign_with", mocker.MagicMock(return_value=0))
    with pytest.raises(PSBTSignError, match="cannot sign"):
        segwit.sign()


def test_unsignable_inputs_scopes_to_this_wallet(psbt_tdata):
    """Another cosigner's type must not refuse a PSBT this device can sign"""
    s = sighash()
    w = multisig()
    sgn = signer(w, psbt_tdata.P2WSH_PSBT)
    derivations = [
        der for inp in sgn.psbt.inputs for der in inp.bip32_derivations.values()
    ]
    assert derivations
    for der in derivations:
        der.fingerprint = b"\xde\xad\xbe\xef"
    # every derivation now belongs to somebody else
    assert s.unsignable_inputs(sgn.psbt, w.key) == []


def test_unsignable_inputs_names_the_input(psbt_tdata):
    s = sighash()
    w = multisig()
    sgn = signer(w, psbt_tdata.P2WSH_PSBT)
    assert len(sgn.psbt.inputs) == 2
    sgn.psbt.inputs[1].sighash_type = 0x02  # SIGHASH_NONE
    assert s.unsignable_inputs(sgn.psbt, w.key) == [1]


def test_a_missing_fingerprint_still_finds_our_inputs(psbt_tdata):
    """A coordinator given only an xpub omits the fingerprint entirely. An exact
    comparison alone would refuse a transaction this wallet can sign."""
    s = sighash()
    w = singlesig()
    sgn = signer(w, psbt_tdata.P2WPKH_PSBT)
    assert s.screen_sighash_type(sgn.psbt, w.key) == (0x01, None)

    for inp in sgn.psbt.inputs:
        for der in inp.bip32_derivations.values():
            der.fingerprint = ZERO_FINGERPRINT
    assert s.screen_sighash_type(sgn.psbt, w.key) == (0x01, None)


def test_another_wallets_input_is_not_ours(psbt_tdata):
    """A derivation that derives to a different key is not ours, zero or not"""
    s = sighash()
    w = singlesig()
    sgn = signer(w, psbt_tdata.P2WPKH_PSBT)
    for inp in sgn.psbt.inputs:
        for der in inp.bip32_derivations.values():
            der.derivation = [0, 0, 0, 0, 0]
            der.fingerprint = ZERO_FINGERPRINT
    assert not any(s.input_is_ours(w.key, i) for i in sgn.psbt.inputs)


def test_default_and_all_are_the_same_request():
    """DEFAULT cannot carry the opt-in bit, so an opted-in type names ALL"""
    from embit.psbt import sighash_types_agree

    assert sighash_types_agree(UNIFIED_ALL, 0x01)
    assert not sighash_types_agree(UNIFIED_ALL, 0x02)
    assert not sighash_types_agree(0x02, 0x01)


def test_the_label_names_the_algorithm_not_the_bit():
    s = sighash()
    assert s.sighash_label(UNIFIED_ALL) == "Unified 0x21"
    assert s.sighash_label(0x01) == "Standard 0x01"
    assert s.sighash_label(0x00) == "Standard 0x00"


def test_the_label_reaches_the_review_screen(segwit):
    """The user is told, on the screen where they read the amounts"""
    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    messages, _ = segwit.outputs()
    assert messages[0].endswith("\n\nUnified 0x21")


def test_a_host_rewriting_the_opt_in_down_is_visible(segwit):
    """Rewriting 0x21 to 0x01 must not make the line disappear"""
    messages, _ = segwit.outputs()
    assert messages[0].endswith("\n\nStandard 0x01")

    segwit.psbt.inputs[0].sighash_type = UNIFIED_ALL
    messages, _ = segwit.outputs()
    assert messages[0].endswith("\n\nUnified 0x21")
