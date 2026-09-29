"""The PSBT signing flow, as the user meets it, when the hash type is the point.

Drives home.sign_psbt() end to end the way a user does: scan, review, sign.
Asserts the review screen names the message that is about to be produced and
that the signature handed to the QR carries the byte it named.
"""

import pytest

from .. import create_ctx
from ...test_psbt import tdata as psbt_tdata  # noqa: F401  re-exported fixture
from .test_home import tdata as home_tdata  # noqa: F401  re-exported fixture

UNIFIED_ALL = 0x21  # SIGHASH.ALL | SIGHASH.UNIFIED
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02


def scanned_psbt_declaring(encoded, declared):
    """The scanned PSBT, re-encoded, with every input declaring `declared`.

    Built rather than pasted as a blob so the test states what the coordinator
    asked for, and so the value cannot drift away from what it asserts.
    """
    from embit.psbt import PSBT
    from krux.baseconv import base_decode, base_encode

    psbt = PSBT.parse(base_decode(encoded, 64))
    for inp in psbt.inputs:
        inp.sighash_type = declared
    return base_encode(psbt.serialize(), 64)


def hash_types_emitted(captured):
    """The hash type byte on every signature the device handed to the QR"""
    from embit.psbt import PSBT
    from krux.baseconv import base_decode

    if isinstance(captured, str):
        captured = base_decode(captured, 64)
    found = set()
    for inp in PSBT.parse(captured).inputs:
        for sig in inp.partial_sigs.values():
            found.add(sig[-1] if len(sig) != 64 else 0x00)
        if inp.taproot_key_sig is not None:
            found.add(
                inp.taproot_key_sig[-1] if len(inp.taproot_key_sig) != 64 else 0x00
            )
    return found


class Flow:
    """One run of home.sign_psbt(), recording what reached the screen and the QR"""

    def __init__(self, mocker, btn_seq, wallet, scanned, sign=True):
        from krux.pages.home_pages.home import Home
        from krux.pages.qr_capture import QRCodeCapture
        from krux.qr import FORMAT_NONE

        self.ctx = create_ctx(mocker, btn_seq, wallet)
        self.home = Home(self.ctx)
        self.texts = []
        self.captured = None

        mocker.patch.object(
            QRCodeCapture,
            "qr_capture_loop",
            new=lambda self: (scanned, FORMAT_NONE),
        )

        # record every line the device draws, and draw it for real
        draw = self.ctx.display.draw_centered_text
        mocker.patch.object(
            self.ctx.display,
            "draw_centered_text",
            new=lambda text, *a, **kw: (self.texts.append(text), draw(text, *a, **kw))[
                -1
            ],
        )
        if sign:
            mocker.patch.object(
                self.home,
                "display_qr_codes",
                new=self._capture_qr,
            )
        else:
            mocker.patch.object(
                self.home,
                "display_qr_codes",
                new=mocker.MagicMock(side_effect=AssertionError("QR displayed")),
            )

    def _capture_qr(self, data, qr_format, title=None):  # pylint: disable=W0613
        self.captured = data
        return self.ctx.input.wait_for_button()

    @property
    def summary(self):
        """The review summary: the screen where the amounts and the hash type are"""
        for text in self.texts:
            if "Inputs (" in text:
                return text
        return ""

    def said(self, fragment):
        return any(fragment in text for text in self.texts)


@pytest.fixture
def signing_wallet(home_tdata):
    """The wallet the PSBT fixtures were built for"""
    from krux.wallet import Wallet

    return Wallet(home_tdata.SINGLESIG_SIGNING_KEY)


def sign_buttons():
    """One pass through scan, review, sign, display, done"""
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    return [
        BUTTON_ENTER,  # Load from QR code
        BUTTON_ENTER,  # Path mismatch ACK
        BUTTON_ENTER,  # PSBT resume
        BUTTON_ENTER,  # output 1
        BUTTON_ENTER,  # output 2
        BUTTON_PAGE,  # move to Sign to QR
        BUTTON_ENTER,  # Sign to QR code
        BUTTON_ENTER,  # Dismiss QR
        BUTTON_ENTER,  # Done?
    ]


def test_unified_opt_in_is_named_on_screen_and_carried(
    mocker, m5stickv, signing_wallet, psbt_tdata
):
    """The screen's claim, carried through to the signature that leaves"""
    flow = Flow(
        mocker,
        sign_buttons(),
        signing_wallet,
        scanned_psbt_declaring(psbt_tdata.P2WPKH_PSBT_B64, UNIFIED_ALL),
    )
    flow.home.sign_psbt()

    # named on the summary, where the amounts it commits to are read
    assert "Unified 0x21" in flow.summary
    # and the signature that left carries the byte it named
    assert hash_types_emitted(flow.captured) == {UNIFIED_ALL}


def test_a_host_rewriting_the_opt_in_down_is_still_named(
    mocker, m5stickv, signing_wallet, psbt_tdata
):
    """A standard request is named as standard, not left unlabelled"""
    flow = Flow(
        mocker,
        sign_buttons(),
        signing_wallet,
        scanned_psbt_declaring(psbt_tdata.P2WPKH_PSBT_B64, SIGHASH_ALL),
    )
    flow.home.sign_psbt()

    assert "Standard 0x01" in flow.summary
    assert hash_types_emitted(flow.captured) == {SIGHASH_ALL}


# The PSBT fixtures, each with the wallet that goes with it. The summary is at
# the screen height on the narrowest device, so every one of these is checked
# rather than a representative few.
SUMMARY_FIXTURES = [
    ("P2PKH_PSBT", "TYPE_SINGLESIG", "P2PKH"),
    ("P2WPKH_PSBT", "TYPE_SINGLESIG", "P2WPKH"),
    ("P2SH_P2WPKH_PSBT", "TYPE_SINGLESIG", "P2SH_P2WPKH"),
    ("P2TR_PSBT", "TYPE_SINGLESIG", "P2TR"),
    ("P2SH_PSBT", "TYPE_MULTISIG", "P2SH"),
    ("P2WSH_PSBT", "TYPE_MULTISIG", "P2WSH"),
    ("P2SH_P2WSH_PSBT", "TYPE_MULTISIG", "P2SH_P2WSH"),
    ("MINIS_P2WSH_PSBT", "TYPE_MINISCRIPT", "P2WSH"),
]


def summary_for(psbt_tdata, fixture):
    """The review summary the device would draw for one fixture"""
    from embit.networks import NETWORKS
    from krux import key
    from krux.key import Key
    from krux.psbt import PSBTSigner
    from krux.qr import FORMAT_NONE
    from krux.wallet import Wallet

    _name, policy, script_type = fixture
    wallet = Wallet(
        Key(
            psbt_tdata.TEST_MNEMONIC,
            getattr(key, policy),
            NETWORKS["test"],
            "",
            0,
            getattr(key, script_type),
        )
    )
    signer = PSBTSigner(wallet, getattr(psbt_tdata, _name), FORMAT_NONE)
    for inp in signer.psbt.inputs:
        inp.sighash_type = UNIFIED_ALL
    return signer.outputs()[0][0]


def test_the_sighash_line_survives_every_display(mocker, multiple_devices, psbt_tdata):
    """a line of margin is demanded, not merely fitting: at the limit one more
    digit in an amount is enough to drop the line silently"""
    import board
    from krux.display import TOTAL_LINES, Display

    lcd = board.config["lcd"]
    mocker.patch(
        "krux.display.lcd",
        new=mocker.MagicMock(
            width=mocker.MagicMock(return_value=lcd["width"]),
            height=mocker.MagicMock(return_value=lcd["height"]),
        ),
    )
    display = Display()

    for fixture in SUMMARY_FIXTURES:
        summary = summary_for(psbt_tdata, fixture)
        needed = len(display.to_lines(summary, max_lines=TOTAL_LINES * 4))
        assert needed < TOTAL_LINES, (fixture, needed, TOTAL_LINES)
        lines = display.to_lines(summary)
        assert any("Unified 0x21" in line for line in lines), (fixture, lines)


def test_a_non_standard_request_is_refused_before_review(
    mocker, m5stickv, signing_wallet, psbt_tdata
):
    """nothing signed, and the review never shown"""
    from krux.input import BUTTON_ENTER

    flow = Flow(
        mocker,
        [
            BUTTON_ENTER,  # Load from QR code
            BUTTON_ENTER,  # Path mismatch ACK
            BUTTON_ENTER,  # "Cannot sign" warning
        ],
        signing_wallet,
        scanned_psbt_declaring(psbt_tdata.P2WPKH_PSBT_B64, SIGHASH_NONE),
        sign=False,
    )
    flow.home.sign_psbt()

    assert flow.said("Cannot sign")
    # the user is told which situation this is, not merely that it failed
    assert flow.said("only sign part of it")
    # and never sees the transaction review, which would read as an ordinary send
    assert "Inputs (" not in flow.summary
    flow.home.display_qr_codes.assert_not_called()


def test_a_wrong_key_reports_a_failed_signature(
    mocker, m5stickv, home_tdata, psbt_tdata
):
    """a failure after approval is a screen, not a traceback"""
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.pages import MENU_CONTINUE
    from krux.wallet import Wallet

    flow = Flow(
        mocker,
        [
            BUTTON_ENTER,  # Load from QR code
            BUTTON_ENTER,  # PSBT resume
            BUTTON_ENTER,  # output 1
            BUTTON_ENTER,  # output 2
            BUTTON_PAGE,  # move to Sign to QR
            BUTTON_ENTER,  # Sign to QR code
            BUTTON_ENTER,  # "Cannot sign"
        ],
        # a wallet that is not the one the PSBT was built for
        Wallet(home_tdata.SINGLESIG_12_WORD_KEY),
        scanned_psbt_declaring(psbt_tdata.P2WPKH_PSBT_B64, UNIFIED_ALL),
        sign=False,
    )
    assert flow.home.sign_psbt() == MENU_CONTINUE
    assert flow.said("could not be signed")
    flow.home.display_qr_codes.assert_not_called()
