"""
The MIT License (MIT)

Copyright (c) 2021-2026 Krux contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Save a seed to a SeedKeeper smartcard, and load one back out of it.

The card keeps secrets at rest; the seed is still derived and signed here.
This screen is reached from the Login menu, so a card-seeded wallet goes
through the same confirmation, editor and passphrase steps as a typed one --
the card is a different way of getting words onto the screen, not a way
around what the screen does with them.

Scope is deliberately the one flow the SeedKeeper quick start describes: put a
BIP-39 seed on a card, take it off again, and look at what else is there.
Descriptors, standalone passphrases, cloning and card maintenance are not
here.

Ported from the SeedSigner fork by 3rdIteration:
https://github.com/3rdIteration/seedsigner
"""

from . import (
    Page,
    Menu,
    MENU_CONTINUE,
    ESC_KEY,
    DIGITS,
    LETTERS,
    UPPERCASE_LETTERS,
)
from ..krux_settings import t
from ..display import FLASH_MSG_TIME
from .. import seedkeeper as sk

# Keysets for the card PIN and for a secret's label. The official Satochip
# apps use digits, but the applet accepts any 4-16 characters, so letters are
# one swipe away rather than forbidden.
PIN_KEYSETS = [DIGITS, LETTERS, UPPERCASE_LETTERS]
LABEL_KEYSETS = [LETTERS, UPPERCASE_LETTERS, DIGITS]


class SeedKeeperPage(Page):
    """Save a seed to, or load one from, a SeedKeeper smartcard.

    The menu depends on what is loaded, because the two directions are only
    available at different times: a card can only be read into a wallet before
    one exists, and a card can only be written from one. Login opens it to
    read, Backup Mnemonic opens it to write.

    ``load_key_fn`` is Login._load_key_from_words, passed in rather than
    imported so the page owns no knowledge of how a wallet gets built, and so
    words from a card meet exactly the same code path a typed mnemonic does.
    """

    def __init__(self, ctx, load_key_fn=None):
        self.load_key_fn = load_key_fn
        wallet_loaded = ctx.wallet is not None
        items = []
        if not wallet_loaded:
            items.append((t("Load Seed from Card"), self.load_seed))
        else:
            items.append((t("Save Seed to Card"), self.save_seed))
        items += [
            (t("View Secrets on Card"), self.view_secrets),
            (t("Delete Secret from Card"), self.delete_secret),
            (t("View Free Space"), self.free_space),
            (t("Card Info"), self.card_info),
        ]
        super().__init__(ctx, Menu(ctx, items))

    # ------------------------------------------------------------ connecting

    def _transport(self):
        """This build's card transport, or None after saying why there isn't one."""
        transport = sk.get_transport()
        if transport is None:
            self.flash_error(t("No card reader"))
            return None
        return transport

    def _prompt_pin(self, title, confirm_title=None):
        """Ask for a card PIN, optionally twice. None if the user backs out.

        The card's rule is 4 to 16 characters and it allows a few wrong tries
        before blocking itself, so an out-of-range PIN is caught here rather
        than spending one of the card's attempts.
        """
        while True:
            pin = self.capture_from_keypad(title, PIN_KEYSETS, esc_prompt=True)
            if pin == ESC_KEY:
                return None
            if sk.PIN_MIN_SIZE <= len(pin) <= sk.PIN_MAX_SIZE:
                if confirm_title is None:
                    return pin
                confirmed = self.capture_from_keypad(
                    confirm_title, PIN_KEYSETS, esc_prompt=True
                )
                if confirmed == ESC_KEY:
                    return None
                if confirmed == pin:
                    return pin
                self.flash_error(t("PINs did not match"))
                continue
            self.flash_error(
                t("PIN must be %d to %d characters")
                % (sk.PIN_MIN_SIZE, sk.PIN_MAX_SIZE)
            )

    def _connect(self):
        """Reach the card and get past its PIN. None if the user backs out.

        A card with no PIN set yet is set up here, since that is the only
        moment the applet allows a PIN to be chosen.
        """
        transport = self._transport()
        if transport is None:
            return None
        # The first command is what makes the reader start looking, and it
        # blocks until the card is tapped or the wait times out. Without a
        # line on screen saying so, that reads as a frozen app.
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Tap your SeedKeeper card"))
        try:
            card = sk.SeedKeeper(transport)
            card.select()
        except sk.SeedKeeperError as exc:
            self.flash_error(
                t("No SeedKeeper applet\nInstall it first.")
                if exc.sw == sk.SW_APPLET_NOT_FOUND
                else "%s\n%s" % (t("Card error"), exc)
            )
            return None
        try:
            status = card.card_status()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return None
        if status["setup_done"]:
            pin = self._prompt_pin(t("Card PIN"))
            if pin is None:
                return None
            try:
                card.verify_pin(pin)
            except sk.SeedKeeperError as exc:
                self.flash_error("%s\n%s" % (t("Card error"), exc))
                return None
            return card
        pin = self._prompt_pin(t("New Card PIN"), t("Confirm Card PIN"))
        if pin is None:
            return None
        try:
            card.setup(pin)
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return None
        self.flash_success(t("Card PIN set"))
        return card

    # ---------------------------------------------------------------- secrets

    def _seed_secrets(self, card):
        """The card's secrets that hold a BIP-39 mnemonic.

        Two formats, because cards do not agree on one: a v2 applet stores a
        Masterseed secret whose subtype says a BIP-39 mnemonic rides along
        with it, and a v1 applet stores the mnemonic on its own under its own
        secret type.

        The subtype is the only discriminator used for the v2 form, and that
        is deliberate. A secret's type byte is assigned by the applet on
        import -- the client never sends it -- so its value is the applet's
        business and not something to match on. The subtype, by contrast, is
        a byte the client does send and the card echoes back unchanged.
        """
        seeds = []
        try:
            headers = card.list_secrets()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return None
        for header in headers:
            if header["subtype"] == sk.SUBTYPE_BIP39:
                seeds.append(header)
            elif header["type"] == sk.TYPE_BIP39_MNEMONIC:
                seeds.append(header)
        return seeds

    def _secret_label(self, header):
        """A one-line name for a secret, for a menu entry or an error."""
        if header["label"]:
            return header["label"]
        # No label means something else wrote it; the id and fingerprint are
        # still enough to tell two of them apart on screen.
        return "%d %s" % (header["id"], header["fingerprint"][:8])

    def _select_secret(self, headers):
        """Pick one secret from a list. The header, or None if cancelled."""
        if not headers:
            self.flash_error(t("No seeds on card"))
            return None
        if len(headers) == 1:
            return headers[0]
        menu = Menu(
            self.ctx,
            [(self._secret_label(h), lambda h=h: h) for h in headers],
        )
        index, _ = menu.run_loop()
        if index == menu.back_index:
            return None
        return headers[index]

    def _decode_secret(self, card, header):
        """Read a seed secret -> (mnemonic, stored passphrase), or None.

        The card hands back a seed, a wordlist, the entropy and the
        passphrase. The seed is checked against the entropy and passphrase
        rather than used: a wallet should be derived from the words the user
        can see and verify, not from a value the card supplied.

        Both on-card formats start with a length byte, so which one this is
        cannot be told from the header. It is decided by decoding: the v2
        format ends in a master seed that must re-derive from the words
        beside it, and a v1 payload has no seed to check, so the two do not
        overlap.
        """
        from embit.bip39 import mnemonic_to_seed

        try:
            _, secret = card.export_secret(header["id"])
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return None
        decoded = _decode_as_bip39(secret)
        if decoded is None:
            try:
                return _unpack_v1_secret(secret)
            except (sk.SeedKeeperError, UnicodeDecodeError):
                pass
            self.flash_error(t("Stored data is not a valid BIP-39 mnemonic"))
            return None
        _, passphrase, mnemonic = decoded
        try:
            # Re-derive and compare all of it. A card whose stored seed does
            # not match its own words has been tampered with or half-written,
            # and loading it would silently produce a different wallet than
            # the words on screen promise.
            if list(mnemonic_to_seed(mnemonic, passphrase)) != list(
                secret[1 : 1 + secret[0]]
            ):
                raise ValueError
        except ValueError:
            self.flash_error(t("Card secret does not match its seed"))
            return None
        return mnemonic, passphrase

    # ------------------------------------------------------------ menu items

    def load_seed(self):
        """Handler for the 'Load Seed from Card' menu item"""
        if self.load_key_fn is None:
            self.flash_error(t("Wallet is already loaded"))
            return MENU_CONTINUE
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        seeds = self._seed_secrets(card)
        if seeds is None:
            return MENU_CONTINUE
        header = self._select_secret(seeds)
        if header is None:
            return MENU_CONTINUE
        decoded = self._decode_secret(card, header)
        if decoded is None:
            return MENU_CONTINUE
        mnemonic, passphrase = decoded
        if passphrase:
            # The card stores the BIP-39 passphrase so a later load restores
            # the same wallet. The load path asks for it separately, so say so
            # rather than leaving the user to notice a missing passphrase.
            self.flash_error(t("Card holds a passphrase.\nSet it after loading."))
        return self.load_key_fn(mnemonic.split())

    def save_seed(self):
        """Handler for the 'Save Seed to Card' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        key = self.ctx.wallet.key
        label = self._prompt_label(key)
        if label is None:
            return MENU_CONTINUE
        try:
            secret_id, _ = self._write_seed(card, key, label)
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        self.flash_success(t("Secret %d saved") % secret_id)
        return MENU_CONTINUE

    def view_secrets(self):
        """Handler for the 'View Secrets on Card' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        try:
            headers = card.list_secrets()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        if not headers:
            self.flash_error(t("No secrets on card"))
            return MENU_CONTINUE
        for header in headers:
            self.flash_text(
                "%s\n%s" % (self._secret_label(header), _type_name(header["type"]))
            )
        return MENU_CONTINUE

    def delete_secret(self):
        """Handler for the 'Delete Secret from Card' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        try:
            headers = card.list_secrets()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        header = self._select_secret(headers)
        if header is None:
            return MENU_CONTINUE
        if not self.prompt(
            t("Delete %s?") % self._secret_label(header),
            self.ctx.display.height() // 2,
        ):
            return MENU_CONTINUE
        try:
            deleted = card.delete_secret(header["id"])
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        self.flash_success(t("Secret deleted") if deleted else t("Secret not found"))
        return MENU_CONTINUE

    def free_space(self):
        """Handler for the 'View Free Space' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        try:
            status = card.memory_status()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        self.flash_text(
            "%s\n%s\n%s\n%d %s"
            % (
                t("Free Space"),
                t("%s bytes") % status["free_memory"],
                t("%s bytes") % status["total_memory"],
                status["nb_secrets"],
                t("secrets"),
            ),
            duration=FLASH_MSG_TIME * 3,
        )
        return MENU_CONTINUE

    def card_info(self):
        """Handler for the 'Card Info' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        try:
            status = card.card_status()
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        self.flash_text(
            "%s\n%s %d.%d\n%s %d.%d"
            % (
                t("Card Info"),
                t("Protocol"),
                status["protocol_major_version"],
                status["protocol_minor_version"],
                t("Applet"),
                status["applet_major_version"],
                status["applet_minor_version"],
            ),
            duration=FLASH_MSG_TIME * 3,
        )
        return MENU_CONTINUE

    # ------------------------------------------------------------- internals

    def _prompt_label(self, key):
        """Ask what to call this seed. None if the user backs out.

        Defaults to the wallet's fingerprint, which is what SeedSigner does and
        is the one label that can be recognised without the card.
        """
        default = key.fingerprint_hex_str(False)
        while True:
            label = self.capture_from_keypad(
                t("Seed Label"),
                LABEL_KEYSETS,
                starting_buffer=default,
                esc_prompt=True,
            )
            if label == ESC_KEY:
                return None
            label = label.strip()
            if label:
                if len(label.encode("utf-8")) > sk.MAX_LABEL_SIZE:
                    self.flash_error(t("Label too long (max %d)") % sk.MAX_LABEL_SIZE)
                    continue
                return label
            self.flash_error(t("Label cannot be empty"))

    def _write_seed(self, card, key, label):
        """Import the wallet's seed onto the card. Returns (id, fingerprint).

        The card is asked how much room it has first. Writing into a full card
        fails partway with 0x9C01 and leaves the user to work out what to
        delete; checking first turns that into a refusal with a number in it.
        """
        from embit.bip39 import mnemonic_to_bytes, mnemonic_to_seed

        entropy = mnemonic_to_bytes(key.mnemonic)
        secret = sk.pack_bip39_secret(
            mnemonic_to_seed(key.mnemonic, key.passphrase), entropy, key.passphrase
        )
        header = sk.make_header(sk.TYPE_MASTERSEED, label, subtype=sk.SUBTYPE_BIP39)
        needed = len(header) + sk.padded_size(secret)
        try:
            free = card.memory_status()["free_memory"]
        except sk.SeedKeeperError:
            # An applet that does not implement the status instruction cannot
            # report its room; let the card be the judge instead of refusing
            # every write.
            free = None
        if free is not None and needed > free:
            raise sk.SeedKeeperError(
                "%s\n%s, %s"
                % (
                    t("Not enough space"),
                    t("%s bytes") % needed,
                    t("%s bytes") % free,
                )
            )
        del entropy
        return card.import_secret(header, secret)


def _decode_as_bip39(secret):
    """Decode a v2 BIP-39 secret -> (entropy, passphrase, mnemonic), or None.

    None means "this is not in that format", not "this is corrupt": the
    caller falls through to the v1 format, which is a legitimate thing for
    the same card to hold.
    """
    from embit.bip39 import mnemonic_from_bytes

    try:
        entropy, passphrase = sk.unpack_bip39_secret(secret)
    except sk.SeedKeeperError:
        return None
    if len(entropy) not in (16, 32):
        return None
    try:
        return entropy, passphrase, mnemonic_from_bytes(entropy)
    except ValueError:
        return None


def _unpack_v1_secret(secret):
    """Read a v1 SeedKeeper BIP-39 secret -> (mnemonic, passphrase).

    A v1 applet stores the mnemonic and passphrase as length-prefixed text,
    with no master seed and no entropy: the words are all there is.
    """
    secret = list(secret)
    if not secret:
        raise sk.SeedKeeperError("Secret is empty")
    mnemonic_len = secret[0]
    if len(secret) < 1 + mnemonic_len + 1:
        raise sk.SeedKeeperError("Secret is truncated")
    mnemonic = bytes(secret[1 : 1 + mnemonic_len]).decode("utf-8")
    offset = 1 + mnemonic_len
    passphrase_len = secret[offset]
    passphrase = bytes(secret[offset + 1 : offset + 1 + passphrase_len]).decode("utf-8")
    return mnemonic, passphrase


def _type_name(secret_type):
    """A secret type byte as something readable on a 128px screen.

    Left untranslated on purpose: these are the card's own type names, the
    same words the Satochip apps show, and SeedSigner matches on them.
    """
    return {
        sk.TYPE_MASTERSEED: "Master Seed",
        sk.TYPE_BIP39_MNEMONIC: "Mnemonic",
        sk.TYPE_PASSWORD: "Password",
        sk.TYPE_DATA: "Data",
        sk.TYPE_DESCRIPTOR: "Descriptor",
    }.get(secret_type, "Unknown")
