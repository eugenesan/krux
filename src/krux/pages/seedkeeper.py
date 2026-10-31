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

import time

from . import (
    Page,
    Menu,
    MENU_CONTINUE,
    MENU_EXIT,
    ESC_KEY,
    DIGITS,
    LETTERS,
    UPPERCASE_LETTERS,
)
from ..krux_settings import t
from ..display import DEFAULT_PADDING, FONT_HEIGHT
from .. import seedkeeper as sk

# Keysets for the card PIN and for a secret's label. The official Satochip
# apps use digits, but the applet accepts any 4-16 characters, so letters are
# one swipe away rather than forbidden.
PIN_KEYSETS = [DIGITS, LETTERS, UPPERCASE_LETTERS]
LABEL_KEYSETS = [LETTERS, UPPERCASE_LETTERS, DIGITS]

# The Nexus 5's NFC antenna is in the back cover and its coupling is weak.
# A card session is therefore allowed to retry for a long time, with a
# bounded wait per activation so the user can cancel between attempts.
CARD_ATTEMPT_TIMEOUT_MS = 8000
CARD_SESSION_ATTEMPTS = 20
CARD_ACTION_RETRIES = 3
CARD_RETRY_PAUSE_S = 0.1


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

    def _reader_prompt(self, transport, attempt=1):
        """Start the reader and show where to hold the card.

        The RF field is started *before* the prompt: this chip only notices a
        card that enters an already-running field.  The Nexus 5 antenna is in
        the back cover around the camera, so the prompt names that spot; the
        coupling is weak enough that placement is part of the procedure.
        """
        prepare = getattr(transport, "prepare", None)
        if prepare is not None:
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(t("Starting card reader"))
            try:
                prepare()
            except Exception as exc:  # transport-specific error
                close = getattr(transport, "close", None)
                if close is not None:
                    close()
                self.flash_error("%s\n%s" % (t("Card error"), exc))
                return False
            self.ctx.display.clear()
        if attempt <= 1:
            text = t(
                "Tap your SeedKeeper card\nflat on the back,\nover the camera.\nHold it still."
            )
        else:
            text = t("Keep card in place.\nRetrying %d.\nTap to cancel.") % attempt
        self.ctx.display.draw_centered_text(text)
        return True

    def _cancel_requested(self):
        """Whether the user tapped the screen since the last check."""
        try:
            btn = self.ctx.input.wait_for_button(
                block=False, wait_duration=50
            )
        except Exception:  # input is optional on some boards
            return False
        # Only a real button value cancels.  This also keeps a mocked input
        # in the host tests from looking like a permanent key press.
        return isinstance(btn, int) and btn in (0, 1, 2, 3)

    def _retry_screen(self, attempt):
        """Tell the user the link was not made and that the card must stay."""
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            t("Card not read.\nKeep it flat.\nTap to cancel.\nRetry %d") % attempt
        )

    def _card_session(self, transport):
        """Select the applet and read its status, retrying until cancelled.

        The card's coupling is marginal, so a single failed activation is
        normal.  Only link failures are retried; a real status word (applet
        not found, for example) is final.  Returns ``(card, status)`` or
        ``(None, None)``.
        """
        # Drop whatever key/touch event opened this screen, so it cannot be
        # mistaken for a cancel request on the first failed activation.
        try:
            self.ctx.input.reset_ios_state()
        except Exception:
            pass
        last_error = None
        for attempt in range(1, CARD_SESSION_ATTEMPTS + 1):
            if not self._reader_prompt(transport, attempt):
                last_error = t("Card reader did not start")
            else:
                try:
                    # The phone transport has an explicit connect step; a
                    # mock/card transport may simply answer transmit().
                    connect = getattr(transport, "connect", None)
                    if connect is not None:
                        connect(CARD_ATTEMPT_TIMEOUT_MS)
                    card = sk.SeedKeeper(transport)
                    card.select()
                    status = card.card_status()
                    return card, status
                except sk.SeedKeeperError as exc:
                    last_error = exc
                    if exc.sw is not None:
                        self.flash_error(
                            t("No SeedKeeper applet\nInstall it first.")
                            if exc.sw == sk.SW_APPLET_NOT_FOUND
                            else "%s\n%s" % (t("Card error"), exc)
                        )
                        return None, None
                except Exception as exc:  # transport/card timeout
                    last_error = exc
            if self._cancel_requested():
                self.flash_text(t("Cancelled"))
                return None, None
            self._retry_screen(attempt)
            time.sleep(CARD_RETRY_PAUSE_S)
        self.flash_error("%s\n%s" % (t("Card error"), last_error or t("No card")))
        return None, None

    def _verify_pin(self, card, pin, transport):
        """Verify the PIN, re-presenting the card if the link was lost."""
        for attempt in range(1, CARD_ACTION_RETRIES + 1):
            try:
                card.verify_pin(pin)
                return card
            except sk.SeedKeeperError as exc:
                if exc.sw is not None:
                    self.flash_error("%s\n%s" % (t("Card error"), exc))
                    return None
            if self._cancel_requested():
                self.flash_text(t("Cancelled"))
                return None
            card, _ = self._card_session(transport)
            if card is None:
                return None
        self.flash_error(t("Card error"))
        return None

    def _connect(self):
        """Ask for the PIN, then present the card once and verify it.

        The PIN is entered before the field is started so the card is only
        needed for one uninterrupted select + secure-channel + verify
        sequence.  Typing it while the card is held is what used to drop the
        link and force a second presentation.

        A blank card is the exception: the first status read is how we learn
        it is blank, so the PIN is confirmed after that read and the card is
        presented once more for setup.  That path only runs once per card.
        """
        transport = self._transport()
        if transport is None:
            return None
        while True:
            pin = self._prompt_pin(t("Card PIN"))
            if pin is None:
                return None
            card, status = self._card_session(transport)
            if card is None:
                return None
            if status["setup_done"]:
                return self._verify_pin(card, pin, transport)

            # A blank card: confirm the PIN on a fresh screen, away from the
            # card, then present it again for the setup write.
            close = getattr(transport, "close", None)
            if close is not None:
                close()
            confirmed = self.capture_from_keypad(
                t("Confirm Card PIN"), PIN_KEYSETS, esc_prompt=True
            )
            if confirmed == ESC_KEY:
                return None
            if confirmed != pin:
                self.flash_error(t("PINs did not match"))
                continue
            card, status = self._card_session(transport)
            if card is None:
                return None
            if status["setup_done"]:
                return self._verify_pin(card, pin, transport)
            try:
                card.setup(pin)
                # setup() installs the PIN but does not validate it.  The
                # commands that follow (list, generate, import) need a
                # validated PIN, so log in once now that it exists.
                card.verify_pin(pin)
            except sk.SeedKeeperError as exc:
                self.flash_error("%s\n%s" % (t("Card error"), exc))
                return None
            self.flash_success(t("Card PIN set"))
            return card

    def _reconnect(self, card):
        """Re-present the card and redo select + secure channel + PIN."""
        for attempt in range(1, CARD_ACTION_RETRIES + 1):
            if not self._reader_prompt(card.transport, attempt):
                return False
            try:
                if card._login_again():
                    return True
            except sk.SeedKeeperError as exc:
                if exc.sw is not None:
                    self.flash_error("%s\n%s" % (t("Card error"), exc))
                    return False
            if self._cancel_requested():
                self.flash_text(t("Cancelled"))
                return False
            self._retry_screen(attempt)
            time.sleep(CARD_RETRY_PAUSE_S)
        return False

    def _card_action(self, card, action):
        """Run a read-only card action, re-presenting the card if needed.

        The link drops after a few seconds without traffic and the first
        secure command after a fresh activation is occasionally lost.  The
        PIN verified by ``_connect`` is retained in the card object, so the
        retry can select, redo the secure channel and re-verify without
        asking the user to type it again.
        """
        last_error = None
        for attempt in range(1, CARD_ACTION_RETRIES + 1):
            try:
                return action()
            except sk.SeedKeeperError as exc:
                last_error = exc
                if exc.sw is not None:
                    raise
            if attempt == CARD_ACTION_RETRIES:
                break
            if not self._reconnect(card):
                raise last_error
        raise last_error

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
            headers = self._card_action(card, card.list_secrets)
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

    def _info_menu(self, text):
        """Show information, then wait for a deliberate dismissal.

        A fixed-duration flash is wrong for information the user may need to
        read twice: a card label, a fingerprint or a byte count.  Drawing the
        text above a one-item menu leaves the screen up until the user taps
        OK (or presses enter on a button-only device).
        """
        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text(text, DEFAULT_PADDING)
        menu = Menu(
            self.ctx,
            [(t("OK"), lambda: MENU_EXIT)],
            back_label=None,
            offset=self.ctx.display.height() - 2 * FONT_HEIGHT,
        )
        menu.run_loop()
        try:
            self.ctx.input.reset_ios_state()
        except Exception:  # input is optional on some boards
            pass

    def _secret_details(self, header):
        """The one-secret screen shown after picking it from View Secrets."""
        kind = _type_name(header["type"])
        if header["subtype"] == sk.SUBTYPE_BIP39:
            kind += " (BIP-39)"
        return "%s\n%s\nID %d\n%s" % (
            self._secret_label(header),
            kind,
            header["id"],
            header["fingerprint"],
        )

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
            _, secret = self._card_action(
                card, lambda: card.export_secret(header["id"])
            )
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

    def create_new_mnemonic(self, len_mnemonic):
        """Generate a new BIP-39 mnemonic with the card's RNG.

        The card generates 16 or 32 random bytes (INS A3, or the deprecated
        INS A0 on an older applet).  Those bytes are the BIP-39 entropy: the
        words are derived here, loaded through the normal new-wallet flow, and
        only then written back to the card in the standard BIP-39 format.

        Writing after the editor, rather than before it, matters: the editor
        can change the words, and a card copy of the pre-edit mnemonic would
        quietly disagree with the wallet the user just confirmed.  The
        temporary on-card entropy secret is removed once the final secret is
        stored.
        """
        if self.load_key_fn is None:
            self.flash_error(t("Wallet is already loaded"))
            return MENU_CONTINUE
        if len_mnemonic not in (12, 24):
            return MENU_CONTINUE

        # Ask for the label before presenting the card, as save_seed() does.
        # Typing while the card is held is what drops the NFC link.
        label = self._prompt_label(default="Krux")
        if label is None:
            return MENU_CONTINUE

        card = self._connect()
        if card is None:
            return MENU_CONTINUE

        temp_id = None
        try:
            temp_id, entropy = self._generate_card_entropy(
                card, 16 if len_mnemonic == 12 else 32
            )
            from embit.bip39 import mnemonic_from_bytes

            words = mnemonic_from_bytes(entropy).split()
            del entropy
        except (sk.SeedKeeperError, ValueError) as exc:
            self._discard_temp(card, temp_id)
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE

        status = self.load_key_fn(words)
        if status != MENU_EXIT or self.ctx.wallet is None:
            # Backing out of the editor leaves no wallet to store.
            self._discard_temp(card, temp_id)
            return status

        # The editor may have changed the words or added a passphrase.  Store
        # the wallet that was actually created, not the pre-edit suggestion.
        if not self._reconnect(card):
            self.flash_error(t("Card error"))
            return status
        try:
            secret_id, _ = self._write_seed(card, self.ctx.wallet.key, label)
            card.delete_secret(temp_id)
        except sk.SeedKeeperError as exc:
            self._discard_temp(card, temp_id)
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return status
        self.flash_success(t("Secret %d saved") % secret_id)
        return status

    def save_seed(self):
        """Handler for the 'Save Seed to Card' menu item"""
        key = self.ctx.wallet.key
        # Ask for the label before the card is presented.  Typing it while
        # the card is held is what used to drop the link and force another
        # presentation; with the label already known, the card is only needed
        # for one uninterrupted PIN + write session.
        label = self._prompt_label(key)
        if label is None:
            return MENU_CONTINUE
        card = self._connect()
        if card is None:
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
            headers = self._card_action(card, card.list_secrets)
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        if not headers:
            self.flash_error(t("No secrets on card"))
            return MENU_CONTINUE
        while True:
            menu = Menu(
                self.ctx,
                [(self._secret_label(h), lambda h=h: h) for h in headers],
            )
            index, _ = menu.run_loop()
            if index == menu.back_index:
                return MENU_CONTINUE
            self._info_menu(self._secret_details(headers[index]))

    def delete_secret(self):
        """Handler for the 'Delete Secret from Card' menu item"""
        card = self._connect()
        if card is None:
            return MENU_CONTINUE
        try:
            headers = self._card_action(card, card.list_secrets)
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
            if not self._reconnect(card):
                self.flash_error(t("Card error"))
                return MENU_CONTINUE
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
            status = self._card_action(card, card.memory_status)
        except sk.SeedKeeperError as exc:
            self.flash_error("%s\n%s" % (t("Card error"), exc))
            return MENU_CONTINUE
        self._info_menu(
            "%s\n%s\n%s\n%d %s"
            % (
                t("Free Space"),
                t("%s bytes") % status["free_memory"],
                t("%s bytes") % status["total_memory"],
                status["nb_secrets"],
                t("secrets"),
            )
        )
        return MENU_CONTINUE

    def card_info(self):
        """Handler for the 'Card Info' menu item.

        GET_STATUS is exempt from the secure-channel gate, so this is also
        the quick way to check the card link without typing the PIN.
        """
        transport = self._transport()
        if transport is None:
            return MENU_CONTINUE
        card, status = self._card_session(transport)
        if card is None:
            return MENU_CONTINUE
        self._info_menu(
            "%s\n%s %d.%d\n%s %d.%d"
            % (
                t("Card Info"),
                t("Protocol"),
                status["protocol_major_version"],
                status["protocol_minor_version"],
                t("Applet"),
                status["applet_major_version"],
                status["applet_minor_version"],
            )
        )
        return MENU_CONTINUE

    # ------------------------------------------------------------- internals

    def _prompt_label(self, key=None, default=None):
        """Ask what to call this seed. None if the user backs out.

        Defaults to the wallet's fingerprint, which is what SeedSigner does and
        is the one label that can be recognised without the card.  A new
        mnemonic has no wallet yet, so its caller supplies a plain default
        instead and asks before the card is presented.
        """
        if default is None:
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

    def _generate_card_entropy(self, card, size):
        """Ask the card for ``size`` random bytes -> (temporary id, entropy).

        INS A3 is the current instruction.  A v0.1 applet only knows the
        deprecated INS A0, so an "unsupported" answer falls back to it.  Both
        store a ``[size | bytes]`` secret; the caller deletes it once the
        final BIP-39 secret exists.
        """
        try:
            temp_id, _ = card.generate_random_secret(size)
        except sk.SeedKeeperError as exc:
            if exc.sw not in sk.GENERATE_UNSUPPORTED_SW:
                raise
            temp_id, _ = card.generate_masterseed(size)
        _, secret = self._card_action(card, lambda: card.export_secret(temp_id))
        if len(secret) < 1 or secret[0] != size or len(secret) < 1 + size:
            raise sk.SeedKeeperError("Card returned the wrong amount of entropy")
        return temp_id, bytes(secret[1 : 1 + size])

    def _discard_temp(self, card, temp_id):
        """Best-effort removal of the temporary entropy secret."""
        if temp_id is None:
            return
        try:
            card.delete_secret(temp_id)
        except sk.SeedKeeperError:
            pass

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
        except sk.SeedKeeperError as exc:
            # An applet that does not implement the status instruction cannot
            # report its room; let the card be the judge instead of refusing
            # every write.  A link failure, though, must stop here: starting
            # an import after the card has gone away would only half-write it.
            if exc.sw is None:
                raise
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
