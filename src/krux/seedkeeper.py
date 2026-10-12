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

SeedKeeper smartcards: the APDU wire protocol and the secret formats.

A SeedKeeper is a PIN-protected JavaCard that keeps secrets at rest. This
module speaks to it and nothing else -- it has no opinion about the screen, and
no opinion about what carries the APDUs. A transport is any object with

    transmit(apdu: bytes) -> (bytes, int, int)

returning the response data and the two status word bytes. That is the only
interface between the card and whatever holds it (a phone's NFC stack, a USB
reader, a test double), and it is why this module is platform independent.

Only the plaintext flows are implemented: import/export with P1=0x01, which
the card gates on PIN verification alone. SeedSigner's own BIP-39 backups use
exactly this, so cards written by SeedSigner read back here and secrets written
here load in SeedSigner. The secure-channel flows (P1=0x02) additionally need
the card's ECDSA key and a per-secret AES key, and SeedKeeper secrets written
that way are unreadable without them; leaving them out keeps this portable and
is the price of interoperability.

Ported from the SeedSigner fork by 3rdIteration:
https://github.com/3rdIteration/seedsigner and the pysatochip library it uses,
both of which are the reference for every wire format encoded here.
"""

from hashlib import sha256

import urandom

# CardEdge class byte, as used by every Satochip/SeedKeeper instruction below.
CLA = 0xB0

INS_SETUP = 0x2A
INS_VERIFY_PIN = 0x42
INS_GET_STATUS = 0x3C
INS_IMPORT_SECRET = 0xA1
INS_EXPORT_SECRET = 0xA2
INS_RESET_SECRET = 0xA5
INS_LIST_HEADERS = 0xA6
INS_SEEDKEEPER_STATUS = 0xA7

# The applet's AID, as the card spells it: "SeedKeepe", ten bytes, no trailing
# 'r'. Not our typo to fix.
SEEDKEEPER_AID = [0x53, 0x65, 0x65, 0x64, 0x4B, 0x65, 0x65, 0x70, 0x65, 0x72]

SELECT_APDU = [0x00, 0xA4, 0x04, 0x00]

# Secret types, as the card reports them in a header's type byte.
TYPE_MASTERSEED = 0x10
TYPE_BIP39_MNEMONIC = 0x30
TYPE_PASSWORD = 0x90
TYPE_DATA = 0xC0
TYPE_DESCRIPTOR = 0xC1

# A Masterseed with this subtype also carries a BIP-39 mnemonic, its wordlist
# and the BIP-39 passphrase, so one secret round-trips a whole wallet. Without
# it a Masterseed secret is an opaque 64-byte seed.
SUBTYPE_BIP39 = 0x01

EXPORT_PLAINTEXT_ALLOWED = 0x01

PIN_MIN_SIZE = 4
PIN_MAX_SIZE = 16
MAX_LABEL_SIZE = 64

# Secrets are sent in chunks of this size; the card reassembles them.
CHUNK_SIZE = 128

# BIP-39 wordlists the card can name in a secret. Krux speaks English only,
# which is wordlist 0x00.
WORDLIST_ENGLISH = 0x00
WORDLIST_NAMES = {
    0x00: "english",
    0x01: "japanese",
    0x02: "korean",
    0x03: "spanish",
    0x04: "chinese_simplified",
    0x05: "chinese_traditional",
    0x06: "french",
    0x07: "italian",
    0x08: "czech",
    0x09: "portuguese",
}

# ISO/IEC 7816-4 status words, plus the proprietary 0x9Cxx range the Satochip
# applets use. Only the codes this feature can actually produce are listed;
# anything missing still decodes through status_text's fallback.
STATUS_WORDS = {
    0x6300: "State unchanged",
    0x6400: "State change expected",
    0x6700: "Wrong length",
    0x6982: "Security status not satisfied",
    0x6985: "Conditions of use not satisfied",
    0x6A80: "Incorrect parameters in the data field",
    0x6A82: "File not found",
    0x6A86: "Incorrect parameters P1 P2",
    0x6B00: "Wrong parameters P1 P2",
    0x6D00: "Not supported by this applet",
    0x6E00: "Class not supported",
    0x6F00: "Unknown error",
    0x9000: "Success",
    0x9C01: "Card is full",
    0x9C02: "Wrong PIN",
    0x9C03: "Operation not allowed",
    0x9C04: "Card setup not done",
    0x9C05: "Feature unsupported",
    0x9C08: "Secret not found",
    0x9C0C: "Identity blocked",
    0x9C0F: "Invalid parameter",
    0x9C11: "Incorrect P2",
    0x9C12: "No more secrets",
    0x9C31: "Export not allowed",
    0x9CFF: "Card internal error",
}


class SeedKeeperError(Exception):
    """A SeedKeeper refused a command.

    ``sw`` is the 16-bit status word when the card produced one, else None.
    Callers that need to tell "wrong PIN" from "card full" test it; everyone
    else just shows ``str(exc)``.
    """

    def __init__(self, message, sw=None):
        super().__init__(message)
        self.sw = sw


def status_text(sw1, sw2):
    """Human-readable description of a status word, hex code included."""
    sw = (sw1 << 8) | sw2
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        tries = sw2 & 0x0F
        return "PIN is incorrect, %d %s left" % (
            tries,
            "try" if tries == 1 else "tries",
        )
    description = STATUS_WORDS.get(sw)
    if description:
        return "%s (%#06x)" % (description, sw)
    return "Unknown error (%#06x)" % sw


def make_header(
    secret_type, label, export_rights=EXPORT_PLAINTEXT_ALLOWED, subtype=0x00
):
    """Build the secret header the card files alongside a secret.

    The layout is fixed by the applet: a 15-byte prefix followed by the label.
    The id, origin, export counters and fingerprint are all written by the
    card on import, so they are sent as zero -- import() strips them again.
    """
    label_bytes = label.encode("utf-8")
    if len(label_bytes) > MAX_LABEL_SIZE:
        raise ValueError("Label is longer than %d bytes" % MAX_LABEL_SIZE)
    header = [0x00, 0x00]  # id, assigned by the card
    header.append(secret_type)
    header.append(0x00)  # origin, the card records the import kind
    header.append(export_rights)
    header += [0x00, 0x00, 0x00]  # export counters, card maintained
    header += [0x00, 0x00, 0x00, 0x00]  # fingerprint, card assigned
    header.append(subtype)
    header.append(0x00)  # reserved
    header.append(len(label_bytes))
    return header + list(label_bytes)


def parse_header(data):
    """Decode a secret header as returned by list_secrets() or export_secret().

    ``label`` is None when the card's bytes are not valid UTF-8, which happens
    when another implementation wrote the secret; the rest still parses.
    """
    if len(data) < 15:
        raise SeedKeeperError("Secret header is too short (%d bytes)" % len(data))
    label_size = data[14]
    if len(data) < 15 + label_size:
        raise SeedKeeperError(
            "Secret header is truncated (want %d, got %d)"
            % (15 + label_size, len(data))
        )
    try:
        label = bytes(data[15 : 15 + label_size]).decode("utf-8")
    except UnicodeDecodeError:
        label = None
    return {
        "id": (data[0] << 8) + data[1],
        "type": data[2],
        "origin": data[3],
        "export_rights": data[4],
        "export_nbplain": data[5],
        "export_nbsecure": data[6],
        "export_counter": data[7],
        "fingerprint": bytes(data[8:12]).hex(),
        "subtype": data[12],
        "label_size": label_size,
        "label": label,
    }


def parse_card_status(data):
    """Decode INS 3C, the card-wide status.

    Trailing fields are optional -- the applet grew them over versions -- so
    anything absent defaults to a safe value rather than raising.
    """
    if len(data) < 4:
        raise SeedKeeperError("Card status is too short (%d bytes)" % len(data))
    status = {
        "protocol_major_version": data[0],
        "protocol_minor_version": data[1],
        "applet_major_version": data[2],
        "applet_minor_version": data[3],
        "PIN0_remaining_tries": data[4] if len(data) > 4 else None,
        # No setup_done byte means the applet predates the field, and such a
        # card could only have got this far already set up.
        "setup_done": data[10] != 0 if len(data) > 10 else True,
    }
    return status


def parse_memory_status(data):
    """Decode INS A7: secret count and free/total object memory."""
    if len(data) < 6:
        raise SeedKeeperError("SeedKeeper status is too short (%d bytes)" % len(data))
    return {
        "nb_secrets": (data[0] << 8) + data[1],
        "total_memory": (data[2] << 8) + data[3],
        "free_memory": (data[4] << 8) + data[5],
        "nb_logs_total": (data[6] << 8) + data[7] if len(data) > 7 else None,
        "nb_logs_avail": (data[8] << 8) + data[9] if len(data) > 9 else None,
    }


def secret_fingerprint(secret):
    """The card's own fingerprint for a plaintext secret: sha256, first 8 hex."""
    return sha256(bytes(secret)).hexdigest()[:8]


def padded_size(secret):
    """Bytes a plaintext secret occupies on the card.

    The card pads every secret up to the next 16-byte boundary and always adds
    a full block when the plaintext already lands on one, so a 16-byte secret
    costs 32. import() has to pad identically or the card rejects the length it
    was promised.
    """
    return len(secret) + 16 - (len(secret) % 16)


def pack_bip39_secret(master_seed, entropy, passphrase):
    """Build the payload for a Masterseed/BIP-39 secret.

    Length-prefixed throughout, every length one byte: master seed, then the
    wordlist that names the entropy, then the entropy itself, then the BIP-39
    passphrase. Storing all four is what makes a later load restore the exact
    wallet rather than a seed that needs the passphrase retyped.
    """
    passphrase_bytes = passphrase.encode("utf-8")
    secret = [len(master_seed)] + list(master_seed)
    secret.append(WORDLIST_ENGLISH)
    secret += [len(entropy)] + list(entropy)
    secret += [len(passphrase_bytes)] + list(passphrase_bytes)
    return secret


def unpack_bip39_secret(secret):
    """Inverse of pack_bip39_secret -> (entropy, passphrase).

    The master seed is validated but not returned: Krux re-derives it from the
    mnemonic and passphrase rather than trusting a stored seed to match them.
    A mismatch is exactly the sort of thing worth catching at load time.
    """
    secret = list(secret)
    if not secret:
        raise SeedKeeperError("Secret is empty")
    offset = 0

    def take(name):
        nonlocal offset
        if offset >= len(secret):
            raise SeedKeeperError("Secret is truncated before its %s" % name)
        size = secret[offset]
        offset += 1
        if offset + size > len(secret):
            raise SeedKeeperError("Secret is truncated inside its %s" % name)
        chunk = secret[offset : offset + size]
        offset += size
        return chunk

    master_seed = take("master seed")
    # The wordlist is a bare byte, not a length-prefixed field: the applet
    # reserved that slot before the payload grew length prefixes.
    if offset >= len(secret):
        raise SeedKeeperError("Secret is truncated before its wordlist")
    wordlist = secret[offset]
    offset += 1
    if wordlist not in WORDLIST_NAMES:
        raise SeedKeeperError("Unknown BIP-39 wordlist (%#04x)" % wordlist)
    entropy = take("entropy")
    passphrase = take("passphrase")
    if len(master_seed) == 0 or len(entropy) == 0:
        raise SeedKeeperError("Secret is missing its seed or entropy")
    return bytes(entropy), bytes(passphrase).decode("utf-8")


class SeedKeeper:
    """One SeedKeeper card, reached through an APDU transport."""

    def __init__(self, transport):
        self.transport = transport

    def _transmit(self, apdu):
        """Send one APDU and hand back (data, sw1, sw2) unexamined.

        A transport speaks whatever its host speaks -- pyjnius raises the
        Java exception it was given -- so whatever it throws is turned into a
        SeedKeeperError here. That puts every failure this module can produce
        behind one exception type, and lets callers above keep catching just
        the one.
        """
        try:
            return self.transport.transmit(bytes(apdu))
        # pylint: disable=broad-except
        # The transport is host code behind a one-method interface; its error
        # type is whatever the host runtime raises, and a card pulled off the
        # phone mid-command must read as a card error, not a crash.
        except SeedKeeperError:
            raise
        except Exception as exc:
            raise SeedKeeperError("Card communication failed: %s" % exc) from exc

    def _transmit_ok(self, apdu):
        """Send one APDU that has to succeed, or raise SeedKeeperError."""
        data, sw1, sw2 = self._transmit(apdu)
        if sw1 != 0x90 or sw2 != 0x00:
            raise SeedKeeperError(status_text(sw1, sw2), (sw1 << 8) | sw2)
        return data

    def select(self):
        """Select the SeedKeeper applet by AID.

        A transport that already resolved the applet (Android's IsoDep does,
        from the tag's AID list) can skip this; a raw one cannot.
        """
        self._transmit_ok(SELECT_APDU + [len(SEEDKEEPER_AID)] + SEEDKEEPER_AID)

    def card_status(self):
        """Card-wide status: versions, PIN tries left, whether setup is done."""
        return parse_card_status(self._transmit_ok([CLA, INS_GET_STATUS, 0x00, 0x00]))

    def memory_status(self):
        """SeedKeeper-specific status: secret count and free memory."""
        return parse_memory_status(
            self._transmit_ok([CLA, INS_SEEDKEEPER_STATUS, 0x00, 0x00])
        )

    def verify_pin(self, pin):
        """Verify PIN 0.

        A wrong PIN raises SeedKeeperError whose message says how many tries
        are left, so a caller can show that without parsing anything.
        """
        pin_bytes = pin.encode("utf-8")
        if not PIN_MIN_SIZE <= len(pin_bytes) <= PIN_MAX_SIZE:
            raise ValueError("PIN must be 4 to 16 bytes")
        self._transmit_ok(
            [CLA, INS_VERIFY_PIN, 0x00, 0x00, len(pin_bytes)] + list(pin_bytes)
        )

    def setup(self, pin):
        """Initialise a blank card with ``pin`` as its PIN (INS 2A).

        The applet keeps a second, unusable PIN and a PUK for unlocking PIN 0.
        None of them are ever used here, so they get random bytes rather than
        something a user could mistake for a credential they must remember.
        """
        pin_bytes = pin.encode("utf-8")
        if not PIN_MIN_SIZE <= len(pin_bytes) <= PIN_MAX_SIZE:
            raise ValueError("PIN must be 4 to 16 bytes")
        junk = list(_random_bytes(16))
        junk2 = list(_random_bytes(16))
        default_pin = list(b"Muscle00")
        data = [len(default_pin)] + default_pin
        data += [0x05, 0x01, len(pin_bytes)] + list(pin_bytes)
        data += [len(junk)] + junk
        data += [0x01, 0x01, len(junk2)] + junk2
        data += [len(junk2)] + junk2
        data += [0x00, 0x20, 0x00, 0x00]  # secmem size, memsize
        data += [0x01, 0x01, 0x01]  # object, key and pin ACLs
        self._transmit_ok([CLA, INS_SETUP, 0x00, 0x00, len(data)] + data)

    def list_secrets(self):
        """Every secret header on the card, in card order.

        The card walks its objects one APDU at a time and ends with 0x9C12;
        that ending is the loop's normal exit, not a failure.
        """
        headers = []
        p2 = 0x01
        while True:
            data, sw1, sw2 = self._transmit([CLA, INS_LIST_HEADERS, 0x00, p2])
            if sw1 == 0x90 and sw2 == 0x00:
                headers.append(parse_header(data))
            elif (sw1 << 8) | sw2 == 0x9C12:
                break
            else:
                raise SeedKeeperError(status_text(sw1, sw2), (sw1 << 8) | sw2)
            p2 = 0x02
        return headers

    def export_secret(self, secret_id):
        """Read one secret in full -> (header, secret bytes).

        Only secrets whose export rights allow plaintext export can be read
        this way; the card answers 0x9C31 for the rest.
        """
        data = self._transmit_ok(
            [
                CLA,
                INS_EXPORT_SECRET,
                0x01,
                0x01,
                0x02,
                (secret_id >> 8) & 0xFF,
                secret_id & 0xFF,
            ]
        )
        header = parse_header(data)
        secret = []
        while True:
            data, sw1, sw2 = self._transmit(
                [
                    CLA,
                    INS_EXPORT_SECRET,
                    0x01,
                    0x02,
                    0x02,
                    (secret_id >> 8) & 0xFF,
                    secret_id & 0xFF,
                ]
            )
            if sw1 != 0x90 or sw2 != 0x00:
                raise SeedKeeperError(status_text(sw1, sw2), (sw1 << 8) | sw2)
            chunk_size = (data[0] << 8) + data[1]
            secret += list(data[2 : 2 + chunk_size])
            # The applet signs the whole secret and appends it to the last
            # chunk only. The signature is not checked here: it is the card's
            # ECDSA key over data the caller can already verify by reimporting
            # and comparing fingerprints, and the key is not part of this
            # plaintext transport.
            if len(data) > 2 + chunk_size:
                break
        return header, bytes(secret)

    def import_secret(self, header, secret):
        """Write one secret and return (id, fingerprint) as the card assigned.

        ``header`` comes from make_header(). The card takes the type and
        origin from its own bookkeeping, so only the header from export_rights
        onwards is sent -- which is why the first four bytes go.
        """
        secret = list(secret)
        size = padded_size(secret)
        payload = header[4:] + [(size >> 8) & 0xFF, size & 0xFF]
        self._transmit_ok([CLA, INS_IMPORT_SECRET, 0x01, 0x01, len(payload)] + payload)
        offset = 0
        remaining = len(secret)
        while remaining > CHUNK_SIZE:
            chunk = [CHUNK_SIZE >> 8, CHUNK_SIZE & 0xFF]
            chunk += secret[offset : offset + CHUNK_SIZE]
            self._transmit_ok([CLA, INS_IMPORT_SECRET, 0x01, 0x02, len(chunk)] + chunk)
            offset += CHUNK_SIZE
            remaining -= CHUNK_SIZE
        final = [remaining >> 8, remaining & 0xFF]
        final += secret[offset : offset + remaining]
        data = self._transmit_ok(
            [CLA, INS_IMPORT_SECRET, 0x01, 0x03, len(final)] + final
        )
        secret_id = (data[0] << 8) + data[1]
        fingerprint = bytes(data[2:6]).hex()
        if fingerprint != secret_fingerprint(secret):
            raise SeedKeeperError(
                "Card stored the secret under a different fingerprint"
            )
        return secret_id, fingerprint

    def delete_secret(self, secret_id):
        """Free one secret's memory. False when there was no such secret."""
        _, sw1, sw2 = self._transmit(
            [
                CLA,
                INS_RESET_SECRET,
                0x00,
                0x00,
                0x02,
                (secret_id >> 8) & 0xFF,
                secret_id & 0xFF,
            ]
        )
        if sw1 == 0x90 and sw2 == 0x00:
            return True
        if (sw1 << 8) | sw2 == 0x9C08:
            return False
        raise SeedKeeperError(status_text(sw1, sw2), (sw1 << 8) | sw2)


def _random_bytes(count):
    """``count`` bytes from the platform CSPRNG."""
    return urandom.getrandbits(count * 8).to_bytes(count, "big")


# Sentinel for "the reader has not been looked up yet", so that a build with
# no reader is asked once rather than on every call.
_UNSET = object()
_transport = _UNSET


def get_transport():
    """This build's card transport, or None when it has no card reader.

    Krux firmware proper has no NFC peripheral and no smartcard reader of any
    kind, so there is nothing to return there. A build that does have one
    supplies an ``nfc`` module -- the mobile app's mocks/nfc.py is exactly
    that -- exposing ``transport()``. Resolving it lazily keeps the import out
    of images that have no reader, which is every Krux firmware image.
    """
    global _transport  # pylint: disable=global-statement  # the memo is the point
    if _transport is _UNSET:
        try:
            import nfc
        except ImportError:
            _transport = None
        else:
            _transport = nfc.transport()
    return _transport


def available():
    """True when this build can reach a smartcard at all."""
    return get_transport() is not None
