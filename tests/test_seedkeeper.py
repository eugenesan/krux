"""The SeedKeeper wire protocol, exercised against a scripted card.

The transport is a fake that answers from a small in-memory card. That is the
point of the module's shape: it depends on nothing but ``transmit(apdu)``,
so everything here is the same code the firmware and the phone run, with the
APDUs it would put on the wire checked byte for byte.
"""

import random
import sys

import pytest

# krux.seedkeeper imports urandom at module scope, as firmware code does for
# its MicroPython builtins. The mp_modules fixture supplies that mock for tests
# that drive pages; this module imports krux.seedkeeper at collection time, so
# it installs the same shim (stdlib random has getrandbits) up front.
sys.modules.setdefault("urandom", random)

from krux.seedkeeper import (
    CLA,
    SEEDKEEPER_AID,
    SUBTYPE_BIP39,
    SW_APPLET_NOT_FOUND,
    TYPE_MASTERSEED,
    SeedKeeper,
    SeedKeeperError,
    available,
    make_header,
    pack_bip39_secret,
    parse_header,
    padded_size,
    secret_fingerprint,
    status_text,
    unpack_bip39_secret,
)

ENTROPY = bytes(range(16))
MASTER_SEED = bytes(range(64))


def pack_bip39_seed(passphrase=""):
    return pack_bip39_secret(MASTER_SEED, ENTROPY, passphrase)


class FakeCard:
    """A SeedKeeper just real enough to answer the APDUs this module sends.

    It holds secrets the way the applet does -- header, id, and a 16-byte
    aligned payload -- so a round trip through it exercises the padding and
    chunking rules rather than trusting them.
    """

    def __init__(self, setup_done=True, applet_minor=2):
        self.setup_done = setup_done
        self.applet_minor = applet_minor
        # Whether the card carries the SeedKeeper applet at all. A blank
        # JavaCard does not, and answers SELECT by AID with 6A82.
        self.has_applet = True
        # A secret's type byte is the applet's to assign: the client never
        # sends it, only the tail of the header from export_rights onwards.
        self.default_type = 0x10  # Masterseed
        # Older applets do not implement INS A7 at all and answer 0x6D00.
        self.status_unsupported = False
        self.free_memory = 4096
        self.pin = None
        self.secrets = {}
        self.next_id = 1
        self.apdus = []
        self.pending = None
        # INS A3 is newer than the v0.1 applet.  Tests that need the old
        # behaviour turn it off and exercise the INS A0 fallback.
        self.random_secret_supported = True
        # Deterministic bytes so a page test can predict the mnemonic while
        # still exercising the same "card chose the entropy" path.
        self.generated_entropy = bytes(range(64))

    def transmit(self, apdu):
        self.apdus.append(bytes(apdu))
        return self._dispatch(bytes(apdu))

    def _fail(self, sw):
        return (b"", sw >> 8, sw & 0xFF)

    def _ok(self, data=b""):
        return (bytes(data), 0x90, 0x00)

    def _dispatch(self, apdu):
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        if ins == 0xA4:
            # SELECT carries its own class byte, not the Satochip one
            if self.has_applet:
                return self._ok()
            return self._fail(0x6A82)
        if cla != CLA:
            return self._fail(0x6E00)
        if ins == 0x3C:
            data = [
                0x00,
                self.applet_minor,
                0x00,
                self.applet_minor,
                3,
                3,
                3,
                3,
                0,
                0,
                0,
            ]
            data[10] = 1 if self.setup_done else 0
            return self._ok(data)
        if ins == 0xA7:
            if self.status_unsupported:
                return self._fail(0x6D00)
            used = sum(len(s) for s in self.secrets.values())
            free = max(0, self.free_memory - used)
            return self._ok(
                [0, len(self.secrets), 0, 100, free >> 8, free & 0xFF, 0, 0, 0, 5]
            )
        if ins == 0x42:
            pin = apdu[5 : 5 + apdu[4]].decode("utf-8")
            if not self.setup_done:
                return self._fail(0x9C04)
            if pin != self.pin:
                return self._fail(0x63C2)  # 2 tries left
            return self._ok()
        if ins == 0x2A:
            self.pin = apdu[17 : 17 + apdu[16]].decode("utf-8")
            self.setup_done = True
            return self._ok()
        if ins == 0xA3:
            if not self.random_secret_supported:
                return self._fail(0x6D00)
            return self._generate_random_secret(apdu)
        if ins == 0xA0:
            return self._generate_masterseed(apdu)
        if ins == 0xA6:
            order = sorted(self.secrets.items())
            if p2 == 0x01:
                index = 0
            else:
                index = self.pending + 1
            if index >= len(order):
                return self._fail(0x9C12)
            self.pending = index
            sid, stored = order[index]
            return self._ok(stored[0])
        if ins == 0xA1:
            return self._import(apdu, p2)
        if ins == 0xA2:
            return self._export(apdu, p2)
        if ins == 0xA5:
            sid = (apdu[5] << 8) + apdu[6]
            if sid not in self.secrets:
                return self._fail(0x9C08)
            del self.secrets[sid]
            return self._ok()
        return self._fail(0x6D00)

    def _generate_random_secret(self, apdu):
        secret_size = apdu[2]
        data = list(apdu[5:])
        if len(data) < 4:
            return self._fail(0x6C00)
        secret_type = data[0]
        subtype = data[1]
        label_size = data[3]
        label = bytes(data[4 : 4 + label_size]).decode("utf-8")
        offset = 4 + label_size
        if offset >= len(data):
            return self._fail(0x6C00)
        entropy_size = data[offset]
        if offset + 1 + entropy_size > len(data):
            return self._fail(0x6C00)
        secret = self.generated_entropy[:secret_size]
        return self._store_generated(secret_type, subtype, apdu[3], label, secret)

    def _generate_masterseed(self, apdu):
        seed_size = apdu[2]
        data = list(apdu[5:])
        if not data:
            return self._fail(0x6C00)
        label_size = data[0]
        label = bytes(data[1 : 1 + label_size]).decode("utf-8")
        secret = self.generated_entropy[:seed_size]
        return self._store_generated(0x10, 0x00, apdu[3], label, secret)

    def _store_generated(self, secret_type, subtype, export_rights, label, secret):
        sid = self.next_id
        self.next_id += 1
        label_bytes = list(label.encode("utf-8"))
        header = (
            [sid >> 8, sid & 0xFF, secret_type, 0x02, export_rights]
            + [0, 0, 0]
            + [0, 0, 0, 0]
            + [subtype, 0x00, len(label_bytes)]
            + label_bytes
        )
        payload = [len(secret)] + list(secret)
        self.secrets[sid] = (header, payload)
        fingerprint = secret_fingerprint(payload)
        return self._ok([sid >> 8, sid & 0xFF] + list(bytes.fromhex(fingerprint)))

    def _import(self, apdu, p2):
        if not self.setup_done:
            return self._fail(0x9C04)
        data = list(apdu[5:])
        if p2 == 0x01:
            # header[2:]: type, origin, export_rights, counters/fingerprint,
            # subtype, reserved, label_size, label, then the padded size.
            label_size = data[12]
            self.pending = {
                "export_rights": data[2],
                "type": data[0],
                "label_size": label_size,
                "label": bytes(data[13 : 13 + label_size]).decode("utf-8"),
                "subtype": data[10],
                "size": (data[13 + label_size] << 8) + data[14 + label_size],
                "payload": [],
            }
            return self._ok()
        if p2 == 0x02:
            self.pending["payload"] += list(apdu[7:])
            return self._ok()
        chunk = list(apdu[5:])
        self.pending["payload"] += chunk[2 : 2 + ((chunk[0] << 8) + chunk[1])]
        pending = self.pending
        payload = pending["payload"]
        # The card pads the plaintext on write, so what it declared is what
        # the plaintext will occupy, not its length: round up to the next
        # 16-byte boundary, adding a whole block when it already lands on one.
        expected = len(payload) + 16 - (len(payload) % 16)
        assert pending["size"] == expected, (pending["size"], expected)
        sid = self.next_id
        self.next_id += 1
        header = (
            [sid >> 8, sid & 0xFF, pending["type"], 0x01, pending["export_rights"]]
            + [0, 0, 0]
            + [0, 0, 0, 0]
            + [pending["subtype"], 0x00, pending["label_size"]]
            + list(pending["label"].encode("utf-8"))
        )
        self.secrets[sid] = (header, payload)
        self.pending = None
        fingerprint = secret_fingerprint(payload)
        return self._ok([sid >> 8, sid & 0xFF] + list(bytes.fromhex(fingerprint)))

    def _export(self, apdu, p2):
        sid = (apdu[5] << 8) + apdu[6]
        if sid not in self.secrets:
            return self._fail(0x9C08)
        header, payload = self.secrets[sid]
        if p2 == 0x01:
            return self._ok(header)
        # Serve 16 bytes at a time so the loop in export_secret() iterates.
        offset = getattr(self, "_export_offset", 0)
        self._export_offset = offset + 16
        chunk = payload[offset : offset + 16]
        data = [len(chunk) >> 8, len(chunk) & 0xFF] + list(chunk)
        if offset + 16 >= len(payload):
            self._export_offset = 0
            data += [0, 20] + [0xAB] * 20  # trailing signature
        return self._ok(data)


@pytest.fixture
def card():
    fake = FakeCard()
    fake.pin = "123456"
    return fake


@pytest.fixture
def keeper(card):
    return SeedKeeper(card)


class TestStatusText:
    def test_a_known_code_carries_its_description(self):
        assert status_text(0x9C, 0x01) == "Card is full (0x9c01)"

    def test_an_unknown_code_still_says_the_hex(self):
        assert status_text(0x9C, 0x7E) == "Unknown error (0x9c7e)"

    def test_a_pin_code_counts_down_the_tries(self):
        assert status_text(0x63, 0xC3) == "PIN is incorrect, 3 tries left"
        assert status_text(0x63, 0xC1) == "PIN is incorrect, 1 try left"


class TestHeader:
    def test_round_trips_through_parse(self):
        header = make_header(TYPE_MASTERSEED, "savings", subtype=SUBTYPE_BIP39)
        parsed = parse_header(header)
        assert parsed["label"] == "savings"
        assert parsed["type"] == TYPE_MASTERSEED
        assert parsed["subtype"] == SUBTYPE_BIP39

    def test_the_card_fills_in_what_the_header_leaves_zero(self):
        parsed = parse_header(make_header(TYPE_MASTERSEED, "savings"))
        # id, origin, counters and fingerprint are all the card's to assign
        assert parsed["id"] == 0
        assert parsed["origin"] == 0
        assert parsed["fingerprint"] == "00000000"

    def test_a_label_too_long_for_the_card_is_refused(self):
        with pytest.raises(ValueError):
            make_header(TYPE_MASTERSEED, "x" * 65)

    def test_a_truncated_header_is_reported_not_guessed(self):
        with pytest.raises(SeedKeeperError):
            parse_header([0] * 10)

    def test_a_label_running_past_the_header_is_reported(self):
        with pytest.raises(SeedKeeperError):
            parse_header([0] * 14 + [9] + [ord("a")] * 3)

    def test_an_undecodable_label_is_none_not_an_exception(self):
        # Another implementation may have written non-UTF-8 label bytes
        parsed = parse_header([0] * 14 + [2, 0xFF, 0xFE])
        assert parsed["label"] is None


class TestSecretPacking:
    def test_round_trips_entropy_and_passphrase(self):
        secret = pack_bip39_secret(MASTER_SEED, ENTROPY, "satoshi")
        entropy, passphrase = unpack_bip39_secret(secret)
        assert entropy == ENTROPY
        assert passphrase == "satoshi"

    def test_an_empty_passphrase_round_trips(self):
        secret = pack_bip39_secret(MASTER_SEED, ENTROPY, "")
        assert unpack_bip39_secret(secret) == (ENTROPY, "")

    def test_padding_always_adds_a_block(self):
        # The card pads up to the next boundary, and a full block when the
        # secret already lands on one.
        assert padded_size([0] * 15) == 16
        assert padded_size([0] * 16) == 32
        assert padded_size([0] * 17) == 32

    def test_an_empty_secret_is_refused(self):
        with pytest.raises(SeedKeeperError):
            unpack_bip39_secret([])

    def test_a_truncated_secret_is_refused(self):
        secret = pack_bip39_secret(MASTER_SEED, ENTROPY, "satoshi")
        with pytest.raises(SeedKeeperError):
            unpack_bip39_secret(secret[:20])

    def test_a_missing_passphrase_length_is_refused(self):
        secret = [len(MASTER_SEED)] + list(MASTER_SEED) + [0x00] + [len(ENTROPY)]
        with pytest.raises(SeedKeeperError):
            unpack_bip39_secret(secret)

    def test_an_unknown_wordlist_is_refused(self):
        secret = [len(MASTER_SEED)] + list(MASTER_SEED) + [0x42] + [len(ENTROPY)]
        with pytest.raises(SeedKeeperError):
            unpack_bip39_secret(secret)


class TestConnection:
    def test_select_uses_the_applets_own_aid(self, keeper, card):
        keeper.select()
        assert card.apdus[-1][5:] == bytes(SEEDKEEPER_AID)

    def test_a_card_without_the_applet_says_so_by_status_word(self, card):
        # A blank JavaCard: SELECT by AID answers 6A82, and the page turns
        # that one code into a sentence. Pinning it here stops the constant
        # drifting away from what the card actually returns.
        card.has_applet = False
        with pytest.raises(SeedKeeperError) as excinfo:
            SeedKeeper(card).select()
        assert excinfo.value.sw == 0x6A82
        assert excinfo.value.sw == SW_APPLET_NOT_FOUND

    def test_a_wrong_class_is_a_seedkeeper_error(self):
        class WrongClass:
            def transmit(self, apdu):
                # Every SeedKeeper instruction but SELECT uses the CardEdge
                # class byte; a card that answers anything else is not one.
                return (b"", 0x6E, 0x00)

        with pytest.raises(SeedKeeperError) as excinfo:
            SeedKeeper(WrongClass()).card_status()
        assert excinfo.value.sw == 0x6E00

    def test_card_status_reports_setup_and_versions(self, keeper):
        status = keeper.card_status()
        assert status["setup_done"] is True
        assert status["protocol_minor_version"] == 2

    def test_a_blank_card_reports_setup_not_done(self, card):
        card.setup_done = False
        assert SeedKeeper(card).card_status()["setup_done"] is False

    def test_memory_status_reports_free_bytes(self, keeper, card):
        status = keeper.memory_status()
        assert status["nb_secrets"] == 0
        assert status["total_memory"] == 100
        assert status["free_memory"] == 4096

    def test_a_pin_outside_the_cards_range_never_reaches_the_card(self, keeper, card):
        for bad in ("123", "x" * 17):
            with pytest.raises(ValueError):
                keeper.verify_pin(bad)
        assert card.apdus == []


class TestPin:
    def test_the_right_pin_unlocks(self, keeper):
        keeper.verify_pin("123456")

    def test_the_wrong_pin_raises_and_says_how_many_tries_are_left(self, keeper):
        with pytest.raises(SeedKeeperError) as excinfo:
            keeper.verify_pin("000000")
        assert "2 tries left" in str(excinfo.value)
        assert excinfo.value.sw == 0x63C2

    def test_verifying_a_blank_card_reports_setup_not_done(self, card):
        card.setup_done = False
        with pytest.raises(SeedKeeperError) as excinfo:
            SeedKeeper(card).verify_pin("123456")
        assert excinfo.value.sw == 0x9C04

    def test_setup_sets_the_pin_and_marks_the_card_done(self, card):
        card.setup_done = False
        keeper = SeedKeeper(card)
        keeper.setup("987654")
        keeper.verify_pin("987654")

    def test_setup_refuses_a_pin_the_card_could_not_store(self, card):
        with pytest.raises(ValueError):
            SeedKeeper(card).setup("1")


class TestSecretRoundTrip:
    def _store(self, keeper, label="savings", passphrase="satoshi"):
        secret = pack_bip39_secret(MASTER_SEED, ENTROPY, passphrase)
        header = make_header(TYPE_MASTERSEED, label, subtype=SUBTYPE_BIP39)
        return keeper.import_secret(header, secret)

    def test_a_stored_secret_lists_with_its_label(self, keeper):
        self._store(keeper, label="cold")
        headers = keeper.list_secrets()
        assert len(headers) == 1
        assert headers[0]["label"] == "cold"
        assert headers[0]["type"] == TYPE_MASTERSEED
        assert headers[0]["subtype"] == SUBTYPE_BIP39

    def test_secrets_list_in_the_order_the_card_stores_them(self, keeper):
        self._store(keeper, label="first")
        self._store(keeper, label="second")
        assert [h["label"] for h in keeper.list_secrets()] == ["first", "second"]

    def test_an_empty_card_lists_nothing_rather_than_failing(self, keeper):
        assert keeper.list_secrets() == []

    def test_a_stored_secret_exports_back_byte_for_byte(self, keeper):
        self._store(keeper, passphrase="satoshi")
        header, secret = keeper.export_secret(1)
        entropy, passphrase = unpack_bip39_secret(secret)
        assert header["label"] == "savings"
        assert entropy == ENTROPY
        assert passphrase == "satoshi"

    def test_importing_returns_the_ids_and_fingerprint_the_card_chose(self, keeper):
        secret_id, fingerprint = self._store(keeper)
        assert secret_id == 1
        assert fingerprint == secret_fingerprint(pack_bip39_seed("satoshi"))

    def test_a_secret_larger_than_one_chunk_is_sent_in_chunks(self, keeper, card):
        # 300 bytes pads to 304, so the middle chunks have to carry it
        secret = pack_bip39_secret(MASTER_SEED, ENTROPY, "p" * 200)
        keeper.import_secret(make_header(TYPE_MASTERSEED, "big"), secret)
        process = [a for a in card.apdus if a[1] == 0xA1 and a[3] == 0x02]
        assert len(process) == 2
        assert all(len(a) == 5 + 2 + 128 for a in process)

    def test_a_secret_exactly_one_chunk_long_sends_no_middle_chunk(self, keeper, card):
        keeper.import_secret(
            make_header(TYPE_MASTERSEED, "one"),
            pack_bip39_secret(MASTER_SEED, ENTROPY, ""),
        )
        assert not [a for a in card.apdus if a[1] == 0xA1 and a[3] == 0x02]

    def test_exporting_a_secret_that_is_not_there_reports_it(self, keeper):
        with pytest.raises(SeedKeeperError) as excinfo:
            keeper.export_secret(99)
        assert excinfo.value.sw == 0x9C08

    def test_a_secret_written_twice_gets_its_own_id(self, keeper):
        first, _ = self._store(keeper, label="one")
        second, _ = self._store(keeper, label="two")
        assert (first, second) == (1, 2)


class TestDelete:
    def test_deleting_a_secret_frees_its_id(self, keeper):
        secret_id, _ = keeper.import_secret(
            make_header(TYPE_MASTERSEED, "gone"),
            pack_bip39_secret(MASTER_SEED, ENTROPY, ""),
        )
        assert keeper.delete_secret(secret_id) is True
        assert keeper.list_secrets() == []

    def test_deleting_a_secret_that_is_not_there_says_so_rather_than_failing(
        self, keeper
    ):
        assert keeper.delete_secret(99) is False

    def test_deleting_releases_the_memory_a_secret_was_holding(self, keeper):
        before = keeper.memory_status()["free_memory"]
        keeper.import_secret(
            make_header(TYPE_MASTERSEED, "big"),
            pack_bip39_seed(passphrase="p" * 200),
        )
        full = keeper.memory_status()["free_memory"]
        assert full < before
        keeper.delete_secret(1)
        assert keeper.memory_status()["free_memory"] == before


class TestGenerate:
    def test_generate_random_secret_uses_the_a3_layout(self, keeper, card):
        from krux.seedkeeper import (
            CLA,
            EXPORT_PLAINTEXT_ALLOWED,
            INS_GENERATE_RANDOM_SECRET,
            secret_fingerprint,
        )

        secret_id, fingerprint = keeper.generate_random_secret(
            16,
            label="tmp",
            subtype=0x02,
            external_entropy=b"abc",
            save_entropy=True,
        )
        apdu = card.apdus[-1]
        assert apdu[0] == CLA
        assert apdu[1] == INS_GENERATE_RANDOM_SECRET
        assert apdu[2] == 16
        assert apdu[3] == EXPORT_PLAINTEXT_ALLOWED
        data = list(apdu[5:])
        assert data[:4] == [TYPE_MASTERSEED, 0x02, 0x01, 3]
        assert data[4:7] == list(b"tmp")
        assert data[7] == 3
        assert data[8:11] == list(b"abc")
        _, secret = keeper.export_secret(secret_id)
        assert secret == bytes([16]) + card.generated_entropy[:16]
        assert fingerprint == secret_fingerprint(secret)

    def test_generate_masterseed_uses_the_a0_layout(self, keeper, card):
        from krux.seedkeeper import (
            CLA,
            INS_GENERATE_MASTERSEED,
        )

        secret_id, _ = keeper.generate_masterseed(32, label="old")
        apdu = card.apdus[-1]
        assert apdu[0] == CLA
        assert apdu[1] == INS_GENERATE_MASTERSEED
        assert apdu[2] == 32
        assert list(apdu[5:]) == [3] + list(b"old")
        _, secret = keeper.export_secret(secret_id)
        assert secret == bytes([32]) + card.generated_entropy[:32]

    def test_generate_refuses_sizes_the_applet_cannot_make(self, keeper):
        for size in (15, 65):
            with pytest.raises(ValueError):
                keeper.generate_random_secret(size)
            with pytest.raises(ValueError):
                keeper.generate_masterseed(size)

    def test_generate_refuses_entropy_larger_than_the_secret(self, keeper):
        with pytest.raises(ValueError):
            keeper.generate_random_secret(16, external_entropy=b"x" * 17)

    def test_generate_refuses_a_label_the_card_cannot_hold(self, keeper):
        with pytest.raises(ValueError):
            keeper.generate_random_secret(16, label="x" * 65)
        with pytest.raises(ValueError):
            keeper.generate_masterseed(16, label="x" * 65)


class TestTransportFailures:
    """Whatever a transport throws becomes a SeedKeeperError.

    The transport is host code behind a one-method interface -- on a phone it
    is pyjnius raising whatever Java raised -- and a card pulled off the phone
    mid-command has to read as a card error rather than crash the menu.
    """

    def test_a_runtime_failure_is_reported_as_a_card_error(self):
        class Broken:
            def transmit(self, _apdu):
                raise RuntimeError("tag lost")

        with pytest.raises(SeedKeeperError) as excinfo:
            SeedKeeper(Broken()).card_status()
        assert "Card communication failed" in str(excinfo.value)
        assert excinfo.value.sw is None

    def test_a_failure_mid_export_does_not_return_half_a_secret(self):
        class DropsMidway:
            def __init__(self):
                self.calls = 0

            def transmit(self, _apdu):
                self.calls += 1
                if self.calls == 1:
                    return (
                        bytes([0, 0, 0x10, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                        + b"a",
                        0x90,
                        0x00,
                    )
                raise RuntimeError("moved")

        with pytest.raises(SeedKeeperError):
            SeedKeeper(DropsMidway()).export_secret(1)

    def test_an_error_the_transport_raised_ourselves_is_left_alone(self):
        class Ours:
            def transmit(self, _apdu):
                raise SeedKeeperError("already ours")

        with pytest.raises(SeedKeeperError) as excinfo:
            SeedKeeper(Ours()).card_status()
        assert str(excinfo.value) == "already ours"


class TestTransportDiscovery:
    """The nfc module decides whether this build can reach a card at all.

    These reach through `module.<fn>` rather than the names imported at the
    top of this file: the board fixtures purge krux from sys.modules between
    tests, so the collection-time `available` can belong to a module instance
    that is no longer the one in play.
    """

    def test_no_reader_module_means_no_card_support(self, monkeypatch):
        import sys

        import krux.seedkeeper as module

        monkeypatch.delitem(sys.modules, "nfc", raising=False)
        monkeypatch.setattr(module, "_transport", module._UNSET)
        assert module.available() is False
        assert module.get_transport() is None

    def test_a_build_with_a_reader_reports_it(self, monkeypatch):
        import sys
        import types

        import krux.seedkeeper as module

        sentinel = object()
        fake = types.ModuleType("nfc")
        fake.transport = lambda: sentinel
        monkeypatch.setitem(sys.modules, "nfc", fake)
        monkeypatch.setattr(module, "_transport", module._UNSET)
        assert module.available() is True
        assert module.get_transport() is sentinel

    def test_the_reader_is_looked_up_once_not_per_call(self, monkeypatch):
        import sys
        import types

        import krux.seedkeeper as module

        calls = []

        class Reader:
            @staticmethod
            def transport():
                calls.append(1)
                return object()

        fake = types.ModuleType("nfc")
        fake.transport = Reader.transport
        monkeypatch.setitem(sys.modules, "nfc", fake)
        monkeypatch.setattr(module, "_transport", module._UNSET)
        module.get_transport()
        module.get_transport()
        assert len(calls) == 1

    def test_the_login_menu_omits_the_item_where_there_is_no_reader(
        self, monkeypatch, amigo, mocker
    ):
        # The K210 firmware has no NFC peripheral, so the menu item would be
        # one that could only ever report "no card reader". It is left out.
        import krux.seedkeeper as module

        monkeypatch.setattr(module, "_transport", module._UNSET)
        monkeypatch.delitem(sys.modules, "nfc", raising=False)
        from .pages import create_ctx

        ctx = create_ctx(mocker, (1,))
        from krux.pages.login import Login

        labels = [item[0] for item in Login(ctx).menu.menu]
        assert "SeedKeeper Card" not in labels

    def test_the_login_menu_offers_the_item_where_there_is_a_reader(
        self, monkeypatch, amigo, mocker
    ):
        import sys
        import types

        import krux.seedkeeper as module

        fake = types.ModuleType("nfc")
        fake.transport = lambda: object()
        monkeypatch.setitem(sys.modules, "nfc", fake)
        monkeypatch.setattr(module, "_transport", module._UNSET)
        from .pages import create_ctx

        ctx = create_ctx(mocker, (1,))
        from krux.pages.login import Login

        labels = [item[0] for item in Login(ctx).menu.menu]
        assert "SeedKeeper Card" in labels
