"""The SeedKeeper screen, driven through its menus and prompts.

The card is the FakeCard from the protocol tests -- the same one -- so these
check what the screen does with a card that behaves like a real applet:
which secrets it offers, what it writes, and where it refuses.

The keypad is stubbed. What a PIN or a label looks like is the keypad's
business; what matters here is what the screen does with what came back.

Everything under krux is imported inside a test or fixture, never at module
scope: board fixtures purge krux from sys.modules, and page modules cannot
even be imported until those mocks are in place.
"""

import pytest

from . import create_ctx
from ..test_seedkeeper import ENTROPY, MASTER_SEED, FakeCard

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
PASSPHRASE = "card"


@pytest.fixture
def sk(m5stickv):
    """krux.seedkeeper as this test will see it."""
    import krux.seedkeeper

    return krux.seedkeeper


@pytest.fixture
def page_cls(m5stickv):
    from krux.pages.seedkeeper import SeedKeeperPage

    return SeedKeeperPage


@pytest.fixture
def card():
    fake = FakeCard()
    fake.pin = "123456"
    return fake


@pytest.fixture
def reader(card, sk, monkeypatch):
    """Make this build look like one that can reach a card."""
    monkeypatch.setattr(sk, "_transport", card)
    return card


@pytest.fixture
def no_reader(sk, monkeypatch):
    """Make this build look like the K210 firmware: no NFC peripheral."""
    monkeypatch.setattr(sk, "_transport", None)


@pytest.fixture
def make_page(page_cls, mocker):
    """Build a page with a wallet funnel that records the words it is given."""

    def _make(wallet=None):
        ctx = create_ctx(mocker, (1,), wallet=wallet)
        loaded = []
        page = page_cls(ctx, lambda words, *a, **k: loaded.append(" ".join(words)))
        return page, loaded

    return _make


@pytest.fixture
def keypad(page_cls, mocker):
    """Answer every keypad capture with a PIN."""
    return mocker.patch.object(page_cls, "capture_from_keypad", return_value="123456")


@pytest.fixture
def errors(page_cls, mocker):
    """Everything the page flashed at the user as an error, in order."""
    collected = []
    mocker.patch.object(
        page_cls, "flash_error", side_effect=lambda t: collected.append(t)
    )
    return collected


@pytest.fixture
def messages(page_cls, mocker):
    """Everything the page flashed at the user, error or not, in order."""
    collected = []
    mocker.patch.object(
        page_cls, "flash_text", side_effect=lambda t, **k: collected.append(t)
    )
    mocker.patch.object(
        page_cls, "flash_error", side_effect=lambda t, **k: collected.append(t)
    )
    mocker.patch.object(
        page_cls, "flash_success", side_effect=lambda t, **k: collected.append(t)
    )
    return collected


@pytest.fixture
def wallet(m5stickv):
    from embit.networks import NETWORKS
    from krux.key import Key, TYPE_SINGLESIG
    from krux.wallet import Wallet

    return Wallet(
        Key(MNEMONIC, TYPE_SINGLESIG, NETWORKS["main"], passphrase=PASSPHRASE)
    )


def store_seed(card, label="savings", passphrase=PASSPHRASE):
    """Put a BIP-39 secret on the fake card the way the save flow would."""
    from embit.bip39 import mnemonic_to_bytes, mnemonic_to_seed
    from krux.seedkeeper import make_header, pack_bip39_secret
    import krux.seedkeeper as sk

    secret = pack_bip39_secret(
        mnemonic_to_seed(MNEMONIC, passphrase),
        mnemonic_to_bytes(MNEMONIC),
        passphrase,
    )
    sk.SeedKeeper(card).import_secret(
        make_header(sk.TYPE_MASTERSEED, label, subtype=sk.SUBTYPE_BIP39), secret
    )
    return secret


def export_seed(card, secret_id=1):
    """Read a secret back off the fake card."""
    import krux.seedkeeper as sk

    return sk.SeedKeeper(card).export_secret(secret_id)


def backup_labels(mocker, ctx):
    """The labels Backup Mnemonic offers, without entering its menus."""
    from krux.pages.home_pages.mnemonic_backup import MnemonicsView

    menu = mocker.patch("krux.pages.home_pages.mnemonic_backup.Menu")
    MnemonicsView(ctx).mnemonic()
    return [item[0] for item in menu.call_args.args[1]]


class TestNoReader:
    def test_the_login_menu_leaves_the_item_out(self, no_reader, m5stickv, mocker):
        # An item that could only ever report "no card reader" is worse than
        # no item: it promises a feature the hardware does not have.
        from krux.pages.login import Login

        ctx = create_ctx(mocker, (1,))
        labels = [item[0] for item in Login(ctx).menu.menu]
        assert "SeedKeeper Card" not in labels

    def test_the_backup_menu_leaves_the_item_out_too(
        self, no_reader, m5stickv, mocker, wallet
    ):
        ctx = create_ctx(mocker, (1,), wallet=wallet)
        assert "SeedKeeper Card" not in backup_labels(mocker, ctx)

    def test_saying_so_when_it_is_reached_anyway(self, no_reader, make_page, errors):
        page, loaded = make_page()
        assert page.load_seed() == 0
        assert errors == ["No card reader"]
        assert loaded == []


class TestMenuContents:
    def test_before_a_wallet_the_page_offers_to_read(self, reader, make_page):
        page, _ = make_page()
        labels = [item[0] for item in page.menu.menu]
        assert "Load Seed from Card" in labels
        assert "Save Seed to Card" not in labels

    def test_with_a_wallet_the_page_offers_to_write(self, reader, make_page, wallet):
        page, _ = make_page(wallet=wallet)
        labels = [item[0] for item in page.menu.menu]
        assert "Save Seed to Card" in labels
        assert "Load Seed from Card" not in labels

    def test_reading_is_offered_where_the_backup_menu_is(
        self, reader, m5stickv, mocker, wallet
    ):
        ctx = create_ctx(mocker, (1,), wallet=wallet)
        assert "SeedKeeper Card" in backup_labels(mocker, ctx)


class TestLoadSeed:
    def test_a_card_with_no_applet_says_so_rather_than_quoting_a_status_word(
        self, reader, make_page, keypad, errors
    ):
        # A blank JavaCard answers SELECT by AID with 6A82. It is the one
        # failure here with a documented remedy, so it gets said in words.
        reader.has_applet = False
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["No SeedKeeper applet\nInstall it first."]
        assert loaded == []

    def test_the_user_is_told_to_tap_before_the_reader_waits(
        self, reader, make_page, keypad
    ):
        # The first command is what makes the reader start looking, and it
        # blocks until the card is tapped. A frozen screen is what the user
        # would otherwise see.
        said = []
        page, _ = make_page()
        page.ctx.display.draw_centered_text = lambda text: said.append(text)
        page.load_seed()
        assert "Tap your SeedKeeper card" in said[0]
        assert "back" in said[0] and "camera" in said[0]

    def test_the_words_reach_the_normal_load_path(self, reader, make_page, keypad):
        store_seed(reader)
        page, loaded = make_page()
        page.load_seed()
        assert loaded == [MNEMONIC]

    def test_a_card_with_no_seeds_says_so(self, reader, make_page, keypad, errors):
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["No seeds on card"]
        assert loaded == []

    def test_a_wrong_pin_is_reported_with_the_tries_left(
        self, reader, make_page, keypad, errors
    ):
        # The card blocks itself after a few tries; how many are left is the
        # difference between a typo and a card that now needs its PUK.
        reader.pin = "999999"
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["Card error\nPIN is incorrect, 2 tries left"]
        assert loaded == []

    def test_a_blank_card_is_set_up_before_use(self, reader, make_page, keypad):
        # Fill the card first, then present it blank: a factory-fresh card has
        # nothing on it to load, and the point here is the setup itself.
        store_seed(reader, passphrase="")
        reader.setup_done = False
        keypad.side_effect = ["4321", "4321"]
        page, loaded = make_page()
        page.load_seed()
        assert reader.setup_done is True
        assert reader.pin == "4321"
        assert loaded == [MNEMONIC]

    def test_mismatched_setup_pins_are_re_asked(
        self, reader, make_page, keypad, errors
    ):
        reader.setup_done = False
        keypad.side_effect = ["4321", "9999", "4321", "4321"]
        page, loaded = make_page()
        page.load_seed()
        assert "PINs did not match" in errors
        assert reader.pin == "4321"

    def test_a_pin_the_card_could_not_store_never_reaches_the_card(
        self, reader, make_page, keypad, errors
    ):
        # Spending one of the card's few attempts on a PIN it could never
        # have accepted would be a self-inflicted lockout.
        keypad.side_effect = ["123", "123", "123456"]
        page, loaded = make_page()
        page.load_seed()
        assert errors.count("PIN must be 4 to 16 characters") == 2
        # Reached the card at last, on a card that is empty
        assert errors[-1] == "No seeds on card"

    def test_a_card_whose_seed_does_not_match_its_words_is_refused(
        self, reader, sk, make_page, keypad, errors
    ):
        secret = [len(MASTER_SEED)] + list(MASTER_SEED) + [0x00]
        secret += [len(ENTROPY)] + list(ENTROPY) + [0]
        sk.SeedKeeper(reader).import_secret(
            sk.make_header(sk.TYPE_MASTERSEED, "bad", subtype=sk.SUBTYPE_BIP39),
            secret,
        )
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["Card secret does not match its seed"]
        assert loaded == []

    def test_a_stored_passphrase_is_reported_rather_than_silently_dropped(
        self, reader, make_page, keypad, errors
    ):
        # The load path asks for the passphrase separately, so the words load
        # without it. Dropping it silently would read as data loss.
        store_seed(reader, passphrase="hunter2")
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["Card holds a passphrase.\nSet it after loading."]
        assert loaded == [MNEMONIC]

    def test_a_v1_card_secret_still_loads(self, reader, sk, make_page, keypad, errors):
        words = MNEMONIC.encode("utf-8")
        # A v1 applet files the mnemonic under its own secret type
        reader.default_type = sk.TYPE_BIP39_MNEMONIC
        sk.SeedKeeper(reader).import_secret(
            sk.make_header(sk.TYPE_BIP39_MNEMONIC, "legacy"),
            [len(words)] + list(words) + [0],
        )
        page, loaded = make_page()
        page.load_seed()
        assert errors == []
        assert loaded == [MNEMONIC]

    def test_secrets_that_are_not_seeds_are_not_offered(
        self, reader, sk, make_page, keypad, errors
    ):
        sk.SeedKeeper(reader).import_secret(
            sk.make_header(sk.TYPE_PASSWORD, "a note"), [4] + list(b"note")
        )
        page, loaded = make_page()
        page.load_seed()
        assert errors == ["No seeds on card"]
        assert loaded == []

    def test_a_second_secret_makes_the_page_ask_which(
        self, reader, make_page, keypad, m5stickv, mocker
    ):
        store_seed(reader, label="cold")
        store_seed(reader, label="hot")
        page, loaded = make_page()
        # The picker is a menu: it stops for the user to choose rather than
        # guessing which of two seeds was meant.
        mocker.patch.object(type(page), "_select_secret", side_effect=lambda h: h[1])
        page.load_seed()
        assert loaded == [MNEMONIC]

    def test_the_type_byte_the_applet_assigns_is_not_relied_on(
        self, reader, sk, make_page, keypad
    ):
        # The client never sends a secret's type, so the applet picks it. A
        # v2 BIP-39 secret is found by its subtype, which the client does
        # send, so whatever type the applet files it under still loads.
        reader.default_type = 0xC0  # Data
        store_seed(reader)
        page, loaded = make_page()
        page.load_seed()
        assert loaded == [MNEMONIC]


class TestSaveSeed:
    def test_the_seed_reaches_the_card_with_its_passphrase(
        self, reader, sk, make_page, keypad, wallet
    ):
        from embit.bip39 import mnemonic_to_bytes, mnemonic_to_seed

        keypad.side_effect = ["savings", "123456"]
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        header, secret = export_seed(reader)
        assert header["label"] == "savings"
        assert header["subtype"] == 1
        entropy, passphrase = sk.unpack_bip39_secret(secret)
        assert entropy == mnemonic_to_bytes(MNEMONIC)
        assert passphrase == PASSPHRASE
        assert list(secret[1 : 1 + secret[0]]) == list(
            mnemonic_to_seed(MNEMONIC, PASSPHRASE)
        )

    def test_what_it_writes_can_be_loaded_back(self, reader, make_page, keypad, wallet):
        # The round trip is the feature: save, then read through the same
        # screen a user would.
        keypad.side_effect = ["savings", "123456", "123456"]
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        import krux.seedkeeper as sk

        sk.SeedKeeper(reader).verify_pin("123456")
        loader, loaded = make_page()
        loader.load_seed()
        assert loaded == [MNEMONIC]

    def test_the_label_defaults_to_the_fingerprint(
        self, reader, make_page, keypad, wallet
    ):
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        # The label is asked for first, before the card is presented.
        assert keypad.call_args_list[0].kwargs[
            "starting_buffer"
        ] == wallet.key.fingerprint_hex_str(False)

    def test_an_empty_label_is_re_asked(
        self, reader, make_page, keypad, wallet, errors
    ):
        keypad.side_effect = ["", "  ", "savings", "123456"]
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        assert errors.count("Label cannot be empty") == 2
        assert export_seed(reader)[0]["label"] == "savings"

    def test_a_label_the_card_cannot_hold_is_re_asked(
        self, reader, make_page, keypad, wallet, errors
    ):
        keypad.side_effect = ["x" * 65, "savings", "123456"]
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        assert errors == ["Label too long (max 64)"]
        assert export_seed(reader)[0]["label"] == "savings"

    def test_a_full_card_is_refused_before_anything_is_written(
        self, reader, make_page, keypad, wallet, errors
    ):
        reader.free_memory = 4
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        assert len(errors) == 1
        assert errors[0].startswith("Card error\nNot enough space")
        assert reader.secrets == {}

    def test_an_applet_that_cannot_report_its_room_still_gets_the_write(
        self, reader, make_page, keypad, wallet
    ):
        # Older applets answer 0x6D00 to the status instruction. Reading that
        # as "no room" would make saving impossible on every one of them.
        reader.status_unsupported = True
        page, _ = make_page(wallet=wallet)
        page.save_seed()
        assert len(reader.secrets) == 1


class TestInspection:
    def test_free_space_reports_the_cards_own_numbers(
        self, reader, sk, make_page, keypad, messages
    ):
        page, _ = make_page()
        page.free_space()
        status = sk.SeedKeeper(reader).memory_status()
        assert messages[0].splitlines()[0] == "Free Space"
        assert "%s bytes" % status["free_memory"] in messages[0]
        assert "%s bytes" % status["total_memory"] in messages[0]
        assert "0 secrets" in messages[0]

    def test_card_info_names_the_protocol_and_applet(
        self, reader, make_page, keypad, messages
    ):
        page, _ = make_page()
        page.card_info()
        assert "Card Info" in messages[0]
        assert "Protocol 0.2" in messages[0]

    def test_viewing_secrets_names_each_one(self, reader, make_page, keypad, messages):
        store_seed(reader, label="cold")
        store_seed(reader, label="hot")
        page, _ = make_page()
        page.view_secrets()
        assert "cold" in messages[0] and "Master Seed" in messages[0]
        assert "hot" in messages[1]

    def test_an_empty_card_says_it_holds_nothing(
        self, reader, make_page, keypad, errors
    ):
        page, _ = make_page()
        page.view_secrets()
        assert errors == ["No secrets on card"]

    def test_deleting_needs_the_user_to_say_so(
        self, reader, page_cls, make_page, keypad, wallet, mocker
    ):
        store_seed(reader)
        page, _ = make_page(wallet=wallet)
        mocker.patch.object(page_cls, "prompt", return_value=False)
        page.delete_secret()
        assert len(reader.secrets) == 1

    def test_deleting_frees_the_secret(
        self, reader, page_cls, make_page, keypad, wallet, mocker, messages
    ):
        store_seed(reader)
        page, _ = make_page(wallet=wallet)
        mocker.patch.object(page_cls, "prompt", return_value=True)
        page.delete_secret()
        assert reader.secrets == {}
        assert "Secret deleted" in messages

    def test_deleting_something_already_gone_says_so(
        self, reader, page_cls, make_page, keypad, wallet, mocker, messages
    ):
        # A listing can name a secret the card no longer has, if it was
        # written elsewhere or the card was reset in between.
        store_seed(reader, label="ghost")
        page, _ = make_page(wallet=wallet)
        mocker.patch.object(page_cls, "prompt", return_value=True)
        mocker.patch.object(
            page_cls, "_select_secret", return_value={"id": 42, "label": "ghost"}
        )
        page.delete_secret()
        assert "Secret not found" in messages
