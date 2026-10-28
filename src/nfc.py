"""
nfc -- the NFC transport for the Nexus 5 (hammerhead) port of Krux.

Krux's firmware needs a card transport: ``nfc.transport()`` has to
hand back an object with ``connect(timeout_ms)``, ``is_connected()``,
``transmit(apdu) -> (bytes, sw1, sw2)`` and ``close()`` (the contract
the phone app's mocks/nfc.py defines).

The chip is a Broadcom BCM20793.  It is reached through
/dev/bcm2079x -- a small misc device with seven ioctls -- because the
kernel's bcm2079x driver owns the chip's I2C address and the chip
NACKs anyone else.  The low-level half of that (open, power, wake,
read, write) is the port's own C module ``_nfc``; this module speaks
the chip's protocol on top of it.

The bring-up below is not guessed: it is the sequence the *vendor's*
HAL sends, captured by logging every packet that goes through the
kernel's bcm2079x driver while the ROM's NFC framework runs on our
kernel (see standalone/nfc/TRANSPORT.md and standalone/cam/STATE.md).

    chip -> 10 60 00 02 00 01        Core Reset notification
    ->    10 2f 04 00                GET_BUILD_INFO
    ->    10 2f 2d 00                GET_PATCH_VERSION
    ->    10 20 00 01 01             CORE_RESET
    ->    10 20 01 00                CORE_INIT
    ->    10 20 02 39 01 b9 36 ...   SET_CONFIG (LPTD)
    ->    10 20 02 66 0c cb 01 ...   SET_CONFIG (start-up + antenna)
    ->    10 20 02 06 01 b7 03 ...   SET_CONFIG (the poll configuration)
    ->    10 21 00 07 02 04 03 ...   DISCOVER

The chip's firmware is already in place (it answers GET_BUILD_INFO
right after a power cycle), so no firmware download is needed.
"""

import _nfc
import time

# --- the NCI framing ---------------------------------------------------
#
# byte 0: the HCIT packet type (0x10 = NFC)
# byte 1: MT | PBF | GID
# byte 2: the OID
# byte 3: the payload length
# byte 4+: the payload

HCIT_NFC = 0x10
MT_CMD = 0x20
MT_RSP = 0x40
MT_NTF = 0x60
GID_CORE = 0x00
GID_RF = 0x01
GID_PROP = 0x0F

# the message types we send
CORE_RESET = 0x00
CORE_INIT = 0x01
CORE_SET_CONFIG = 0x02
CORE_SET_CLK = 0x03
# GID_RF OIDs.  The names follow the NCI 1.0 table; the captured
# vendor trace uses exactly these numbers:
#   0x00 RF_DISCOVER_MAP      one mapping per protocol
#   0x01 RF_SET_ROUTING      which NFCEE gets which protocol
#   0x03 RF_DISCOVER         configure + (re)start polling
#   0x04 RF_DISCOVER_SELECT  choose one discovered tag
#   0x05 RF_INTF_ACTIVATED_NTF
#   0x06 RF_DEACTIVATE       stop polling
RF_DISCOVER_MAP = 0x00
RF_SET_ROUTING = 0x01
RF_DISCOVER = 0x03
RF_DISCOVER_SELECT = 0x04
RF_INTF_ACTIVATED_NTF = 0x05
RF_DEACTIVATE = 0x06
# This chip reports "a tag is there" as an OID-0x06 notification with
# a 0x02 first payload byte; the vendor trace shows it right before
# the RF_DISCOVER_SELECT below.  (NCI 1.0 calls that OID the
# deactivate one; the chip is from 2012 and the trace is the
# reference, not the spec.)
RF_TAG_NTF = 0x06
MT_DATA = 0x00
PROP_GET_BUILD_INFO = 0x04
PROP_GET_PATCH_VERSION = 0x2D

# --- the configuration the ROM's HAL sends ------------------------------
#
# These are the *payloads* of the vendor's commands, taken straight
# out of the trace the kernel logged while the ROM's NFC framework
# ran (the kernel logs every packet that goes through the bcm2079x
# driver).  They are replayed verbatim: the chip is known to accept
# exactly these.
#
# Every one of them is counted in bytes, and two were wrong on the
# first try: the LPTD one was three bytes short and the routing one
# was missing its first byte.  The chip accepted both and then never
# polled -- so the counts come from the trace, not from typing them.
#
# The first byte of a SET_CONFIG payload is the number of parameters
# that follow.

SET_CONFIG_LPTD = bytes.fromhex(
    "01 b9 36 01 00 ff ff 08 00 00 00 a0 0f 40 00 00 12 02 10 00 00 00 2d 0b 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 00 d0 07 00 00 08 07 00 00 c8 00 00 00 00 00 00 00")

SET_CONFIG_START_UP = bytes.fromhex(
    "0c cb 01 01 a5 01 01 ca 17 00 00 00 00 06 00 00 00 00 0f 00 00 00 00 e0 67 35 00 14 01 00 00 10 b5 03 01 02 ff 80 01 01 c9 03 03 0f ab 5b 01 00 b2 04 e8 03 00 00 cf 02 02 08 b1 06 00 20 00 00 00 12 c2 02 00 c8 c8 1e 06 3f 00 0a 03 30 00 04 24 00 1c 00 75 00 77 00 76 00 1c 00 03 00 0a 00 4c 01 00 00 40 04")

SET_CONFIG_POLL = bytes.fromhex(
    "01 b7 03 02 00 01")

SET_CONFIG_RF = bytes.fromhex(
    "02 51 08 01 fe ff ff ff ff ff ff 58 01 70")

# the parameters the vendor sets one by one
SET_CONFIG_19 = bytes.fromhex("01 19 01 01")
SET_CONFIG_80 = bytes.fromhex("01 80 01 01")
SET_CONFIG_POLL_PARAMS = bytes.fromhex(
    "05 30 01 04 31 01 00 32 01 20 38 01 00 50 01 00")
SET_CONFIG_00 = bytes.fromhex("01 00 02 f4 01")

# the chip's own clock
SET_CLK = bytes.fromhex("01 52")

# the proprietary commands the HAL makes
PROP_0C = bytes.fromhex("00")
PROP_06 = bytes.fromhex("01")

# the routing (GID_RF, OID 1)
RF_ROUTING = bytes.fromhex(
    "00 04 01 03 00 01 03 01 03 00 01 04 00 03 00 01 00 00 03 00 01 02")

# the discovery mapping the HAL sets up (GID_RF, OID 0): two mappings,
# ISO-DEP (0x04) and NFC-DEP (0x05), both in poll mode (0x03)
DISCOVER_MAP_PARAMS = bytes.fromhex("02 04 03 02 05 03 03")

# the discovery configuration (GID_RF, OID 3): seven poll
# configurations, with the vendor's proprietary 0x74/0x77 ones
DISCOVER_PARAMS = bytes.fromhex(
    "07 00 01 01 01 02 01 80 01 06 01 74 01 77 01")

# the ISO-DEP selection request (GID_RF, OID 4): discovery id 1,
# protocol 4 (ISO-DEP), interface 2 (ISO-DEP)
SELECT_PARAMS = bytes.fromhex("01 04 02")


# The wake line.  The HAL deasserts it at power-on (that is what
# NFC_WAKE_ASSERTED_ON_POR says) and asserts it again while the
# framework wants the chip to work.
WAKE_WHEN_POLLING = 1

# How often the discovery is restarted while we wait for a card.  The
# chip polls in cycles, so a card that appears between two of them is
# only seen at the next one.
DISCOVER_INTERVAL_MS = 1000

# how long one polling cycle waits for a card, in milliseconds
POLL_WINDOW_MS = 8000

# how long the chip is given to settle after the power-on, in seconds
# (time.sleep() takes seconds, not milliseconds)
SETTLE_S = 0.3

# set to 1 to print every packet that goes to and from the chip
DEBUG = 1


def _dbg(what, data):
    if DEBUG:
        print("  [%s] %s" % (what, " ".join("%02x" % c for c in data)))


class NfcError(Exception):
    """The chip said no."""


class CardTimeout(Exception):
    """No card was tapped within the timeout."""


def _hexs(b):
    return " ".join("%02x" % c for c in b)


class Chip:
    """The chip itself: the node, the power line and the packets."""

    def __init__(self):
        self.fd = None

    # -- the node ---------------------------------------------------------

    def open(self):
        self.fd = _nfc.open()
        return self

    def close(self):
        if self.fd is not None:
            try:
                _nfc.power(self.fd, 0)
            except OSError:
                pass
            _nfc.close(self.fd)
            self.fd = None

    def wake(self, state):
        """The host's wake line (1 = asserted)."""
        _nfc.wake(self.fd, state)

    def power_cycle(self):
        """The reset sequence the HAL does.

        The kernel log of the vendor's own HAL shows:

            WAKE_CTL 0 -> POWER_CTL 0 -> POWER_CTL 1 -> WAKE_CTL 0 -> WAKE_CTL 1

        so the wake line is deasserted again after the power comes back
        on, and only then asserted for real.
        """
        _nfc.wake(self.fd, 0)
        _nfc.power(self.fd, 0)
        time.sleep(0.01)
        _nfc.power(self.fd, 1)
        _nfc.wake(self.fd, 0)

    # -- the packets ------------------------------------------------------

    def read(self, timeout_ms=2000):
        """One whole packet, or None if none arrived."""
        return _nfc.read(self.fd, timeout_ms)

    def write(self, data):
        return _nfc.write(self.fd, data)

    def send(self, mt, gid, oid, payload=b""):
        """Send one command and return the packet that answers it."""
        pkt = bytes([HCIT_NFC, mt | gid, oid, len(payload)]) + payload
        _dbg("tx", pkt)
        self.write(pkt)
        # the answer comes back as a response, not as a command
        rsp = self.wait_for(MT_RSP | gid, oid, 2000)
        _dbg("rsp", rsp)
        return rsp

    def wait_for(self, want, oid, timeout_ms=2000):
        """Read until a packet with this message type and OID arrives.

        Notifications that come along the way are collected in
        self.notifications, because the chip interleaves them.
        """
        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        while True:
            left = time.ticks_diff(deadline, time.ticks_ms())
            if left <= 0:
                raise NfcError("timeout waiting for 0x%02x/0x%02x" % (want, oid))
            pkt = self.read(left)
            if pkt is None:
                continue
            if len(pkt) < 4:
                continue
            if pkt[1] == want and pkt[2] == oid:
                return pkt
            self.notifications.append(pkt)

    def wait_ntf(self, oid, timeout_ms=2000):
        """Read until a notification with this OID arrives."""
        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        while True:
            left = time.ticks_diff(deadline, time.ticks_ms())
            if left <= 0:
                return None
            pkt = self.read(left)
            if pkt is None or len(pkt) < 4:
                continue
            if pkt[1] & 0xE0 == MT_NTF and pkt[2] == oid:
                return pkt
            self.notifications.append(pkt)


class IsoDepTransport:
    """One SeedKeeper, reached over ISO-DEP on a tapped card.

    The contract is the phone app's mocks/nfc.py: connect, is_connected,
    transmit, close.
    """

    TAG_TIMEOUT_MS = 30000

    def __init__(self):
        self.chip = None
        self.connected = False
        self.cid = None

    # -- the plumbing -----------------------------------------------------

    def _bring_up(self):
        """Everything the HAL does before it starts polling."""
        chip = self.chip
        chip.notifications = []

        # the reset: the chip announces itself right after
        chip.power_cycle()
        # The wake line has to be asserted *before* the configuration:
        # with it deasserted the chip stays asleep and answers nothing.
        # (On Android the framework does this when the screen comes on,
        # which is why the chip is quiet with the screen off.)
        chip.wake(WAKE_WHEN_POLLING)
        ntf = chip.read(5000)
        if ntf is None:
            raise NfcError("the chip did not announce itself")
        # the chip needs a moment: it does its field calibration here
        time.sleep(SETTLE_S)
        chip.notifications.append(ntf)

        # GET_BUILD_INFO and GET_PATCH_VERSION: the HAL asks, so we ask.
        # (The answers are the chip's version string; nothing depends on
        # them yet, but they are part of the sequence the chip expects.)
        chip.send(MT_CMD, GID_PROP, PROP_GET_BUILD_INFO)
        chip.send(MT_CMD, GID_PROP, PROP_GET_PATCH_VERSION)

        # CORE_RESET, then CORE_INIT
        rsp = chip.send(MT_CMD, GID_CORE, CORE_RESET, bytes([0x01]))
        if rsp[4] != 0:
            raise NfcError("CORE_RESET failed")
        rsp = chip.send(MT_CMD, GID_CORE, CORE_INIT)
        if rsp[4] != 0:
            raise NfcError("CORE_INIT failed")

        # the configurations, in the order the HAL sends them
        for cfg in (SET_CONFIG_LPTD, SET_CONFIG_START_UP, SET_CONFIG_POLL):
            rsp = chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, cfg)
            if rsp[4] != 0:
                raise NfcError("SET_CONFIG failed")

        # a proprietary command the HAL makes after the poll configuration
        chip.send(MT_CMD, GID_PROP, 0x06, PROP_06)

        # The map does not start a poll cycle, it only says which
        # protocol goes on which interface; the discover below starts
        # the polling.
        rsp = chip.send(MT_CMD, GID_RF, RF_DISCOVER_MAP, DISCOVER_MAP_PARAMS)
        if rsp[4] != 0:
            raise NfcError("DISCOVER_MAP failed")

        # the RF parameters and the chip's own clock
        chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, SET_CONFIG_RF)
        chip.send(MT_CMD, GID_CORE, CORE_SET_CLK, SET_CLK)
        chip.send(MT_CMD, GID_PROP, 0x0C, PROP_0C)

        # the routing and the protocol numbers
        chip.send(MT_CMD, GID_RF, RF_SET_ROUTING, RF_ROUTING)
        chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, SET_CONFIG_19)
        chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, SET_CONFIG_80)
        chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, SET_CONFIG_POLL_PARAMS)
        chip.send(MT_CMD, GID_CORE, CORE_SET_CONFIG, SET_CONFIG_00)
        chip.send(MT_CMD, GID_RF, RF_DISCOVER, DISCOVER_PARAMS)
        chip.send(MT_CMD, GID_RF, RF_DEACTIVATE, bytes([0x00]))

        # And then the routing and the protocol numbers *again*: the
        # vendor's stack sends them a second time, after the
        # deactivate, and the chip only finds a tag after that.  (The
        # trace of the ROM's own stack shows the tag notification
        # right after these two commands and not before.)
        chip.send(MT_CMD, GID_RF, RF_SET_ROUTING, RF_ROUTING)
        chip.send(MT_CMD, GID_RF, RF_DISCOVER, DISCOVER_PARAMS)

        # whatever the chip said in between
        for n in chip.notifications:
            _dbg("ntf", n)
        chip.notifications = []

    @staticmethod
    def _is_tag(pkt):
        """A notification that says a tag is in the field."""
        if len(pkt) < 4 or pkt[1] & 0xE0 != MT_NTF:
            return False
        if pkt[2] == RF_INTF_ACTIVATED_NTF:
            return True
        # this chip's "tag is there" notification
        return pkt[2] == RF_TAG_NTF and len(pkt) >= 6 and pkt[4] == 0x02

    def _discover(self, timeout_ms):
        """Start polling and wait for a tag.

        The chip polls in cycles.  The vendor's own stack stops the
        poll with RF_DEACTIVATE, re-sends the routing and then the
        discovery configuration, and the tag notification follows
        right after that.  Sending RF_DISCOVER while a poll is still
        running is refused with a semantic error (0x06), so the
        deactivate is not optional.
        """
        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        # The discover that closed the bring-up gets its full window
        # before the first restart: a restart interrupts a poll.
        last_discover = time.ticks_ms()

        while True:
            left = time.ticks_diff(deadline, time.ticks_ms())
            if left <= 0:
                raise CardTimeout("no card within %d ms" % timeout_ms)

            # Notifications that arrived while a command was being
            # sent are buffered by Chip.send(); look at them first.
            while self.chip.notifications:
                ntf = self.chip.notifications.pop(0)
                _dbg("ntf", ntf)
                if self._is_tag(ntf):
                    return ntf

            now = time.ticks_ms()
            if time.ticks_diff(now, last_discover) >= DISCOVER_INTERVAL_MS:
                last_discover = now
                # stop whatever poll is running, then start a fresh
                # one exactly as the vendor's stack does
                self.chip.send(MT_CMD, GID_RF, RF_DEACTIVATE, bytes([0x00]))
                self.chip.send(MT_CMD, GID_RF, RF_SET_ROUTING, RF_ROUTING)
                rsp = self.chip.send(
                    MT_CMD, GID_RF, RF_DISCOVER, DISCOVER_PARAMS
                )
                status = rsp[4]
                # 0x00 ok, 0x09 already started, 0x0a target activated
                if status not in (0x00, 0x09, 0x0A):
                    raise NfcError("DISCOVER failed (0x%02x)" % status)

            pkt = self.chip.read(min(left, 500))
            if pkt is None:
                continue
            _dbg("rx", pkt)
            if self._is_tag(pkt):
                return pkt

    def _activate(self, ntf):
        """Make sure the ISO-DEP tag is activated.

        The chip does it by itself once the routing and the protocol
        numbers are set up -- it then sends the activation
        notification on its own.  If that has not happened yet, ask
        for it: the request is three bytes (the discovery id, 1 =
        ISO-DEP protocol 4, ISO-DEP interface 2).
        """
        if ntf is not None and len(ntf) >= 4 and ntf[2] == RF_INTF_ACTIVATED_NTF:
            return ntf

        rsp = self.chip.send(
            MT_CMD, GID_RF, RF_DISCOVER_SELECT, SELECT_PARAMS
        )
        if rsp[4] != 0:
            raise NfcError("the activation was refused")

        # the activation notification carries the tag's details
        act = self.chip.wait_ntf(RF_INTF_ACTIVATED_NTF, 3000)
        if act is None:
            raise NfcError("no activation notification")
        _dbg("act", act)
        return act

    def _data(self, apdu, timeout_ms=2000):
        """One APDU exchange: the data goes out as an MT_DATA packet."""
        pkt = bytes([HCIT_NFC, MT_DATA, 0x00, len(apdu)]) + apdu
        _dbg("data tx", pkt)
        self.chip.write(pkt)

        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        while True:
            left = time.ticks_diff(deadline, time.ticks_ms())
            if left <= 0:
                raise CardTimeout("the card did not answer")
            pkt = self.chip.read(left)
            if pkt is None or len(pkt) < 4:
                continue
            _dbg("data rx", pkt)
            if pkt[1] == MT_DATA:
                # the payload is the response: the data, then SW1 SW2
                body = pkt[4:]
                if len(body) < 2:
                    raise NfcError("the card's answer is too short")
                return body[:-2], body[-2], body[-1]

    # -- the contract -----------------------------------------------------

    def connect(self, timeout_ms=TAG_TIMEOUT_MS):
        """Bring the chip up, poll, and activate the card that shows up.

        The chip's poll is not always lucky: a card that is in the
        field is seen in some cycles and not in others, so the whole
        cycle is repeated until the timeout runs out.  (On the card
        that was tested here, three cycles went by before the fourth
        one found it.)
        """
        deadline = time.ticks_add(time.ticks_ms(), timeout_ms)
        attempt = 0

        while True:
            left = time.ticks_diff(deadline, time.ticks_ms())
            if left <= 0:
                raise CardTimeout("no card within %d ms" % timeout_ms)

            attempt += 1
            try:
                self.chip = Chip().open()
                self._bring_up()
                ntf = self._discover(min(left, POLL_WINDOW_MS))
                self._activate(ntf)
                self.connected = True
                return self
            except CardTimeout:
                # the chip did not see a card in this cycle: start over
                self.close()
                self.connected = False
                continue

    def is_connected(self):
        return self.connected

    def transmit(self, apdu):
        """Send one APDU; hand back (data, sw1, sw2) unexamined.

        A transport that was never connected connects itself on the first
        command, so a caller that never mentions a card still gets one
        (the mobile app's mock behaves the same way).
        """
        if not self.connected:
            self.connect()
        if not self.connected:
            raise NfcError("not connected")
        return self._data(bytes(apdu))

    def close(self):
        self.connected = False
        if self.chip is not None:
            self.chip.close()
            self.chip = None


def transport():
    """The card transport, or None when there is no card reader."""
    return IsoDepTransport()
