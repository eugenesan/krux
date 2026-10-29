"""
The buttons, on Linux -- the port's replacement for the K210's GPIO
buttons.

The K210 boards have three buttons (enter, page and page previous)
wired to GPIOs, and the firmware reads them through interrupts.  The
hammerhead has no such buttons: what it has are the *phone's* keys --
the power key and the two volume keys -- and they are ordinary input
devices.

The mapping:

    enter        the power key
    page         the volume up key
    page_prev    the volume down key

The API is the one the firmware uses (``value()`` and ``event()``),
and so are the constants, so ``krux.input`` does not have to know
that the hardware is different.

THE CONSTANTS ARE UPSTREAM'S
----------------------------

Upstream's ``krux/buttons.py`` says::

    PRESSED = 0
    RELEASED = 1

because a K210 button is a GPIO that reads 1 when it is *up*: the
firmware's ``value()`` returns the level, not a "is it down" flag.
``krux.input`` compares that value with ``PRESSED`` all over the
place -- the button integrity check, ``wait_for_release()``, the
long-press detection -- so the numbers have to mean the same thing
here.

This module had them the other way round (``PRESSED = 1``,
``RELEASED = 0``), which broke the firmware in a way that was very
hard to see: the touch screen's ``value()`` returns 1 when the
finger is *up* (the touch module's own convention, which upstream
also uses), so the integrity check in ``krux.input`` read

    if self.touch and self.touch_value() == PRESSED:

as true on a screen nobody had touched, and the firmware turned the
touch screen off for good at start-up.  The constants are therefore
upstream's, and ``_Key`` reports the key's level the same way a
GPIO would.
"""

import time

import evdev
import lcd

import board

PRESSED = 0
RELEASED = 1


class Button:
    """Generic button handler format"""

    def __init__(self) -> None:
        pass

    def value(self):
        """Returns IO state"""
        return RELEASED

    def event(self):
        """Returns event state"""
        return False


class _Key:
    """One key of the phone, read from an input device."""

    def __init__(self, path, code):
        self.fd = evdev.open(path)
        self.code = code
        # the key's level, the way a GPIO would report it: 1 when the
        # key is up, 0 when it is down
        self.state = RELEASED
        self.event_flag = False

    def _poll(self):
        while True:
            event = evdev.read(self.fd, 0)
            if event is None:
                break
            etype, ecode, value = event
            if etype == evdev.EV_KEY and ecode == self.code:
                if value:
                    # the key was pressed
                    self.state = PRESSED
                    self.event_flag = True
                else:
                    # the key was released
                    self.state = RELEASED
        # The page has been drawn and the firmware is now waiting for a
        # key: this is where the page ends, so this is where the display
        # is told to show it.
        #
        # The panel scans a copy of the framebuffer that the driver
        # makes when the display is committed, and the commit costs a
        # frame (it waits for the vertical blank).  Committing after
        # every drawing primitive therefore made a redraw take a third
        # of a second, and showed every half-drawn frame in turn --
        # "the redraw is slow and flickers the whole screen".
        # the idle time is counted here: this is where the firmware
        # waits for a key
        try:
            auto_shutdown.tick()
        except Exception:  # pylint: disable=W0703
            pass
        lcd.flush()

    def value(self):
        self._poll()
        return self.state

    def event(self):
        self._poll()
        if self.event_flag:
            self.event_flag = False
            return True
        return False


class _Keys:
    """The phone's keys, opened once.

    A board may expose fewer than the phone's three keys (the upstream test
    boards are one example), so a missing pin simply means that key is not
    present rather than an import-time failure.
    """

    def __init__(self):
        pins = board.config["krux"]["pins"]

        def open_key(name, code):
            path = pins.get(name)
            return _Key(path, code) if path is not None else None

        self.enter = open_key("BUTTON_A", evdev.KEY_POWER)
        self.page = open_key("BUTTON_B", evdev.KEY_VOLUME_DOWN)
        self.page_prev = open_key("BUTTON_C", evdev.KEY_VOLUME_UP)


buttons_control = _Keys()


class ButtonEnter:
    """Class to manage button ENTER state and events"""

    def __init__(self, pin) -> None:
        self.pin = pin

    def value(self):
        """Returns the ENTER IO state"""
        return buttons_control.enter.value()

    def event(self):
        """Returns the ENTER event state"""
        return buttons_control.enter.event()


class ButtonPage:
    """Class to manage button PAGE state and events"""

    def __init__(self, pin) -> None:
        self.pin = pin

    def value(self):
        """Returns the PAGE IO state"""
        return buttons_control.page.value()

    def event(self):
        """Returns the PAGE event state"""
        return buttons_control.page.event()


class ButtonPagePrev:
    """Class to manage button PAGE PREV state and events"""

    def __init__(self, pin) -> None:
        self.pin = pin

    def value(self):
        """Returns the PAGE PREV IO state"""
        return buttons_control.page_prev.value()

    def event(self):
        """Returns the PAGE PREV event state"""
        return buttons_control.page_prev.event()
