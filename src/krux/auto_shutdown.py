"""
auto_shutdown -- the port's version.

The firmware's own auto_shutdown.py counts the seconds of inactivity
with a *hardware* timer (the K210's `machine.Timer`), whose callback
shuts the device down when the timeout is reached.

There is no such timer here, and the port's `machine` module does not
carry one, so the count is done from the clock instead: the deadline
is kept as a tick count, and it is checked whenever the firmware asks
(the input loop calls `feed()` on every event, and the page code calls
`seconds_counter()`).

Everything else -- the settings, the shutdown, the context -- is the
firmware's.

THE BACKLIGHT
-------------

The firmware's screen saver is an *animation* (the logo scrolls), so
it wants the backlight on.  But the phone's panel blanks itself when
the framebuffer is idle, and the backlight is a separate device
(the lm3630): without this the panel goes dark while the backlight
keeps burning the battery, and the user sees a lit black screen.

So the port turns the backlight off when the device has been idle
for a while, and back on at the first sign of life.  The timeout is
a fifth of the shutdown timeout, and it is never longer than a
minute: the point is to save the battery while the device sits on a
table, not to blank the screen the user is reading.

The level that was on is remembered, so a user who had dimmed the
screen gets their own level back.
"""

import time

from .krux_settings import Settings
from .power import power_manager

ONE_SECOND = 1000

# The backlight goes off after this many seconds of inactivity, and
# comes back at the first key or touch.
BACKLIGHT_OFF_AFTER = 30


def seconds_counter(_):
    """The timer callback the firmware uses; the port counts by hand."""
    auto_shutdown.seconds_counter()


class AutoShutdown:
    """Shuts the device down if there is no activity for a while."""

    def __init__(self):
        self.auto_shutdown_timer = None
        self.shutdown_time = 0
        self.time_out = 0
        self.ctx = None
        self.last_tick = time.ticks_ms()
        # the backlight: the level that was on, whether it is off, and
        # the seconds the device has been idle
        self.backlight_level = 0
        self.backlight_off = False
        self.idle = 0
        self.init_timer(Settings().security.auto_shutdown)

    def init_timer(self, value=None):
        """Sets the timeout, in seconds"""
        self.shutdown_time = value * 60
        self.time_out = self.shutdown_time
        self.last_tick = time.ticks_ms()

    def add_ctx(self, ctx):
        """Add a context to the auto_shutdown object"""
        self.ctx = ctx

    def backlight_timeout(self):
        """How long the device may be idle before the backlight goes off"""
        if self.shutdown_time <= 0:
            # the device never shuts down by itself, so the backlight
            # would never go off either: use the fixed timeout
            return BACKLIGHT_OFF_AFTER
        timeout = self.shutdown_time // 5
        if timeout > BACKLIGHT_OFF_AFTER:
            timeout = BACKLIGHT_OFF_AFTER
        if timeout < 1:
            timeout = 1
        return timeout

    def turn_the_backlight_off(self):
        """Turns the backlight off, remembering the level that was on"""
        if self.backlight_off:
            return
        try:
            self.backlight_level = power_manager.pmu.get_screen_brightness()
        except Exception:  # pylint: disable=W0703
            self.backlight_level = 0
        if not self.backlight_level:
            return
        try:
            # the port's own way in: the level, not the K210's scale
            power_manager.pmu.set_backlight_level(0)
            self.backlight_off = True
        except Exception:  # pylint: disable=W0703
            pass

    def turn_the_backlight_on(self):
        """Turns the backlight back on, at the level that was on"""
        if not self.backlight_off:
            return
        try:
            power_manager.pmu.set_backlight_level(self.backlight_level)
        except Exception:  # pylint: disable=W0703
            pass
        self.backlight_off = False

    def tick(self):
        """Counts the idle time.

        The firmware's own auto_shutdown counts the seconds with a
        hardware timer, which this port has not got (the machine
        module's Timer is a stub).  So the count is done from the
        clock, and the clock is read here -- the port's input modules
        call this on every poll, which is where the firmware waits
        for a key and so where the idle time passes.
        """
        self.seconds_counter()

    def seconds_counter(self):
        """Counts the seconds and shuts the device down if threshold is reached"""
        # the port: the seconds that passed since the last check
        now = time.ticks_ms()
        elapsed = time.ticks_diff(now, self.last_tick) // ONE_SECOND
        if elapsed > 0:
            self.last_tick = now
        else:
            return

        # the idle time is counted on its own: the backlight goes off
        # after its own timeout, which has nothing to do with the
        # shutdown timeout (the device may be set never to shut down)
        self.idle += elapsed
        if self.idle >= self.backlight_timeout():
            self.turn_the_backlight_off()

        if self.time_out > 0:
            self.time_out -= elapsed
        elif self.shutdown_time > 0:
            if self.ctx:
                self.ctx.clear()
            # The port does NOT power the device off here.
            #
            # On the K210 this is the "sleep": the firmware calls
            # power_manager.shutdown(), which puts the PMU into its
            # sleep mode (the device wakes up at the next key press)
            # and then resets the board.  Here a reset means a power
            # off, and a powered-off phone is unreachable until
            # somebody presses the power key -- so an idle phone
            # would vanish from the USB bus on its own, which is not
            # what "idle" is supposed to mean.
            #
            # So the port's idle state is the K210's sleep state: the
            # screen is dark, the device is alive, and the first key
            # press or touch brings the backlight back (feed()).
            self.turn_the_backlight_off()

    def feed(self):
        """Feed the auto_shutdown timer"""
        self.seconds_counter()
        self.time_out = self.shutdown_time
        # there is life: the backlight comes back
        self.idle = 0
        self.turn_the_backlight_on()


auto_shutdown = AutoShutdown()  # Singleton
