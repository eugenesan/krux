"""
The touch screen, on Linux -- the port's replacement for the K210's
I2C touch controller.

The API is the one the firmware uses (``current_state``, ``event``,
``value``, ``current_index`` and the four ``swipe_*_value`` methods) and
so are the constants, so ``krux.input`` does not have to know that the
hardware is different.

The K210 boards talk to a touch controller over I2C (the cst816, the
gt911 or the ft6x36, depending on the board).  The hammerhead's touch
screen is a plain evdev device: /dev/input/event1, the multitouch
protocol (ABS_MT_*).  The events are read through the port's ``evdev``
module.

The touch controller's coordinates are in the panel's own space; on
this device that is the display's (1080x1920), so they are used as
they are.

THE REGIONS ARE THE MENU'S
--------------------------

The firmware's menu draws one region per item and asks the touch
object which region was hit (``current_index()``).  The upstream
implementation does that with ``x_regions`` and ``y_regions`` -- lists
of boundaries -- and ``_extract_index()`` counts how many of them the
point is past.  An earlier version of this module left all of that
out, so the firmware's calls to ``touch.current_index()`` and
``touch.y_regions`` raised AttributeError, and the menu's touch
handling never worked.  The regions are therefore implemented here,
the way upstream does it.
"""

import time

import evdev
import lcd

import board

from .kboard import kboard
from .auto_shutdown import auto_shutdown
from .krux_settings import Settings

# The debug log is only written when the sentinel file is there, so
# that it costs nothing when the firmware runs on its own.
DEBUG_LOG = "/data/krux/touch.log"
DEBUG_FLAG = "/data/krux/touch.debug"
_debug_on = None


def _debug(message):
    """Appends a line to the debug log, if it is switched on"""
    global _debug_on
    try:
        if _debug_on is None:
            import os

            # MicroPython's os has no path module, so the sentinel
            # file is looked up with stat()
            try:
                os.stat(DEBUG_FLAG)
                _debug_on = True
            except Exception:  # pylint: disable=W0703
                _debug_on = False
        if not _debug_on:
            return
        with open(DEBUG_LOG, "a") as log:
            log.write(message + "\n")
    except Exception:  # pylint: disable=W0703
        pass


IDLE = 0
PRESSED = 1
RELEASED = 2

SWIPE_THRESHOLD = 35
SWIPE_RIGHT = 1
SWIPE_LEFT = 2
SWIPE_UP = 3
SWIPE_DOWN = 4

TOUCH_S_PERIOD = 20  # Touch sample period - Min = 10


class Touch:
    """Touch is a singleton API to interact with touchscreen driver"""

    def __init__(self, width, height, irq_pin=None, res_pin=None):
        self.width = width
        self.height = height
        self.state = IDLE
        self.gesture = None
        self.press_point = []
        self.release_point = None
        self.sample_time = time.ticks_ms()

        self.x = 0
        self.y = 0
        self.tracking = -1
        self.new_touch = False
        self.index = 0

        # the menu's regions, in the firmware's terms: the boundaries
        # of the touch areas, in the display's pixels
        self.x_regions = []
        self.y_regions = []

        self.fd = evdev.open(board.config["krux"]["pins"]["TOUCH_IRQ"])
        # the firmware's settings page calls touch.touch_driver.threshold(...);
        # there is no hardware threshold on this port, so provide a no-op
        self.touch_driver = self
        _debug("Touch created on %s" % board.config["krux"]["pins"]["TOUCH_IRQ"])

    def threshold(self, value):
        # no-op: evdev has no hardware threshold
        return

    # ------------------------------------------------------------------
    # the regions the menu draws its items in

    def clear_regions(self):
        """Clears the region delimiters"""
        self.x_regions = []
        self.y_regions = []

    def add_y_delimiter(self, region):
        """Adds a y delimiter to the touch region"""
        if region > self.width:
            raise ValueError("Touch region added outside display area")
        self.y_regions.append(region)

    def add_x_delimiter(self, region):
        """Adds an x delimiter to the touch region"""
        if region > self.height:
            raise ValueError("Touch region added outside display area")
        self.x_regions.append(region)

    def set_regions(self, x_list=None, y_list=None):
        """Set buttons map regions x and y"""
        if x_list:
            if isinstance(x_list, list):
                self.x_regions = x_list
            else:
                raise ValueError("x_list must be a list")
        else:
            self.x_regions = []

        if y_list:
            if isinstance(y_list, list):
                self.y_regions = y_list
            else:
                raise ValueError("y_list must be a list")
        else:
            self.y_regions = []

    def valid_position(self, data):
        """Checks if the touch position is within the touch areas"""

        if Settings().is_flipped_orientation():
            data = (self.height - data[0], self.width - data[1])

        if self.x_regions and data[0] < self.x_regions[0]:
            return False
        if self.x_regions and data[0] > self.x_regions[-1]:
            return False
        if self.y_regions and data[1] < self.y_regions[0]:
            return False
        if self.y_regions and data[1] > self.y_regions[-1]:
            return False
        return True

    def _extract_index(self, data):
        """Gets an index from the touched point and the delimiters.

        The index is the region the point falls in: how many y
        boundaries it is past, and (if the menu has columns) how many x
        boundaries it is past.
        """
        y_index = 0
        x_index = 0

        for region in self.y_regions:
            if data[1] > region:
                y_index += 1
        y_index -= 1 if y_index > 0 else 0

        if self.x_regions:
            for x_region in self.x_regions:
                if data[0] >= x_region:
                    x_index += 1
            x_index -= 1
            index = y_index * (len(self.x_regions) - 1) + x_index
        else:
            index = y_index

        return index

    def _store_points(self, data):
        """Store the pressed point and work out which region it is in"""

        if Settings().is_flipped_orientation():
            new_y = max(0, self.height - data[0])
            new_y = min(new_y, self.height - 1)
            new_x = max(0, self.width - data[1])
            new_x = min(new_x, self.width - 1)
            data = (new_y, new_x)

        if self.state == IDLE:
            self.state = PRESSED
            self.press_point = [data]
            self.index = self._extract_index(self.press_point[0])
        # an average (max. 10 samples) of the pressed points, to
        # increase the precision
        elif self.state == PRESSED and len(self.press_point) < 10:
            self.press_point.append(data)
            len_press = len(self.press_point)
            x = 0
            y = 0
            for n in range(len_press):
                x += self.press_point[n][0]
                y += self.press_point[n][1]
            x //= len_press
            y //= len_press
            self.index = self._extract_index((x, y))
        self.release_point = data

    # ------------------------------------------------------------------

    def _poll(self):
        """Read the events that are waiting.

        Sets self.new_touch when a *new* touch starts (the equivalent
        of the K210's interrupt).
        """
        while True:
            event = evdev.read(self.fd, 0)
            if event is None:
                break
            etype, code, value = event

            if etype != evdev.EV_ABS:
                continue
            if code == evdev.ABS_MT_POSITION_X:
                self.x = value
            elif code == evdev.ABS_MT_POSITION_Y:
                self.y = value
            elif code == evdev.ABS_MT_TRACKING_ID:
                if value >= 0:
                    if self.tracking < 0:
                        # a finger went down
                        self.new_touch = True
                        _debug("finger down")
                    self.tracking = value
                else:
                    # the finger left the screen
                    self.tracking = -1
                    self.release_point = (self.x, self.y)
                    _debug("finger up")
        # The page has been drawn and the firmware is now waiting for a
        # touch: this is where the page ends, so this is where the
        # display is told to show it.  (See the note in buttons.py.)
        # the idle time is counted here: this is where the firmware
        # waits for a key
        try:
            auto_shutdown.tick()
        except Exception:  # pylint: disable=W0703
            pass
        lcd.flush()
        return self.new_touch

    def current_state(self):
        """Returns the touchscreen state"""
        self.sample_time = time.ticks_ms()
        self._poll()
        previous = self.state

        if self.tracking >= 0:
            self.state = PRESSED
            return self.state

        # the finger is up
        if self.state == PRESSED:
            if self.release_point is not None and self.press_point:
                lateral_length = self.release_point[0] - self.press_point[0][0]
                if lateral_length > SWIPE_THRESHOLD:
                    self.gesture = SWIPE_RIGHT
                elif -lateral_length > SWIPE_THRESHOLD:
                    self.gesture = SWIPE_LEFT
                    lateral_length *= -1  # make the positive value
                vertical_length = self.release_point[1] - self.press_point[0][1]
                if (
                    vertical_length > SWIPE_THRESHOLD
                    and vertical_length > lateral_length
                ):
                    self.gesture = SWIPE_DOWN
                elif (
                    -vertical_length > SWIPE_THRESHOLD
                    and -vertical_length > lateral_length
                ):
                    self.gesture = SWIPE_UP
            self.state = RELEASED
        elif self.state == RELEASED:
            self.state = IDLE
        if self.state != previous:
            _debug("current_state: %d -> %d" % (previous, self.state))
        return self.state

    def event(self, validate_position=True):
        """Checks if a touch happened and stores the point"""
        # The touch is polled by current_state(), which the firmware
        # calls in the same loop iteration; it sets self.new_touch when
        # a finger goes down.  So this must NOT poll on its own and
        # must NOT gate on a sample period: current_state() resets the
        # sample time every time it runs, so a gate here would never
        # open, and the touch would never be seen at all.
        self._poll()
        if self.new_touch:
            self.new_touch = False
            self.state = IDLE
            data = (self.x, self.y)
            if not validate_position:
                self.press_point = [data]
                self.release_point = None
                _debug("event() at %s (unvalidated)" % str(data))
                return True
            if self.valid_position(data):
                self._store_points(data)
                _debug("event() at %s index=%d" % (str(data), self.index))
                return True
            _debug("event() at %s REJECTED by valid_position" % str(data))
        return False

    def value(self):
        """Wraps touch states to behave like a regular button"""
        return 1 if self.current_state() == IDLE else 0

    def swipe_right_value(self):
        """Returns detected gestures and clean respective variable"""
        if self.gesture == SWIPE_RIGHT:
            self.gesture = None
            return 0
        return 1

    def swipe_left_value(self):
        """Returns detected gestures and clean respective variable"""
        if self.gesture == SWIPE_LEFT:
            self.gesture = None
            return 0
        return 1

    def swipe_up_value(self):
        """Returns detected gestures and clean respective variable"""
        if self.gesture == SWIPE_UP:
            self.gesture = None
            return 0
        return 1

    def swipe_down_value(self):
        """Returns detected gestures and clean respective variable"""
        if self.gesture == SWIPE_DOWN:
            self.gesture = None
            return 0
        return 1

    def current_index(self):
        """Returns the index of the currently selected region"""
        return self.index
