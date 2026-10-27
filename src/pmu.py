"""
pmu -- the power management unit, on the hammerhead.

The K210 boards have a PMU chip (the AXP19x) that the MaixPy `pmu`
module drives: the battery's voltage, whether it is charging, whether
USB is plugged in, the screen's brightness and the sleep mode.

The hammerhead has none of that: the battery and the USB are in the
kernel's power supply class, the display's backlight is a sysfs file,
and "sleep" is the phone's suspend.  So the module is the same API
over different resources.
"""

import os


def _read(path, default=""):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return default


def _power_supply(name, attribute, default=""):
    return _read("/sys/class/power_supply/%s/%s" % (name, attribute), default)


class PMUController:
    """The phone's power: the battery, the USB and the backlight.

    The firmware constructs it with the I2C bus the K210's PMU chip
    is on; there is no such chip here, so the bus is ignored.
    """

    def __init__(self, i2c_bus=None):
        # The level that is on now.  The init stub sets the backlight
        # to half before it starts the firmware, so the level is read
        # out of the driver rather than assumed: assuming the maximum
        # would make the screen blaze the moment the firmware turned
        # the backlight back on.
        self._brightness = self._read_brightness_level()

    def _read_brightness_level(self):
        """The backlight's level, from 0 to 8, as the driver has it"""
        base = "/sys/class/backlight/lm3630"
        maximum = _read(base + "/max_brightness", "255")
        value = _read(base + "/brightness", "")
        try:
            maximum = int(maximum)
            value = int(value)
        except ValueError:
            return 8
        if maximum <= 0:
            return 8
        level = (value * 8 + maximum // 2) // maximum
        if level < 0:
            level = 0
        if level > 8:
            level = 8
        return level


    # -- the battery -----------------------------------------------------

    def get_battery_voltage(self):
        """The battery's voltage, in millivolts."""
        value = _power_supply("battery", "voltage_now", "")
        if not value:
            return 0
        try:
            return int(value) // 1000
        except ValueError:
            return 0

    def get_battery_capacity(self):
        """The battery's charge, in percent."""
        value = _power_supply("battery", "capacity", "")
        try:
            return int(value)
        except ValueError:
            return 0

    def charging(self):
        """Is the battery charging?"""
        return _power_supply("battery", "status", "") == "Charging"

    def usb_connected(self):
        """Is USB plugged in?"""
        online = _power_supply("usb", "online", "")
        if online == "1":
            return True
        # some kernels name the supply differently
        for name in ("usb", "ac", "mains", "wireless"):
            if _power_supply(name, "online", "") == "1":
                return True
        return False

    # -- the display's backlight -----------------------------------------

    def set_screen_brightness(self, value):
        """The screen's brightness.

        The value is the one the firmware's power_manager passes: the
        firmware's own scale is 0 to 8, and it adds 7 to it before it
        gets here, because the K210's PMU register only counts from 7
        (7 is off, 15 is full).  So the number that arrives is 7 to 15
        and the level is that minus 7.

        Getting this wrong is not a small thing: with the level taken
        as it was, every level was above 8 and was clamped to 8, so
        the backlight was pinned at the maximum and the setting did
        nothing at all.
        """
        try:
            value = int(value)
        except (TypeError, ValueError):
            return
        # the firmware's 0 to 8, after its own +7
        value -= 7
        if value < 0:
            value = 0
        if value > 8:
            value = 8
        self._brightness = value

        # the backlight is a plain file: the maximum is what it says
        base = "/sys/class/backlight/lm3630"
        maximum = _read(base + "/max_brightness", "255")
        try:
            maximum = int(maximum)
        except ValueError:
            maximum = 255
        if maximum <= 0:
            return
        try:
            with open(base + "/brightness", "w") as f:
                f.write(str(value * maximum // 8))
        except OSError:
            pass

    def set_backlight_level(self, level):
        """Sets the backlight's level, from 0 to 8.

        This is the port's own way in: the firmware's power_manager
        speaks the K210's scale (7 to 15), and the caller here means
        the level the user sees (0 is off, 8 is full).
        """
        try:
            level = int(level)
        except (TypeError, ValueError):
            return
        if level < 0:
            level = 0
        if level > 8:
            level = 8
        self._brightness = level
        base = "/sys/class/backlight/lm3630"
        maximum = _read(base + "/max_brightness", "255")
        try:
            maximum = int(maximum)
        except ValueError:
            maximum = 255
        if maximum <= 0:
            return
        try:
            with open(base + "/brightness", "w") as f:
                f.write(str(level * maximum // 8))
        except OSError:
            pass

    def get_screen_brightness(self):
        """The screen's brightness, from 0 to 8."""
        return self._brightness

    # -- the rest --------------------------------------------------------

    def enable_adcs(self, enable):
        """The K210's analogue to digital converters: nothing here."""

    def enable_pek_button_monitor(self):
        """The K210's power key monitor: the phone's own keys are read
        from the input devices, so there is nothing to enable."""

    def enter_sleep_mode(self):
        """Suspend the phone."""
        try:
            with open("/sys/power/state", "w") as f:
                f.write("mem")
        except OSError:
            pass


# The name the firmware uses.
PMU = PMUController
