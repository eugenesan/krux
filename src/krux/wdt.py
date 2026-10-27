"""
wdt -- the watchdog, on the hammerhead.

The firmware's own wdt.py asks MaixPy's `machine.WDT` for a watchdog
and feeds it while it works, so that a hang restarts the board.

The port does not arm the kernel's watchdog (/dev/watchdog) for now:
on Linux, closing the watchdog without the "magic close" *reboots* the
device, and a firmware that exits normally (or is killed) would then
restart the phone instead of coming back to the prompt.  So the port's
watchdog only keeps the bookkeeping: the firmware's flow is unchanged,
nothing is armed.

When it is wanted, the kernel's device is the one to use:

    fd = open("/dev/watchdog", "w")
    fd.write(b"")            # feed
    fd.write(b"V")           # magic close: do not reboot
"""

RESET_TIMEOUT = 30000


class _Watchdog:
    """The watchdog: nothing is armed, but the firmware's flow is the
    same."""

    def __init__(self, timeout=RESET_TIMEOUT):
        self.timeout = timeout
        self.fd = None

    def feed(self):
        """Keep the watchdog happy."""
        if self.fd is None:
            return
        try:
            self.fd.write(b"")
        except OSError:
            pass


wdt = _Watchdog(RESET_TIMEOUT)
