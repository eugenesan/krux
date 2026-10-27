"""Maix stub for the Nexus 5 port.

Only `Maix.GPIO` is referenced, and only by touchscreen drivers the phone
does not use (the phone's touch is /dev/input/event1 via evdev).  Provided
so those modules keep importing.
"""


class GPIO:
    pass
